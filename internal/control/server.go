// Package control implements the noobtunnel control node: it owns the WireGuard
// hub, enrolls agents, publishes membership, discovers real endpoints, and
// serves the web UI.
package control

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/geoip"
	"github.com/noobtunnel/noobtunnel/internal/ipam"
	"github.com/noobtunnel/noobtunnel/internal/proto"
	"github.com/noobtunnel/noobtunnel/internal/proxy"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/tlsutil"
	"github.com/noobtunnel/noobtunnel/internal/topology"
	"github.com/noobtunnel/noobtunnel/internal/version"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// Options configures the control node.
type Options struct {
	StateDir string
	// Listen is the TLS listen address for the UI, API and agent channel.
	Listen string
	// PublicEndpoint overrides the WireGuard endpoint advertised to agents, in
	// host or host:port form. When empty the address an agent connected to is
	// used, which is correct in almost every deployment.
	PublicEndpoint string
	// AdminPassword seeds the admin password on first start.
	AdminPassword string
	Backend       wg.Backend
	// Runner executes host commands (exit node setup); injectable for tests.
	Runner wg.Runner
	Logger *slog.Logger
	// SetupSystem applies kernel and firewall settings at startup.
	SetupSystem bool
	// BinaryDir holds release binaries served to enrolling agents.
	BinaryDir string
	// DisableWGHub skips programming the hub device (used by tests).
	DisableWGHub bool
	// ACMEEmail enables managed Let's Encrypt certificates for HTTPS resources
	// that have a domain. Empty means self-signed certificates.
	ACMEEmail string
	// Domain is the hostname this control node is published on, for example
	// noobtunnel.example.com. When it is set the control node's own UI is served
	// on that name over the shared HTTPS port (443) with a managed certificate,
	// so operators reach it without a browser warning and without giving port
	// 443 up to the control node. Empty keeps the UI on Listen only.
	Domain string
	// ControlRoutePort is the port the Domain route listens on. Zero means 443,
	// the port published HTTPS resources share; tests point it at a free port so
	// they never need a privileged one.
	ControlRoutePort int
	// DNSFactory builds the client used to update domain records. Tests inject a
	// client pointed at a fake provider.
	DNSFactory func(provider store.DNSProvider) (DNSClient, error)
	// IPAPIHost is the hostname of the IP API that answers country lookups, for
	// example iplog.example.com. Empty leaves country rules inert until it is set
	// in the settings panel.
	IPAPIHost string
	// IPAPIToken is the token that API expects, sent as a bearer token.
	IPAPIToken string
	// DialTimeout bounds agent ping responses.
	PingTimeout time.Duration
	// ProxyDialTimeout bounds connecting to a published target. Zero uses the
	// proxy manager's own default; tests point it at something short so a target
	// that cannot be reached fails quickly.
	ProxyDialTimeout time.Duration

	// Now overrides the clock in tests.
	Now func() time.Time
}

// Server is a running control node.
type Server struct {
	opts     Options
	log      *slog.Logger
	store    *store.Store
	auth     *store.Auth
	cert     *tlsutil.Cert
	backend  wg.Backend
	commands wg.Runner
	events   *eventHub
	proxies  *proxy.Manager

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	listener  net.Listener
	httpSrv   *http.Server
	startedAt time.Time
	pingSeq   atomic.Uint64
	genSeq    atomic.Uint64

	mu sync.Mutex
	// geoIP is the client for the operator's IP API, used by country rules.
	geoIP *geoip.API
	// geoIPReported is the last API failure written to the Errors view, so an API
	// that is down is reported once rather than once per request.
	geoIPReported string
	requests      *requestLog
	errors        *errorLog
	// reportedErrors remembers the last failure reported per resource, target and
	// agent, so the Errors view gets one entry per change rather than one per
	// reconcile pass.
	reportedErrors map[string]string
	sessions       map[uint32]*Session
	endpoints      map[uint32]string
	pending        map[uint64]*pendingPing
	pendingProbes  map[uint64]chan proto.ProbeResult
	pendingCounts  map[uint64]chan proto.CounterResult
	probeSeq       atomic.Uint64
	hubStatus      wg.InterfaceStatus
	hubErr         string
	rejected       []topology.Rejected
	peerStats      map[uint32]map[uint32]proto.PeerStat
	peerDirty      bool
	checks         []Check
	checksAt       time.Time
}

// pendingPing tracks an outstanding latency probe.
type pendingPing struct {
	ch   chan time.Duration
	sent time.Time
}

// Session is one connected agent's control channel.
type Session struct {
	ID        uint32
	Token     string
	Hello     proto.Hello
	Remote    string
	StartedAt time.Time
	LocalAddr string

	conn   net.Conn
	out    chan any
	closed chan struct{}
	once   sync.Once

	mu        sync.Mutex
	stats     proto.Stats
	statsAt   time.Time
	peers     map[uint32]proto.PeerStat
	latency   time.Duration
	latencyAt time.Time
}

func (s *Session) send(v any) error {
	select {
	case <-s.closed:
		return errors.New("control: session closed")
	case s.out <- v:
		return nil
	default:
		return errors.New("control: session send queue full")
	}
}

func (s *Session) close() {
	s.once.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
}

func (s *Session) snapshot() (proto.Stats, time.Time, map[uint32]proto.PeerStat, time.Duration, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peers := make(map[uint32]proto.PeerStat, len(s.peers))
	for k, v := range s.peers {
		peers[k] = v
	}
	return s.stats, s.statsAt, peers, s.latency, s.latencyAt
}

// New creates a control node, loading state and preparing TLS.
func New(opts Options) (*Server, error) {
	if opts.StateDir == "" {
		opts.StateDir = "/var/lib/noobtunnel"
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if opts.Backend == nil {
		opts.Backend = &wg.ExecBackend{}
	}
	if opts.PingTimeout == 0 {
		opts.PingTimeout = 5 * time.Second
	}
	st, err := store.Open(opts.StateDir)
	if err != nil {
		return nil, err
	}
	auth, err := store.OpenAuth(opts.StateDir)
	if err != nil {
		return nil, err
	}
	if opts.AdminPassword != "" {
		if err := auth.EnsureAdmin(opts.AdminPassword); err != nil {
			return nil, err
		}
	}
	settings := st.Settings()
	if opts.Listen == "" {
		opts.Listen = settings.ControlListenAddr
	}
	if opts.Listen == "" {
		opts.Listen = ":8443"
	}
	hosts := tlsutil.LocalHosts()
	if opts.PublicEndpoint != "" {
		hosts = append(hosts, opts.PublicEndpoint)
	}
	// The self-signed certificate is still what agents pin, so it covers the
	// public name too: connecting to the control listener by name stays possible
	// even when the managed certificate could not be issued.
	if opts.Domain != "" {
		hosts = append(hosts, opts.Domain)
	}
	cert, err := tlsutil.LoadOrCreate(opts.StateDir, hosts)
	if err != nil {
		return nil, err
	}
	// The request log is written by the proxy manager and read by the API.
	requestEvents := newRequestLog()
	// Everything that goes wrong and explains itself goes here, for Logs → Errors.
	errorEvents := newErrorLog()
	return &Server{
		opts:          opts,
		log:           opts.Logger,
		store:         st,
		auth:          auth,
		cert:          cert,
		backend:       opts.Backend,
		commands:      opts.Runner,
		events:        newEventHub(),
		proxies:       newProxyManager(opts, st, auth, requestEvents, errorEvents),
		requests:      requestEvents,
		errors:        errorEvents,
		sessions:      map[uint32]*Session{},
		endpoints:     map[uint32]string{},
		pending:       map[uint64]*pendingPing{},
		pendingProbes: map[uint64]chan proto.ProbeResult{},
		pendingCounts: map[uint64]chan proto.CounterResult{},
		peerStats:     map[uint32]map[uint32]proto.PeerStat{},
		startedAt:     time.Now(),
	}, nil
}

// Store exposes the persistent state (used by the CLI and tests).
func (s *Server) Store() *store.Store { return s.store }

// Auth exposes the credential store.
func (s *Server) Auth() *store.Auth { return s.auth }

// Cert returns the control node's TLS identity.
func (s *Server) Cert() *tlsutil.Cert { return s.cert }

// BackendValue exposes the WireGuard backend (used by --demo).
func (s *Server) BackendValue() wg.Backend { return s.backend }

// runner returns the command runner used for host networking changes.
func (s *Server) runner() wg.Runner {
	if s.commands != nil {
		return s.commands
	}
	return wg.ExecRunner{}
}

// Addr returns the bound listen address once the server is running.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return s.opts.Listen
	}
	return s.listener.Addr().String()
}

// Settings returns the current settings.
func (s *Server) Settings() store.Settings { return s.store.Settings() }

func (s *Server) now() time.Time {
	if s.opts.Now != nil {
		return s.opts.Now()
	}
	return time.Now()
}

// Run starts the control node and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.ctx, s.cancel = ctx, cancel
	// Published resources must not outlive the control node.
	defer s.proxies.Close()

	addr := s.opts.Listen
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use") ||
			strings.Contains(err.Error(), "Only one usage of each socket address") {
			return fmt.Errorf("control: %s is already in use.\n"+
				"Another noobtunnel (or another program) is probably still running with the old settings.\n"+
				"Stop that process, or start this one with --listen on a free port: %w", addr, err)
		}
		return fmt.Errorf("control: listen on %s: %w", addr, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{s.cert.Certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	handler := s.Handler()
	// The same handler answers the control node's own UI when it is published on
	// a domain over the shared HTTPS port, so both doors show the same thing.
	s.proxies.ControlHandler = handler
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 20 * time.Second,
		TLSConfig:         tlsCfg,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	s.mu.Lock()
	s.httpSrv = httpSrv
	s.mu.Unlock()

	if err := s.syncHub(ctx); err != nil {
		s.log.Warn("could not program the wireguard hub yet", "error", err)
	}
	s.checks = s.RunChecks(ctx)
	s.startGeoIP(ctx)

	s.reconcileResources()
	s.wg.Add(8)
	go func() { defer s.wg.Done(); s.discoveryLoop(ctx) }()
	go func() { defer s.wg.Done(); s.peerPushLoop(ctx) }()
	go func() { defer s.wg.Done(); s.latencyLoop(ctx) }()
	go func() { defer s.wg.Done(); s.resourceLoop(ctx) }()
	go func() { defer s.wg.Done(); s.dnsLoop(ctx) }()
	go func() { defer s.wg.Done(); s.checkLoop(ctx) }()
	go func() { defer s.wg.Done(); s.routeLoop(ctx) }()
	go func() { defer s.wg.Done(); s.errorRecheckLoop(ctx) }()
	// When the control node issues certificates it must answer the HTTP-01
	// challenge on port 80, even if no HTTP resource is published there yet.
	if s.proxies.ACMEChallenge != nil {
		if challenge, err := net.Listen("tcp", net.JoinHostPort("", "80")); err == nil {
			challengeServer := &http.Server{Handler: s.proxies.ACMEChallenge}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				if err := challengeServer.Serve(challenge); err != nil && !errors.Is(err, http.ErrServerClosed) {
					s.log.Debug("ACME challenge listener stopped", "error", err)
				}
			}()
			go func() {
				<-ctx.Done()
				_ = challengeServer.Close()
			}()
			s.log.Info("serving ACME challenges on port 80")
		} else {
			s.log.Debug("port 80 is busy; ACME challenges are served through HTTP resources", "error", err)
		}
	}

	if s.opts.SetupSystem {
		if err := s.ApplySystemSetup(ctx); err != nil {
			s.log.Warn("system setup incomplete", "error", err)
		}
	}

	s.log.Info("control node listening",
		"address", ln.Addr().String(),
		"certificate", s.cert.Fingerprint,
		"wireguardInterface", s.store.Settings().Interface,
		"backend", s.backend.Name())

	// Cancelling the context (Ctrl+C, systemd stop, or a test shutting down) must
	// actually stop serving; otherwise the process keeps the port and never exits.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		if err := s.Shutdown(shutdownCtx); err != nil {
			s.log.Debug("shutdown reported an error", "error", err)
		}
	}()

	err = httpSrv.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	s.wg.Wait()
	return err
}

// Shutdown stops the HTTP server and closes every agent session.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	s.proxies.Close()
	s.mu.Lock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		_ = sess.send(proto.Bye{T: proto.TBye, Reason: "control node shutting down"})
		sess.close()
	}
	if s.httpSrv != nil {
		s.mu.Lock()
		srv := s.httpSrv
		s.mu.Unlock()
		if srv != nil {
			return srv.Shutdown(ctx)
		}
	}
	return nil
}

// --- agent control channel -------------------------------------------------

// handleAgentConnect upgrades an HTTPS request into an agent control channel.
func (s *Server) handleAgentConnect(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), proto.UpgradeToken) {
		http.Error(w, "expected upgrade: "+proto.UpgradeToken, http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		s.log.Warn("failed to hijack agent connection", "error", err)
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + proto.UpgradeToken +
		"\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		_ = conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return
	}

	brc := &bufferedConn{Conn: conn, r: rw.Reader}
	go func() {
		defer conn.Close()
		if err := s.serveAgent(brc); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Debug("agent control channel closed", "remote", conn.RemoteAddr().String(), "error", err)
		}
	}()
}

// serveAgent performs the enrollment handshake and then serves the channel.
func (s *Server) serveAgent(conn net.Conn) error {
	magic := make([]byte, len(proto.Magic))
	if _, err := io.ReadFull(conn, magic); err != nil {
		return err
	}
	if string(magic) != string(proto.Magic) {
		return errors.New("control: bad control channel magic")
	}
	var hello proto.Hello
	if err := proto.ReadJSON(conn, &hello); err != nil {
		return err
	}
	if hello.T != proto.THello {
		return fmt.Errorf("control: expected hello, got %q", hello.T)
	}

	agent, err := s.authorise(hello)
	if err != nil {
		_ = proto.WriteJSON(conn, proto.Error{T: proto.TError, Code: errCode(err), Message: err.Error()})
		return err
	}

	local := conn.LocalAddr().String()
	session := &Session{
		ID:        agent.ID,
		Token:     agent.Token,
		Hello:     hello,
		Remote:    conn.RemoteAddr().String(),
		LocalAddr: local,
		StartedAt: s.now(),
		conn:      conn,
		out:       make(chan any, 64),
		closed:    make(chan struct{}),
		peers:     map[uint32]proto.PeerStat{},
	}

	s.mu.Lock()
	if old, exists := s.sessions[agent.ID]; exists {
		s.mu.Unlock()
		s.log.Info("replacing existing agent session", "agent", agent.Name, "agentID", agent.ID)
		old.close()
		s.mu.Lock()
	}
	s.sessions[agent.ID] = session
	s.peerDirty = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if cur, ok := s.sessions[agent.ID]; ok && cur == session {
			delete(s.sessions, agent.ID)
			s.peerDirty = true
		}
		s.mu.Unlock()
		session.close()
		s.broadcastState()
		s.log.Info("agent disconnected", "agent", agent.Name, "agentID", agent.ID)
	}()

	// Record the enrollment (public key, version, first seen).
	err = s.store.UpdateAgent(agent.ID, func(a *store.Agent) error {
		a.PublicKey = hello.PublicKey
		a.Version = hello.Version
		a.OS = hello.OS
		a.Arch = hello.Arch
		a.Hostname = hello.Hostname
		a.LastSeen = s.now().UTC()
		if a.EnrolledAt == nil {
			now := s.now().UTC()
			a.EnrolledAt = &now
		}
		if len(hello.Advertise) > 0 {
			if advertise, err := store.NormalisePrefixes(hello.Advertise); err == nil {
				a.Advertise = advertise
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if err := s.syncHub(context.Background()); err != nil {
		s.log.Warn("failed to update hub peers", "error", err)
	}
	welcome, err := s.buildWelcome(agent.ID, hello, local)
	if err != nil {
		return err
	}
	session.out <- welcome

	s.log.Info("agent enrolled",
		"agent", agent.Name,
		"agentID", agent.ID,
		"address", welcome.Address,
		"remote", session.Remote,
		"version", hello.Version)
	s.recordEvent("agent-online", agent.Name+" connected from "+session.Remote)
	s.broadcastState()

	go s.sessionWriter(session)
	s.markDirty()

	for {
		typ, raw, err := proto.ReadRaw(conn)
		if err != nil {
			return err
		}
		switch typ {
		case proto.TStats:
			var stats proto.Stats
			if err := json.Unmarshal(raw, &stats); err != nil {
				continue
			}
			session.mu.Lock()
			session.stats = stats
			session.statsAt = s.now()
			session.peers = map[uint32]proto.PeerStat{}
			for _, ps := range stats.PeerStats {
				session.peers[ps.ID] = ps
			}
			peerCopy := make(map[uint32]proto.PeerStat, len(session.peers))
			for id, ps := range session.peers {
				peerCopy[id] = ps
			}
			session.mu.Unlock()
			s.mu.Lock()
			s.peerStats[agent.ID] = peerCopy
			s.mu.Unlock()
			s.broadcastState()
		case proto.TPong:
			var pong proto.Pong
			if err := json.Unmarshal(raw, &pong); err != nil {
				continue
			}
			s.resolvePing(pong.Seq)
		case proto.TProbe:
			var probe proto.ProbeResult
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			s.resolveProbe(probe)
		case proto.TCounters:
			var counters proto.CounterResult
			if err := json.Unmarshal(raw, &counters); err != nil {
				continue
			}
			s.resolveCounters(counters)
		case proto.TLog:
			var entry proto.Log
			if err := json.Unmarshal(raw, &entry); err != nil {
				continue
			}
			s.log.Debug("agent log", "agent", agent.Name, "level", entry.Level, "message", entry.Message)
		case proto.TBye:
			var bye proto.Bye
			_ = json.Unmarshal(raw, &bye)
			s.log.Info("agent said goodbye", "agent", agent.Name, "reason", bye.Reason)
			return nil
		}
	}
}

func (s *Server) sessionWriter(session *Session) {
	for {
		select {
		case <-session.closed:
			return
		case msg := <-session.out:
			if err := proto.WriteJSON(session.conn, msg); err != nil {
				session.close()
				return
			}
		}
	}
}

var (
	errTokenUnknown = errors.New("token is not recognised")
	errTokenExpired = errors.New("this enrollment link has expired")
	errDisabled     = errors.New("this agent is disabled")
	errBadKey       = errors.New("the agent sent an invalid WireGuard public key")
)

func errCode(err error) string {
	switch {
	case errors.Is(err, errTokenUnknown), errors.Is(err, errTokenExpired):
		return "token"
	case errors.Is(err, errDisabled):
		return "disabled"
	default:
		return "error"
	}
}

// authorise validates an enrollment hello against the agent registry.
func (s *Server) authorise(hello proto.Hello) (*store.Agent, error) {
	if !wg.ValidKey(hello.PublicKey) {
		return nil, errBadKey
	}
	agent, err := s.store.AgentByToken(hello.Token)
	if err != nil {
		return nil, errTokenUnknown
	}
	if !store.EqualToken(agent.Token, hello.Token) {
		return nil, errTokenUnknown
	}
	if agent.Expired(s.now()) {
		return nil, errTokenExpired
	}
	if !agent.Enabled {
		return nil, errDisabled
	}
	return agent, nil
}

// buildWelcome renders the membership snapshot an agent needs.
func (s *Server) buildWelcome(agentID uint32, hello proto.Hello, localAddr string) (proto.Welcome, error) {
	st := s.store.View()
	settings := st.Settings
	pool, err := ipam.New(settings.MeshCIDR)
	if err != nil {
		return proto.Welcome{}, err
	}
	agent, err := s.store.Agent(agentID)
	if err != nil {
		return proto.Welcome{}, err
	}
	prefix, err := agent.AddressPrefix()
	if err != nil {
		return proto.Welcome{}, err
	}
	s.mu.Lock()
	s.mu.Unlock()
	generation := s.genSeq.Load()

	welcome := proto.Welcome{
		T:                proto.TWelcome,
		AgentID:          agentID,
		Name:             agent.Name,
		Address:          prefix.Addr().String(),
		Prefix:           prefix.Bits(),
		MeshCIDR:         settings.MeshCIDR,
		MTU:              settings.MTU,
		KeepaliveSec:     settings.KeepaliveSec,
		Interface:        settings.Interface,
		Generation:       generation,
		ServerTime:       s.now().Unix(),
		StatsIntervalSec: settings.StatsIntervalSec,
		DirectFreshSec:   settings.DirectFreshSec,
		DirectProbeSec:   settings.DirectProbeSec,
		Hub: proto.Hub{
			PublicKey:    st.Hub.PublicKey,
			Endpoint:     s.hubEndpoint(localAddr),
			Address:      pool.HubAddress().String(),
			PresharedKey: agent.HubPresharedKey,
		},
	}
	peers, err := s.peersFor(agentID)
	if err != nil {
		return proto.Welcome{}, err
	}
	welcome.Peers = peers
	// Tell the agent which networks the mesh routes through it. Its own install
	// flags are not the whole story: the operator can add networks here after the
	// machine enrolled, and without this the agent would never open forwarding
	// for them.
	welcome.Carry = s.store.CarriedPrefixes(agentID)
	// What this agent has to carry for services that only listen on its loopback.
	welcome.Forwards = s.forwardsFor(agentID)
	return welcome, nil
}

// peersFor builds the peer list an agent should configure.
func (s *Server) peersFor(selfID uint32) ([]proto.Peer, error) {
	st := s.store.View()
	settings := st.Settings
	s.mu.Lock()
	endpoints := make(map[uint32]string, len(s.endpoints))
	for id, ep := range s.endpoints {
		endpoints[id] = ep
	}
	sessions := make(map[uint32]*Session, len(s.sessions))
	for id, sess := range s.sessions {
		sessions[id] = sess
	}
	s.mu.Unlock()

	var out []proto.Peer
	for _, agent := range st.Agents {
		if agent.ID == selfID || !agent.Enabled || agent.PublicKey == "" {
			continue
		}
		_, online := sessions[agent.ID]
		psk, err := s.store.PairKey(selfID, agent.ID)
		if err != nil {
			return nil, err
		}
		peer := proto.Peer{
			ID:           agent.ID,
			Name:         agent.Name,
			Address:      agent.Address,
			PublicKey:    agent.PublicKey,
			Advertise:    agent.Advertise,
			Endpoint:     endpoints[agent.ID],
			Online:       online,
			PresharedKey: psk,
			Direct:       settings.DirectPaths && endpoints[agent.ID] != "",
		}
		out = append(out, peer)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// publicURL is the address an operator opens in a browser: the domain when the
// control node is published on one, and the TLS listener otherwise.
func (s *Server) publicURL() string {
	if domain := strings.TrimSpace(s.opts.Domain); domain != "" {
		return "https://" + domain
	}
	return "https://" + s.Addr()
}

// controlEndpoint is the address agents dial for the control channel. It stays
// on the TLS listener, so the certificate agents pin is the control node's own
// and never a publicly trusted one that gets renewed underneath them.
func (s *Server) controlEndpoint() string {
	addr := s.Addr()
	if domain := strings.TrimSpace(s.opts.Domain); domain != "" {
		if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
			return net.JoinHostPort(domain, port)
		}
		return domain
	}
	return addr
}

// hubEndpoint decides which WireGuard endpoint agents should dial.
func (s *Server) hubEndpoint(localAddr string) string {
	settings := s.store.Settings()
	port := settings.WGListenPort
	if s.opts.PublicEndpoint != "" {
		return ensurePort(s.opts.PublicEndpoint, port)
	}
	host, _, err := net.SplitHostPort(localAddr)
	if err == nil && host != "" {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			// The agent is on the same machine; the loopback address still works
			// but a real address is friendlier.
			if len(tlsutil.LocalHosts()) > 0 {
				return net.JoinHostPort(firstNonLoopback(tlsutil.LocalHosts()), itoa(port))
			}
		}
		return net.JoinHostPort(host, itoa(port))
	}
	return net.JoinHostPort(firstNonLoopback(tlsutil.LocalHosts()), itoa(port))
}

func ensurePort(endpoint string, port int) string {
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	return net.JoinHostPort(strings.Trim(endpoint, "[]"), itoa(port))
}

func firstNonLoopback(hosts []string) string {
	var fallback string
	for _, h := range hosts {
		ip := net.ParseIP(h)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.To4() != nil && !ip.IsPrivate() {
			return h
		}
		if fallback == "" && ip.To4() != nil {
			fallback = h
		}
	}
	if fallback != "" {
		return fallback
	}
	for _, h := range hosts {
		ip := net.ParseIP(h)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return h
	}
	if len(hosts) > 0 {
		return hosts[0]
	}
	return "127.0.0.1"
}

func itoa(v int) string { return fmt.Sprintf("%d", v) }

// --- hub maintenance --------------------------------------------------------

// syncHub programs the control node's own WireGuard device.
func (s *Server) syncHub(ctx context.Context) error {
	if s.opts.DisableWGHub {
		return nil
	}
	cfg, err := s.hubConfig()
	if err != nil {
		return err
	}
	settings := s.store.Settings()

	if err := s.backend.Sync(ctx, settings.Interface, cfg); err != nil {
		s.mu.Lock()
		s.hubErr = err.Error()
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.hubErr = ""
	s.mu.Unlock()
	return nil
}

// hubConfig renders everything the control node's own device should hold: the
// agents, the networks they offer and the addresses published resources pin to
// them. It is also what the periodic route re-assertion uses, so both always
// describe the same mesh.
func (s *Server) hubConfig() (wg.Config, error) {
	st := s.store.View()
	settings := st.Settings
	pool, err := ipam.New(settings.MeshCIDR)
	if err != nil {
		return wg.Config{}, err
	}
	s.mu.Lock()
	endpoints := make(map[uint32]string, len(s.endpoints))
	for id, ep := range s.endpoints {
		endpoints[id] = ep
	}
	s.mu.Unlock()

	hubPSKs := map[uint32]string{}
	var members []topology.Member
	for _, agent := range st.Agents {
		if !agent.Enabled || agent.PublicKey == "" {
			continue
		}
		addr, err := netip.ParseAddr(agent.Address)
		if err != nil {
			continue
		}
		member := topology.Member{
			ID:        agent.ID,
			Name:      agent.Name,
			Address:   addr,
			PublicKey: agent.PublicKey,
			Enabled:   true,
			// A published target names its agent, so the address goes to that
			// machine no matter which agent advertised the range around it.
			Pinned: s.store.PinnedHosts(agent.ID),
		}
		for _, raw := range agent.Advertise {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				member.Advertise = append(member.Advertise, prefix)
			}
		}
		members = append(members, member)
		hubPSKs[agent.ID] = agent.HubPresharedKey
	}

	cfg, rejected := topology.BuildHubConfig(topology.HubInput{
		Mesh: topology.Mesh{
			CIDR:          pool.Prefix(),
			MTU:           settings.MTU,
			KeepaliveSec:  settings.KeepaliveSec,
			DirectEnabled: settings.DirectPaths,
		},
		HubAddress:    pool.HubAddress(),
		PrivateKey:    st.Hub.PrivateKey,
		WGPort:        settings.WGListenPort,
		Members:       members,
		HubPSKs:       hubPSKs,
		DiscoveredEPs: endpoints,
	})

	s.mu.Lock()
	s.rejected = rejected
	s.mu.Unlock()
	return cfg, nil
}

// discoveryLoop reads the hub device to learn real endpoints and traffic.
func (s *Server) discoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.discover(ctx)
		}
	}
}

func (s *Server) discover(ctx context.Context) {
	settings := s.store.Settings()
	status, err := s.backend.Status(ctx, settings.Interface)
	if err != nil {
		s.mu.Lock()
		s.hubErr = err.Error()
		s.mu.Unlock()
		return
	}
	st := s.store.View()
	byKey := map[string]uint32{}
	for _, agent := range st.Agents {
		if agent.PublicKey != "" {
			byKey[agent.PublicKey] = agent.ID
		}
	}

	changed := false
	s.mu.Lock()
	s.hubStatus = status
	s.hubErr = ""
	for _, peer := range status.Peers {
		id, known := byKey[peer.PublicKey]
		if !known {
			continue
		}
		if peer.Endpoint != "" && s.endpoints[id] != peer.Endpoint {
			s.endpoints[id] = peer.Endpoint
			changed = true
		}
	}
	s.mu.Unlock()

	if changed {
		if err := s.syncHub(ctx); err != nil {
			s.log.Debug("hub resync after endpoint discovery failed", "error", err)
		}
		s.markDirty()
		s.broadcastState()
		s.log.Info("agent endpoints updated")
	}
}

// peerPushLoop debounces membership pushes to the connected agents.
func (s *Server) peerPushLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			dirty := s.peerDirty
			s.peerDirty = false
			sessions := make([]*Session, 0, len(s.sessions))
			for _, sess := range s.sessions {
				sessions = append(sessions, sess)
			}
			s.mu.Unlock()
			if !dirty {
				continue
			}
			generation := s.genSeq.Add(1)
			for _, sess := range sessions {
				peers, err := s.peersFor(sess.ID)
				if err != nil {
					s.log.Warn("failed to build peer list", "agent", sess.Hello.Name, "error", err)
					continue
				}
				carry := s.store.CarriedPrefixes(sess.ID)
				forwards := s.forwardsFor(sess.ID)
				if err := sess.send(proto.Peers{
					T: proto.TPeers, Generation: generation, Peers: peers,
					Carry: carry, Forwards: forwards,
				}); err != nil {
					s.log.Debug("failed to push peers", "agent", sess.Hello.Name, "error", err)
				}
			}
		}
	}
}

func (s *Server) markDirty() {
	s.mu.Lock()
	s.peerDirty = true
	s.mu.Unlock()
}

// latencyLoop measures control channel round trip times.
func (s *Server) latencyLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			sessions := make([]*Session, 0, len(s.sessions))
			for _, sess := range s.sessions {
				sessions = append(sessions, sess)
			}
			s.mu.Unlock()
			for _, sess := range sessions {
				go func(sess *Session) {
					if _, err := s.Ping(ctx, sess.ID); err != nil {
						s.log.Debug("latency probe failed", "agent", sess.Hello.Name, "error", err)
					}
				}(sess)
			}
		}
	}
}

// Ping measures the control channel round trip time to an agent.
func (s *Server) Ping(ctx context.Context, agentID uint32) (time.Duration, error) {
	s.mu.Lock()
	sess, ok := s.sessions[agentID]
	s.mu.Unlock()
	if !ok {
		return 0, errors.New("control: agent is not connected")
	}
	seq := s.pingSeq.Add(1)
	ch := make(chan time.Duration, 1)
	s.mu.Lock()
	s.pending[seq] = &pendingPing{ch: ch, sent: s.now()}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, seq)
		s.mu.Unlock()
	}()
	if err := sess.send(proto.Ping{T: proto.TPing, Seq: seq}); err != nil {
		return 0, err
	}
	timeout := s.opts.PingTimeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
		return 0, errors.New("control: agent did not answer the ping")
	case rtt := <-ch:
		sess.mu.Lock()
		sess.latency = rtt
		sess.latencyAt = s.now()
		sess.mu.Unlock()
		s.broadcastState()
		return rtt, nil
	}
}

func (s *Server) resolvePing(seq uint64) {
	s.mu.Lock()
	p, ok := s.pending[seq]
	delete(s.pending, seq)
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case p.ch <- s.now().Sub(p.sent):
	default:
	}
}

// probeWait bounds how long the control node waits for an agent to answer a
// probe. It is longer than the agent's own dial timeout so a slow target still
// produces an answer, and it means an agent too old to understand the command
// ends up as "did not answer" rather than as a hang.
const probeWait = 10 * time.Second

// ProbeTargets asks an agent to try reaching these host:port targets itself, and
// returns what it saw.
//
// The control node can see the tunnel and its own route, but not what happens on
// the other side of it: whether the service answers the agent at all, which
// interface the packets take there, and whether it answers a connection whose
// source is the mesh address. That is exactly the half that is missing when a
// target times out.
func (s *Server) ProbeTargets(ctx context.Context, agentID uint32, targets []string) (proto.ProbeResult, error) {
	s.mu.Lock()
	sess, ok := s.sessions[agentID]
	s.mu.Unlock()
	if !ok {
		return proto.ProbeResult{}, errors.New("control: the agent is not connected")
	}
	if len(targets) == 0 {
		return proto.ProbeResult{}, errors.New("control: no targets to probe")
	}
	seq := s.probeSeq.Add(1)
	ch := make(chan proto.ProbeResult, 1)
	s.mu.Lock()
	s.pendingProbes[seq] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingProbes, seq)
		s.mu.Unlock()
	}()
	if err := sess.send(proto.Command{T: proto.TCommand, Seq: seq, Action: proto.ActionProbe, Targets: targets}); err != nil {
		return proto.ProbeResult{}, err
	}
	timer := time.NewTimer(probeWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return proto.ProbeResult{}, ctx.Err()
	case <-timer.C:
		return proto.ProbeResult{}, errors.New("control: the agent did not answer the probe; update the agent on that machine")
	case result := <-ch:
		return result, nil
	}
}

// FirewallCounters asks an agent for its host firewall's packet counters.
//
// Two of these around a failing connection are the only way to see which rule
// consumed a packet: a firewall that drops silently leaves nothing in a capture
// and nothing in a log, but the counter of the rule that matched always moves.
func (s *Server) FirewallCounters(ctx context.Context, agentID uint32) ([]string, error) {
	s.mu.Lock()
	sess, ok := s.sessions[agentID]
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("control: the agent is not connected")
	}
	seq := s.probeSeq.Add(1)
	ch := make(chan proto.CounterResult, 1)
	s.mu.Lock()
	s.pendingCounts[seq] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingCounts, seq)
		s.mu.Unlock()
	}()
	if err := sess.send(proto.Command{T: proto.TCommand, Seq: seq, Action: proto.ActionCounters}); err != nil {
		return nil, err
	}
	timer := time.NewTimer(probeWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errors.New("control: the agent did not answer; update the agent on that machine")
	case result := <-ch:
		return result.Rules, nil
	}
}

func (s *Server) resolveCounters(result proto.CounterResult) {
	s.mu.Lock()
	ch, ok := s.pendingCounts[result.Seq]
	delete(s.pendingCounts, result.Seq)
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- result:
	default:
	}
}

func (s *Server) resolveProbe(result proto.ProbeResult) {
	s.mu.Lock()
	ch, ok := s.pendingProbes[result.Seq]
	delete(s.pendingProbes, result.Seq)
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- result:
	default:
	}
}

// Command sends an action to a connected agent.
func (s *Server) Command(agentID uint32, action string) error {
	s.mu.Lock()
	sess, ok := s.sessions[agentID]
	s.mu.Unlock()
	if !ok {
		return errors.New("control: agent is not connected")
	}
	return sess.send(proto.Command{T: proto.TCommand, Action: action})
}

// Revoke disconnects and disables an agent, then republishes membership.
func (s *Server) Revoke(ctx context.Context, agentID uint32, reason string) {
	s.mu.Lock()
	sess, ok := s.sessions[agentID]
	delete(s.endpoints, agentID)
	s.mu.Unlock()
	if ok {
		_ = sess.send(proto.Revoked{T: proto.TRevoked, Reason: reason})
		time.AfterFunc(200*time.Millisecond, sess.close)
	}
	if err := s.syncHub(ctx); err != nil {
		s.log.Warn("failed to update hub after revoke", "error", err)
	}
	s.markDirty()
}

// Sync pushes the current membership to agents and the hub.
func (s *Server) Sync(ctx context.Context) error {
	if err := s.syncHub(ctx); err != nil {
		return err
	}
	s.markDirty()
	return nil
}

// ConnectedAgentIDs returns the ids of agents with a live control channel.
func (s *Server) ConnectedAgentIDs() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint32, 0, len(s.sessions))
	for id := range s.sessions {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *Server) broadcastState() {
	s.events.broadcast(s.StateSnapshot())
}

// resourceLoop keeps published services in sync with the store. It also retries
// listeners that failed to bind, for example because a port was briefly busy.
func (s *Server) resourceLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileResources()
		}
	}
}

// reconcileResources pushes the current resource definitions to the proxy
// manager, which starts, updates or stops listeners as needed.
func (s *Server) reconcileResources() {
	s.proxies.SetBrandName(s.BrandName())
	specs := s.ResourceSpecs()
	s.proxies.Reconcile(specs)
	s.recordResourceErrors()
	// A resource may have changed which exit node its domain points at.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.syncDomains(ctx)
	}()
}

// recordResourceErrors copies the failures the Resources view shows into the
// Errors view: a resource that is not listening, one target that cannot be
// dialled while the other answers, and an agent whose device is out of sync. Each
// distinct failure is recorded once, when it appears or changes.
func (s *Server) recordResourceErrors() {
	if s.errors == nil {
		return
	}
	stats := s.proxies.Stats()
	agents := map[uint32]string{}
	for _, agent := range s.store.Agents() {
		agents[agent.ID] = agent.Name
	}
	s.mu.Lock()
	previous := s.reportedErrors
	current := make(map[string]string, len(previous)+8)
	sessions := make(map[uint32]*Session, len(s.sessions))
	for id, sess := range s.sessions {
		sessions[id] = sess
	}
	s.mu.Unlock()

	var fresh []ErrorEntry
	note := func(key, source, message, detail, hint string) {
		if detail == "" {
			return
		}
		current[key] = detail
		if previous[key] == detail {
			return
		}
		fresh = append(fresh, ErrorEntry{
			Time:    time.Now().UTC(),
			Source:  source,
			Message: message,
			Detail:  detail,
			Hint:    hint,
		})
	}

	for _, resource := range s.store.Resources() {
		stat, ok := stats[resource.ID]
		if !ok {
			continue
		}
		note(fmt.Sprintf("resource/%d", resource.ID), "resource",
			resource.Name+" is not listening", stat.LastError,
			"the port may be taken by another service, or the exit node address may not be on this host")
		for _, target := range resource.Targets {
			// The mesh can only deliver a network to one agent: a target that
			// another agent's advertisement would capture is reported here, with
			// the store's explanation of which one wins. This is checked before
			// the counters, because a target nobody has dialled yet has none.
			if err := s.store.CheckTargetReachability(target.AgentID, target.Host); err != nil {
				note(fmt.Sprintf("unreachable/%d/%d", resource.ID, target.ID), "target",
					resource.Name+": target "+target.Target()+" would not reach that agent",
					err.Error(),
					"fix the advertised networks of the agents involved, then publish again")
			}
			ts, ok := stat.Targets[target.ID]
			if !ok {
				continue
			}
			who := agents[target.AgentID]
			if who == "" {
				who = "the agent"
			}
			// The dial error alone is not enough: a connected agent that cannot
			// program its WireGuard device answers on its own machine while the
			// tunnel is dead, which looks like "the service is down" from here.
			detail := ts.LastError
			hint := "check that the service listens on that address behind the agent and that the agent is online"
			s.mu.Lock()
			hubErr, hubUp := s.hubErr, s.hubStatus.Exists
			hubPeers := append([]wg.PeerStatus(nil), s.hubStatus.Peers...)
			s.mu.Unlock()
			// "no route to host" is what WireGuard answers when it has no peer for
			// the destination: the route is there, the tunnel is not.
			tunnelDead := strings.Contains(ts.LastError, "no route to host")
			// A timeout is the other shape: the packet goes out and the answer
			// never comes back. The service is usually fine, so the hint has to
			// send the operator to the agent itself.
			silentTimeout := strings.Contains(ts.LastError, "i/o timeout")
			handshake := false
			if agent, err := s.store.Agent(target.AgentID); err == nil && agent.PublicKey != "" {
				for _, peer := range hubPeers {
					if peer.PublicKey == agent.PublicKey && !peer.LatestHandshake.IsZero() {
						handshake = true
					}
				}
			}
			// explained marks the cases where the control node already knows what
			// is wrong: the agent's own device report is only worth adding when it
			// does not.
			explained := false
			if hubErr != "" || !hubUp {
				hint = "the control node's own WireGuard hub is not up, so nothing can be reached through it"
				explained = true
			} else if tunnelDead && !handshake {
				detail = strings.TrimSpace(detail + "\nthe control node has no WireGuard handshake with that agent")
				hint = "the agent's device is not configured, or it was re-enrolled: check wg show on the agent and its log for \"wireguard device in sync\""
				explained = true
			} else if silentTimeout {
				port := target.Host
				if _, p, err := net.SplitHostPort(target.Target()); err == nil {
					port = p
				}
				settings := s.store.Settings()
				detail = strings.TrimSpace(detail + "\n" + silentTimeoutDetail(who, port, settings.Interface, settings.MeshCIDR))
				hint = "run the lines in the error column on " + who + ", in that order"
				explained = true
			}
			if !explained {
				if sess, ok := sessions[target.AgentID]; ok && sess != nil {
					agentStats, _, _, _, _ := sess.snapshot()
					switch {
					case agentStats.LastError != "":
						detail = strings.TrimSpace(detail + "\nthe agent reports: " + agentStats.LastError)
						hint = "the agent is connected but its WireGuard device is not in sync, so nothing reaches it through the tunnel"
					case agentStats.Interface == "":
						detail = strings.TrimSpace(detail + "\nthe agent reports no WireGuard interface")
						hint = "the agent's device does not exist on that machine; check its service or container logs"
					case len(agentStats.PeerStats) == 0:
						detail = strings.TrimSpace(detail + "\nthe agent's device has no peers configured")
						hint = "the agent is connected but its WireGuard device was never configured; update the agent on that machine"
					}
				} else if ts.LastError != "" {
					hint = "the agent is not connected right now, so the tunnel to it is down"
				}
			}
			note(fmt.Sprintf("target/%d/%d", resource.ID, target.ID), "target",
				resource.Name+": target "+target.Target()+" ("+who+") is not reachable",
				detail, hint)
		}
	}

	for id, sess := range sessions {
		agentStats, _, _, _, _ := sess.snapshot()
		lastError := agentStats.LastError
		who := agents[id]
		if who == "" {
			who = "an agent"
		}
		note(fmt.Sprintf("agent/%d", id), "agent",
			who+" cannot program its WireGuard device", lastError,
			"check wireguard-tools, the kernel module and NET_ADMIN on that machine")
	}

	// An advertised network the hub refused to route belongs here too. It shows
	// up as "no route to host" everywhere else, and a network nobody has
	// published a target for yet would otherwise leave no trace at all.
	s.mu.Lock()
	rejected := append([]topology.Rejected(nil), s.rejected...)
	s.mu.Unlock()
	for _, entry := range rejected {
		who := agents[entry.MemberID]
		if who == "" {
			who = fmt.Sprintf("agent %d", entry.MemberID)
		}
		note(fmt.Sprintf("advertise/%d/%s", entry.MemberID, entry.Prefix), "agent",
			who+": advertised network "+entry.Prefix+" is not routed",
			entry.Reason,
			"a network is routed to one agent only: drop it from one of them, or advertise a range only that machine can reach")
	}

	// The hub is the thing every target is reached through: if the control node
	// cannot program it, nothing is reachable no matter what the agents report.
	s.mu.Lock()
	hubErr, hubUp := s.hubErr, s.hubStatus.Exists
	s.mu.Unlock()
	switch {
	case strings.HasPrefix(s.backend.Name(), "fake"):
		// The demo backend simulates the mesh in memory: agents enroll, addresses
		// are assigned, and nothing at all reaches the kernel, which is exactly
		// what "no route to host" looks like from the proxy's point of view.
		note("hub", "wireguard", "this control node runs with the simulated WireGuard backend",
			"the mesh is not real: no interface or route exists on this host",
			"restart the control node without --backend fake (or the demo flags) to run a real mesh")
	case hubErr != "":
		note("hub", "wireguard", "the control node cannot program its WireGuard hub", hubErr,
			"check that wg(8) and ip(8) are installed and that the service runs as root; if the module cannot be loaded (some OpenVZ and LXC VPSs), this host cannot run a real mesh")
	case !hubUp && !s.opts.DisableWGHub:
		note("hub", "wireguard", "the WireGuard hub interface is not up",
			s.store.Settings().Interface+" does not exist on this host",
			"load the module (modprobe wireguard) and look at journalctl -u noobtunnel-server; the dashboard checklist names what is missing")
	}

	s.mu.Lock()
	s.reportedErrors = current
	s.mu.Unlock()
	for _, entry := range fresh {
		s.errors.record(entry.Source, entry.Message, entry.Detail, entry.Hint)
	}
}

// silentTimeoutDetail is what an operator needs when a target times out: the
// packet left, nothing valid came back, and a service that answers on the agent
// itself can still be perfectly healthy - a plain curl there never uses the
// forwarding and NAT path the tunnel does.
//
// It is written as an ordered procedure rather than a description, because the
// question it has to answer is "so what do I do now": start the capture (it
// waits for packets, nothing can be missed), press Diagnose, then read which of
// the two answers arrived.
func silentTimeoutDetail(who, port, iface, meshCIDR string) string {
	if iface == "" {
		iface = "noobtun"
	}
	lines := []string{
		"the packet left the control node and nothing valid came back",
		"the service on that machine can still be healthy: a curl there never uses this path",
		"",
		"1. press Diagnose on this target. The control node asks the agent to try it from where it",
		"   is, and says which side is broken: the service itself, or the path between the two.",
		"2. to watch the packets yourself while it runs, start this on " + who + " first and leave",
		"   it running (it waits, so nothing is missed), then press Diagnose again:",
		"       sudo tcpdump -ni any port " + port,
	}
	lines = append(lines, strings.Split(silentTimeoutBranches(iface, meshCIDR), "\n")...)
	lines = append(lines, "3. update the agent on that machine:  install.sh --update",
		"       it applies these forwarding and NAT rules itself, and keeps them in place")
	return strings.Join(lines, "\n")
}

// silentTimeoutBranches is the reading of the capture: three shapes, each with
// the command that fixes it there and then.
func silentTimeoutBranches(iface, meshCIDR string) string {
	nat := "cannot be fixed without a mesh range"
	if meshCIDR != "" {
		nat = "sudo iptables -t nat -I POSTROUTING -d " + meshCIDR + " -j RETURN"
	}
	return strings.Join([]string{
		"       nothing arrives on " + iface + " at all",
		"           the mesh is not sending it here: another agent carries that network (see the other",
		"           Errors entries), or the hub has no route - check both from the control node with",
		"           sudo wg show " + iface + " allowed-ips",
		"       a SYN arrives, nothing leaves for the container",
		"           forwarding is filtered; fix it now with",
		"               sudo iptables -I FORWARD -i " + iface + " -j ACCEPT",
		"               sudo iptables -I FORWARD -o " + iface + " -j ACCEPT",
		"       the container answers, but the answer leaves with another address",
		"           host NAT rewrote it (Docker masquerade does this to a container); fix it now with",
		"               " + nat,
	}, "\n")
}

// ResourceSpecs renders the store's resources for the proxy manager.
func (s *Server) ResourceSpecs() []proxy.Spec {
	resources := s.store.Resources()
	nodes := map[string]store.ExitNode{}
	for _, node := range s.store.ExitNodes() {
		nodes[node.ID] = node
	}
	specs := make([]proxy.Spec, 0, len(resources))
	for _, r := range resources {
		bind := ""
		if node, ok := nodes[r.ExitNodeID]; ok {
			bind = node.BindAddress()
		}
		// A resource on a disabled exit node stops listening.
		exitEnabled := true
		if node, ok := exitNodeFor(nodes, r.ExitNodeID); ok && !node.Enabled {
			exitEnabled = false
		}
		targets := make([]proxy.TargetSpec, 0, len(r.Targets))
		for _, t := range r.Targets {
			if !t.Enabled {
				continue
			}
			// A loopback target is reached through its agent's mesh address, which
			// the agent listens on for exactly that service.
			targets = append(targets, proxy.TargetSpec{
				ID: t.ID, Host: t.Host, Port: t.Port,
				DialAddr: s.DialAddress(t), AgentID: t.AgentID,
			})
		}
		specs = append(specs, proxy.Spec{
			ID:            r.ID,
			Name:          r.Name,
			Protocol:      string(r.Protocol),
			Targets:       targets,
			Strategy:      string(r.Strategy),
			BindAddr:      bind,
			ListenPort:    r.EffectiveListenPort(),
			Domain:        r.Domain,
			Enabled:       r.Enabled && len(targets) > 0 && exitEnabled,
			ProxyProtocol: r.ProxyProtocol,
			Identity:      r.Identity,
			BlockExploits: r.BlockExploits,
			WebSockets:    r.AllowsWebSockets(),
			Rules:         r.Rules,
		})
	}
	return specs
}

// exitNodeFor resolves the exit node of a resource, treating the empty id as the
// built-in control node.
func exitNodeFor(nodes map[string]store.ExitNode, id string) (store.ExitNode, bool) {
	if node, ok := nodes[id]; ok {
		return node, true
	}
	for _, node := range nodes {
		if node.Kind == store.ExitNodeControl {
			return node, true
		}
	}
	return store.ExitNode{}, false
}

func (s *Server) recordEvent(kind, message string) {
	s.events.record(Event{Kind: kind, Message: message, Time: s.now().UTC()})
}

// bufferedConn exposes a hijacked connection whose buffered reader holds bytes
// that were already consumed from the socket.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// RuntimeInfo describes the control node for the UI.
func (s *Server) RuntimeInfo() map[string]any {
	settings := s.store.Settings()
	s.mu.Lock()
	hubErr := s.hubErr
	hubStatus := s.hubStatus
	endpoints := len(s.endpoints)
	geoReady := s.geoIP != nil && s.geoIP.Ready()
	s.mu.Unlock()
	return map[string]any{
		"version":        version.Version,
		"buildDate":      version.BuildDate,
		"commit":         version.Commit,
		"goVersion":      runtime.Version(),
		"platform":       runtime.GOOS + "/" + runtime.GOARCH,
		"uptimeSec":      int64(s.now().Sub(s.startedAt).Seconds()),
		"listen":         s.Addr(),
		"domain":         s.opts.Domain,
		"publicURL":      s.publicURL(),
		"fingerprint":    s.cert.Fingerprint,
		"publicEndpoint": s.hubEndpoint(""),
		"backend":        s.backend.Name(),
		"interface":      settings.Interface,
		"hubPublicKey":   s.store.Hub().PublicKey,
		"hubError":       hubErr,
		"hubUp":          hubStatus.Exists,
		"knownEndpoints": endpoints,
		"geoipReady":     geoReady,
		"geoip":          s.geoIPStatus(),
		"requests":       s.requestSummaryView(),
		"brandName":      s.BrandName(),
		"brandCSS":       s.customCSSVersion(),
		"customCss":      s.hasCustomCSS(),
	}
}
