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
	// GeoIPLicenceKey (and account id) enable country rules: the control node
	// downloads the MaxMind GeoLite2-Country database at startup.
	GeoIPLicenceKey string
	GeoIPAccountID  string
	// GeoIPDir holds a database the operator downloaded, and is where a
	// downloaded one is cached.
	GeoIPDir string
	// DialTimeout bounds agent ping responses.
	PingTimeout time.Duration

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

	mu         sync.Mutex
	geoIP      *geoip.Database
	geoIPError string
	requests   *requestLog
	sessions   map[uint32]*Session
	endpoints  map[uint32]string
	pending    map[uint64]*pendingPing
	hubStatus  wg.InterfaceStatus
	hubErr     string
	rejected   []topology.Rejected
	peerStats  map[uint32]map[uint32]proto.PeerStat
	peerDirty  bool
	checks     []Check
	checksAt   time.Time
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
	return &Server{
		opts:      opts,
		log:       opts.Logger,
		store:     st,
		auth:      auth,
		cert:      cert,
		backend:   opts.Backend,
		commands:  opts.Runner,
		events:    newEventHub(),
		proxies:   newProxyManager(opts, st, auth, requestEvents),
		requests:  requestEvents,
		sessions:  map[uint32]*Session{},
		endpoints: map[uint32]string{},
		pending:   map[uint64]*pendingPing{},
		peerStats: map[uint32]map[uint32]proto.PeerStat{},
		startedAt: time.Now(),
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
	s.wg.Add(5)
	go func() { defer s.wg.Done(); s.discoveryLoop(ctx) }()
	go func() { defer s.wg.Done(); s.peerPushLoop(ctx) }()
	go func() { defer s.wg.Done(); s.latencyLoop(ctx) }()
	go func() { defer s.wg.Done(); s.resourceLoop(ctx) }()
	go func() { defer s.wg.Done(); s.dnsLoop(ctx) }()
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
	st := s.store.View()
	settings := st.Settings
	pool, err := ipam.New(settings.MeshCIDR)
	if err != nil {
		return err
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
				if err := sess.send(proto.Peers{T: proto.TPeers, Generation: generation, Peers: peers}); err != nil {
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
	// A resource may have changed which exit node its domain points at.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.syncDomains(ctx)
	}()
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
			targets = append(targets, proxy.TargetSpec{ID: t.ID, Host: t.Host, Port: t.Port})
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
	geoReady := s.geoIP != nil && s.geoIP.Loaded()
	s.mu.Unlock()
	return map[string]any{
		"version":        version.Version,
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
