// Package agent implements the mesh agent: it enrolls with the control node
// over a pinned TLS connection, keeps its WireGuard device in sync with the
// membership the control node publishes, reports statistics, and decides when a
// peer can be reached directly instead of through the hub.
package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"strings"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proto"
	"github.com/noobtunnel/noobtunnel/internal/topology"
	"github.com/noobtunnel/noobtunnel/internal/version"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// Options configures an agent.
type Options struct {
	// ControlEndpoint is the control node's TLS address, host:port.
	ControlEndpoint string
	Token           string
	// Fingerprint pins the control node certificate: sha256 of the DER, hex,
	// optionally colon separated and optionally prefixed with "sha256:".
	Fingerprint string
	// Insecure disables certificate verification entirely. Lab use only.
	Insecure bool
	// Interface is the WireGuard device name.
	Interface string
	StateDir  string
	// Name overrides the hostname reported to the control node.
	Name string
	// Advertise lists extra CIDRs this agent routes for the mesh.
	Advertise []string
	// AdvertiseAll routes every network this machine can reach.
	AdvertiseAll bool
	// Direct enables opportunistic direct paths to other agents.
	Direct bool
	// KeepInterface leaves the WireGuard device up when the agent exits.
	KeepInterface bool
	// SetupSystem opens the host firewall for the mesh interface at startup. It is
	// on by default in the CLI; false leaves the firewall completely alone.
	SetupSystem bool
	Logger      *slog.Logger
	Backend     wg.Backend
	// DialTimeout bounds a single control connection attempt.
	DialTimeout time.Duration
}

const (
	defaultDialTimeout = 15 * time.Second
	minBackoff         = 2 * time.Second
	maxBackoff         = 60 * time.Second
	// statusInterval is how often local device state is inspected to drive the
	// direct/relayed decision.
	statusInterval = 3 * time.Second
	// natAssertInterval is how often the mesh is re-excluded from the host's NAT
	// rules, so a Docker restart cannot quietly put its masquerade rules back in
	// front of ours.
	natAssertInterval = 30 * time.Second
)

var (
	errRevoked          = errors.New("agent: enrollment revoked by control node")
	errTokenRejected    = errors.New("agent: token rejected")
	errShutdown         = errors.New("agent: shutdown requested")
	errReconnectRequest = errors.New("agent: reconnect requested")
	errNoSession        = errors.New("agent: no active control session")
)

// Agent is a mesh agent instance.
type Agent struct {
	opts      Options
	log       *slog.Logger
	identity  *Identity
	backend   wg.Backend
	advertise []string
	// hostRunner runs host commands (the firewall setup); injectable for tests.
	hostRunner hostRunner

	mu          sync.Mutex
	session     *sessionState
	direct      map[uint32]bool
	candidate   map[uint32]time.Time
	lastApplied string
	// forwardedFor remembers the last carried set the host was opened for, so the
	// firewall commands are not repeated on every membership message.
	forwardedFor string
	startedAt    time.Time

	connectedMu sync.Mutex
	connected   bool
	lastErr     string
}

// sessionState is the membership pushed by the control node.
type sessionState struct {
	welcome    proto.Welcome
	peers      map[uint32]proto.Peer
	generation uint64
	// carry is what the control node resolved to this agent, which is what it has
	// to forward for.
	carry []string
}

// New creates an agent.
func New(opts Options) (*Agent, error) {
	if opts.ControlEndpoint == "" {
		return nil, errors.New("agent: control endpoint is required")
	}
	if !strings.Contains(opts.ControlEndpoint, ":") {
		opts.ControlEndpoint = net.JoinHostPort(opts.ControlEndpoint, "8443")
	}
	if opts.StateDir == "" {
		opts.StateDir = "/var/lib/noobtunnel"
	}
	if opts.Interface == "" {
		opts.Interface = "noobtun"
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = defaultDialTimeout
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if opts.Backend == nil {
		opts.Backend = &wg.ExecBackend{}
	}
	if err := wg.ValidateInterfaceName(opts.Interface); err != nil {
		return nil, err
	}
	identity, err := LoadIdentity(opts.StateDir)
	if err != nil {
		return nil, err
	}
	return &Agent{
		opts:      opts,
		log:       opts.Logger,
		identity:  identity,
		backend:   opts.Backend,
		advertise: advertiseList(opts),
		direct:    map[uint32]bool{},
		candidate: map[uint32]time.Time{},
		startedAt: time.Now(),
	}, nil
}

// Identity returns the agent's persistent identity.
func (a *Agent) Identity() *Identity { return a.identity }

// Backend returns the WireGuard backend in use.
func (a *Agent) Backend() wg.Backend { return a.backend }

// Interface returns the configured device name.
func (a *Agent) Interface() string { return a.opts.Interface }

// Connected reports whether the control channel is currently established.
func (a *Agent) Connected() bool {
	a.connectedMu.Lock()
	defer a.connectedMu.Unlock()
	return a.connected
}

func (a *Agent) setConnected(v bool) {
	a.connectedMu.Lock()
	a.connected = v
	a.connectedMu.Unlock()
	if !v {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		a.saveRuntime(ctx)
	}
}

// saveRuntime records what this agent knows locally, so `noobtunnel status`
// works without a control connection.
func (a *Agent) saveRuntime(ctx context.Context) {
	st := &RuntimeState{
		Interface:   a.opts.Interface,
		ControlNode: a.opts.ControlEndpoint,
		Connected:   a.Connected(),
		Backend:     a.backend.Name(),
		LastError:   a.lastError(),
	}
	welcome, peers, direct, _, ok := a.snapshot()
	if ok {
		st.AgentID = welcome.AgentID
		st.AgentName = welcome.Name
		st.Address = prefixString(welcome.Address, welcome.Prefix)
		st.MeshCIDR = welcome.MeshCIDR
		st.HubEndpoint = welcome.Hub.Endpoint
		st.MTU = welcome.MTU
	}
	if status, err := a.backend.Status(ctx, a.opts.Interface); err == nil {
		st.Routes = routesFromStatus(status)
		if st.MTU == 0 {
			st.MTU = status.MTU
		}
		byKey := map[string]proto.Peer{}
		for _, p := range peers {
			byKey[p.PublicKey] = p
		}
		for _, ps := range status.Peers {
			peer, known := byKey[ps.PublicKey]
			if !known {
				continue
			}
			mode := "relay"
			if direct[peer.ID] {
				mode = "direct"
			}
			st.Peers = append(st.Peers, PeerRow{
				ID:        peer.ID,
				Name:      peer.Name,
				Address:   peer.Address,
				Mode:      mode,
				Endpoint:  ps.Endpoint,
				Handshake: ps.LatestHandshake,
				RxBytes:   ps.RxBytes,
				TxBytes:   ps.TxBytes,
			})
		}
	}
	if err := writeRuntime(a.opts.StateDir, st); err != nil {
		a.log.Debug("could not write runtime state", "error", err)
	}
}

func routesFromStatus(status wg.InterfaceStatus) []string {
	var routes []string
	for _, addr := range status.Addresses {
		routes = append(routes, addr)
	}
	return routes
}

func (a *Agent) setLastError(msg string) {
	a.connectedMu.Lock()
	a.lastErr = msg
	a.connectedMu.Unlock()
}

func (a *Agent) lastError() string {
	a.connectedMu.Lock()
	defer a.connectedMu.Unlock()
	return a.lastErr
}

// Run connects to the control node and stays connected until ctx is cancelled
// or the control node revokes this agent.
func (a *Agent) Run(ctx context.Context) error {
	defer a.shutdown()
	// The mesh interface is this machine's, so the host firewall has to accept
	// traffic on it: a default-deny firewall answers every packet from the tunnel
	// with ICMP host-prohibited, which looks like "no route to host" on the
	// control node while the service here is fine.
	if runtime.GOOS == "linux" {
		a.setupHost(ctx)
	}
	backoff := minBackoff
	for {
		start := time.Now()
		err := a.controlSession(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return nil
		}
		switch {
		case errors.Is(err, errRevoked), errors.Is(err, errTokenRejected):
			a.setLastError(err.Error())
			return err
		case errors.Is(err, errShutdown):
			a.log.Info("stopping on control node request")
			return nil
		}
		a.setLastError(err.Error())
		a.log.Warn("control connection ended, retrying", "error", err, "in", backoff.Round(time.Second))
		if time.Since(start) > 60*time.Second {
			backoff = minBackoff
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// controlSession runs one control channel connection to completion.
func (a *Agent) controlSession(ctx context.Context) error {
	conn, err := a.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write(proto.Magic); err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	hello := proto.Hello{
		T:         proto.THello,
		Token:     a.opts.Token,
		PublicKey: a.identity.PublicKey,
		Name:      a.opts.Name,
		Version:   version.Version,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Hostname:  hostname,
		Advertise: a.advertise,
		Direct:    a.opts.Direct,
	}
	if writeErr := proto.WriteJSON(conn, hello); writeErr != nil {
		return writeErr
	}

	writer := &connWriter{conn: conn}
	msgs := make(chan rawMessage, 128)
	readErr := make(chan error, 1)
	go readLoop(conn, msgs, readErr)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-readErr:
		return err
	case msg := <-msgs:
		if err := a.handleFirstMessage(msg); err != nil {
			return err
		}
	}
	a.setConnected(true)
	a.setLastError("")
	defer a.setConnected(false)
	a.log.Info("connected to control node",
		"endpoint", a.opts.ControlEndpoint,
		"address", a.currentAddress(),
		"interface", a.opts.Interface,
		"backend", a.backend.Name())

	statsTicker := time.NewTicker(a.statsInterval())
	defer statsTicker.Stop()
	stateTicker := time.NewTicker(statusInterval)
	defer stateTicker.Stop()
	// The host NAT rule has to stay ahead of the ones Docker inserts, and Docker
	// reinstates its own whenever the daemon or a network is created, so it is
	// re-asserted while the agent runs instead of only at enrollment.
	natTicker := time.NewTicker(natAssertInterval)
	defer natTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = writer.send(proto.Bye{T: proto.TBye, Reason: "shutdown"})
			return ctx.Err()
		case err := <-readErr:
			if err == nil {
				err = errors.New("control connection closed by peer")
			}
			return err
		case msg := <-msgs:
			if err := a.handleMessage(msg, writer); err != nil {
				return err
			}
		case <-statsTicker.C:
			if err := writer.send(a.collectStats(ctx)); err != nil {
				return err
			}
		case <-stateTicker.C:
			if err := a.reconcile(ctx); err != nil {
				a.setLastError(err.Error())
				a.log.Debug("reconcile failed", "error", err)
			}
		case <-natTicker.C:
			a.ensureRoutes(ctx)
			if runtime.GOOS == "linux" {
				// Docker reinstates its own chains in front of ours, so the mesh
				// rules are re-asserted rather than assumed.
				a.allowMeshTraffic(ctx)
				a.meshNATExempt(ctx, a.meshCIDR())
			}
		}
	}
}

func (a *Agent) statsInterval() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	sec := 5
	if a.session != nil && a.session.welcome.StatsIntervalSec > 0 {
		sec = a.session.welcome.StatsIntervalSec
	}
	return time.Duration(sec) * time.Second
}

func (a *Agent) currentAddress() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil {
		return ""
	}
	return prefixString(a.session.welcome.Address, a.session.welcome.Prefix)
}

// ensureRoutes re-asserts the kernel routes the tunnel needs.
//
// A device can be up, handshaking and carrying traffic and still have no route
// for the mesh range: the table can be rewritten by another tool, and an install
// that failed once must not be remembered as done. Without the route, every
// answer the tunnel receives is sent out of this machine's default gateway, so
// the far end sees a healthy tunnel and a service that never replies.
func (a *Agent) ensureRoutes(ctx context.Context) {
	cfg, err := a.desiredConfig()
	if err != nil || len(cfg.Routes) == 0 {
		return
	}
	if err := a.backend.EnsureRoutes(ctx, a.opts.Interface, cfg.Routes); err != nil {
		a.setLastError(err.Error())
		a.log.Warn("could not install the mesh routes", "error", err)
	}
}

// meshCIDR is the overlay range, as announced by the control node. Empty until
// this agent has enrolled.
func (a *Agent) meshCIDR() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil {
		return ""
	}
	return a.session.welcome.MeshCIDR
}

// snapshot returns a consistent copy of the current membership.
func (a *Agent) snapshot() (proto.Welcome, []proto.Peer, map[uint32]bool, uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil {
		return proto.Welcome{}, nil, nil, 0, false
	}
	peers := make([]proto.Peer, 0, len(a.session.peers))
	for _, id := range sortedIDs(a.session.peers) {
		peers = append(peers, a.session.peers[id])
	}
	direct := make(map[uint32]bool, len(a.direct))
	for id, v := range a.direct {
		direct[id] = v
	}
	return a.session.welcome, peers, direct, a.session.generation, true
}

func sortedIDs(m map[uint32]proto.Peer) []uint32 {
	ids := make([]uint32, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}

func (a *Agent) handleFirstMessage(msg rawMessage) error {
	switch msg.typ {
	case proto.TWelcome:
		var welcome proto.Welcome
		if err := json.Unmarshal(msg.raw, &welcome); err != nil {
			return err
		}
		a.mu.Lock()
		a.session = &sessionState{
			welcome:    welcome,
			peers:      map[uint32]proto.Peer{},
			generation: welcome.Generation,
		}
		for _, p := range welcome.Peers {
			a.session.peers[p.ID] = p
		}
		a.mu.Unlock()
		a.setCarry(welcome.Carry)
		a.log.Info("enrolled with control node",
			"agentID", welcome.AgentID,
			"name", welcome.Name,
			"address", prefixString(welcome.Address, welcome.Prefix),
			"mesh", welcome.MeshCIDR,
			"peers", len(welcome.Peers),
			"hub", welcome.Hub.Endpoint)
		// The mesh range is only known after enrollment, and it is what keeps
		// Docker's masquerade rules from rewriting answers that come back
		// through the tunnel.
		if runtime.GOOS == "linux" {
			a.meshNATExempt(context.Background(), welcome.MeshCIDR)
			a.syncCarriedForwarding(context.Background())
		}
		return a.applyDevice(context.Background(), true)
	case proto.TError:
		var e proto.Error
		_ = json.Unmarshal(msg.raw, &e)
		if e.Code == "token" {
			return fmt.Errorf("%w: %s", errTokenRejected, e.Message)
		}
		return fmt.Errorf("agent: control node rejected enrollment: %s", e.Message)
	default:
		return fmt.Errorf("agent: unexpected first message %q", msg.typ)
	}
}

func (a *Agent) handleMessage(msg rawMessage, writer *connWriter) error {
	switch msg.typ {
	case proto.TPeers:
		var p proto.Peers
		if err := json.Unmarshal(msg.raw, &p); err != nil {
			return err
		}
		a.updatePeers(p.Generation, p.Peers)
		// The membership message carries what the mesh routes through this agent,
		// which changes when the operator edits its networks.
		if a.setCarry(p.Carry) && runtime.GOOS == "linux" {
			go a.syncCarriedForwarding(context.Background())
		}
		return a.reconcile(context.Background())
	case proto.TPing:
		var ping proto.Ping
		if err := json.Unmarshal(msg.raw, &ping); err != nil {
			return err
		}
		return writer.send(proto.Pong{T: proto.TPong, Seq: ping.Seq})
	case proto.TCommand:
		var cmd proto.Command
		if err := json.Unmarshal(msg.raw, &cmd); err != nil {
			return err
		}
		switch cmd.Action {
		case proto.ActionReconnect:
			a.log.Info("reconnect requested by control node")
			return errReconnectRequest
		case proto.ActionResync:
			a.log.Info("resync requested by control node")
			return a.applyDevice(context.Background(), true)
		case proto.ActionShutdown:
			return errShutdown
		case proto.ActionProbe:
			// Probing means making connections, which must not hold up the read
			// loop that keeps the rest of the mesh in sync.
			go a.probeTargets(cmd, writer)
		}
		return nil
	case proto.TRevoked:
		var rev proto.Revoked
		_ = json.Unmarshal(msg.raw, &rev)
		a.log.Error("control node revoked this agent", "reason", rev.Reason)
		return errRevoked
	case proto.TError:
		var e proto.Error
		_ = json.Unmarshal(msg.raw, &e)
		a.log.Error("control node reported an error", "code", e.Code, "message", e.Message)
		return nil
	default:
		a.log.Debug("ignoring control message", "type", msg.typ)
		return nil
	}
}

func (a *Agent) updatePeers(generation uint64, peers []proto.Peer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil {
		return
	}
	a.session.peers = map[uint32]proto.Peer{}
	for _, p := range peers {
		a.session.peers[p.ID] = p
	}
	a.session.generation = generation
}

// setCarry records what the mesh routes through this agent and reports whether it
// changed, so the host setup only runs when there is something new to apply.
func (a *Agent) setCarry(prefixes []string) bool {
	joined := strings.Join(prefixes, ",")
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil {
		return false
	}
	if strings.Join(a.session.carry, ",") == joined {
		return false
	}
	a.session.carry = append([]string(nil), prefixes...)
	return true
}

// carriedPrefixes is what the control node resolved to this agent.
func (a *Agent) carriedPrefixes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil {
		return nil
	}
	return append([]string(nil), a.session.carry...)
}

// advertises reports whether this agent has to forward for anything: either what
// it offered at enrollment, or what the control node decided to route through it.
func (a *Agent) advertises() bool {
	if a.opts.AdvertiseAll || len(a.opts.Advertise) > 0 {
		return true
	}
	return len(a.carriedPrefixes()) > 0
}

// syncCarriedForwarding opens the host's forwarding rules for the networks the
// mesh routes through this agent.
//
// It runs whenever that set changes, because the networks an operator adds in the
// UI after enrollment never reach the machine any other way: without this the hub
// would route a network here and the host would drop every packet for it, which
// looks exactly like a service that is down.
func (a *Agent) syncCarriedForwarding(ctx context.Context) {
	if !a.advertises() {
		return
	}
	carry := a.carriedPrefixes()
	if a.forwardedFor == strings.Join(carry, ",") {
		return
	}
	a.forwardedFor = strings.Join(carry, ",")
	a.log.Info("the mesh routes networks through this agent: opening host forwarding",
		"networks", strings.Join(carry, ", "))
	a.allowMeshTraffic(ctx)
}

// reconcile recomputes path ownership from the live device and applies changes.
func (a *Agent) reconcile(ctx context.Context) error {
	welcome, peers, _, _, ok := a.snapshot()
	if !ok {
		return nil
	}
	status, err := a.backend.Status(ctx, a.opts.Interface)
	if err != nil {
		return err
	}
	now := time.Now()
	fresh := time.Duration(a.freshWindow(welcome)) * time.Second
	probe := time.Duration(a.probeWindow(welcome)) * time.Second

	var promoted, demoted []string
	a.mu.Lock()
	for _, peer := range peers {
		if peer.ID == welcome.AgentID || !peer.Direct || peer.Endpoint == "" {
			continue
		}
		healthy := false
		if st, found := status.PeerByKey(peer.PublicKey); found && !st.LatestHandshake.IsZero() {
			healthy = now.Sub(st.LatestHandshake) <= fresh
		}
		if a.direct[peer.ID] {
			if !healthy {
				a.direct[peer.ID] = false
				delete(a.candidate, peer.ID)
				demoted = append(demoted, peer.Name)
			}
			continue
		}
		if !healthy {
			delete(a.candidate, peer.ID)
			continue
		}
		since, seen := a.candidate[peer.ID]
		if !seen {
			a.candidate[peer.ID] = now
			continue
		}
		if now.Sub(since) >= probe {
			a.direct[peer.ID] = true
			delete(a.candidate, peer.ID)
			promoted = append(promoted, peer.Name)
		}
	}
	a.mu.Unlock()

	if len(promoted) > 0 {
		a.log.Info("direct path established", "peers", strings.Join(promoted, ", "))
	}
	if len(demoted) > 0 {
		a.log.Warn("direct path lost, falling back to the relay", "peers", strings.Join(demoted, ", "))
	}
	return a.applyDevice(ctx, len(promoted) > 0 || len(demoted) > 0)
}

func (a *Agent) freshWindow(welcome proto.Welcome) int {
	if welcome.DirectFreshSec > 0 {
		return welcome.DirectFreshSec
	}
	return 180
}

func (a *Agent) probeWindow(welcome proto.Welcome) int {
	if welcome.DirectProbeSec > 0 {
		return welcome.DirectProbeSec
	}
	return 30
}

// applyDevice renders and programs the desired configuration.
func (a *Agent) applyDevice(ctx context.Context, force bool) error {
	cfg, err := a.desiredConfig()
	if err != nil {
		return err
	}
	rendered := cfg.Render()
	a.mu.Lock()
	sameConfig := a.lastApplied == rendered
	if sameConfig && !force {
		a.mu.Unlock()
		return nil
	}
	a.lastApplied = rendered
	a.mu.Unlock()

	if err := a.backend.Sync(ctx, a.opts.Interface, cfg); err != nil {
		a.setLastError(err.Error())
		return err
	}
	a.setLastError("")
	// Re-applying the same configuration (a forced resync, a retry after a
	// failure) is worth a line in the file only when someone is debugging: the
	// interesting line is the one that describes a change.
	level := slog.LevelInfo
	if sameConfig {
		level = slog.LevelDebug
	}
	a.log.Log(ctx, level, "wireguard device in sync",
		"addresses", cfg.Interface.Addresses,
		"peers", len(cfg.Peers),
		"routes", len(cfg.Routes))
	a.saveRuntime(ctx)
	return nil
}

// desiredConfig builds the WireGuard configuration the agent should run.
func (a *Agent) desiredConfig() (wg.Config, error) {
	welcome, peers, direct, _, ok := a.snapshot()
	if !ok {
		return wg.Config{}, errNoSession
	}
	meshPrefix, err := netip.ParsePrefix(welcome.MeshCIDR)
	if err != nil {
		return wg.Config{}, fmt.Errorf("agent: control node sent an invalid mesh range %q: %w", welcome.MeshCIDR, err)
	}
	selfAddr, err := netip.ParseAddr(welcome.Address)
	if err != nil {
		return wg.Config{}, err
	}
	hubAddr, err := netip.ParseAddr(welcome.Hub.Address)
	if err != nil {
		return wg.Config{}, err
	}
	in := topology.AgentInput{
		Mesh: topology.Mesh{
			CIDR:          meshPrefix,
			MTU:           welcome.MTU,
			KeepaliveSec:  welcome.KeepaliveSec,
			DirectEnabled: a.opts.Direct,
		},
		Self: topology.Member{ID: welcome.AgentID, Name: welcome.Name, Address: selfAddr},
		Hub: topology.HubMember{
			Address:      hubAddr,
			PublicKey:    welcome.Hub.PublicKey,
			Endpoint:     welcome.Hub.Endpoint,
			PresharedKey: welcome.Hub.PresharedKey,
		},
		PairKeys:   map[uint32]string{},
		Direct:     direct,
		PrivateKey: a.identity.PrivateKey,
	}
	for _, p := range peers {
		if p.ID == welcome.AgentID {
			continue
		}
		addr, err := netip.ParseAddr(p.Address)
		if err != nil {
			continue
		}
		member := topology.Member{
			ID:        p.ID,
			Name:      p.Name,
			Address:   addr,
			PublicKey: p.PublicKey,
			Endpoint:  p.Endpoint,
			Online:    p.Online,
			Enabled:   true,
		}
		for _, raw := range p.Advertise {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				member.Advertise = append(member.Advertise, prefix)
			}
		}
		in.Peers = append(in.Peers, member)
		in.PairKeys[p.ID] = p.PresharedKey
	}
	cfg, _ := topology.BuildAgentConfig(in)
	return cfg, nil
}

// collectStats reads the live device state and packages it for the control node.
func (a *Agent) collectStats(ctx context.Context) proto.Stats {
	welcome, peers, direct, generation, ok := a.snapshot()
	stats := proto.Stats{
		T:         proto.TStats,
		UptimeSec: int64(time.Since(a.startedAt).Seconds()),
		Backend:   a.backend.Name(),
		LastError: a.lastError(),
	}
	if ok {
		stats.Generation = generation
	}
	status, err := a.backend.Status(ctx, a.opts.Interface)
	if err != nil {
		stats.LastError = err.Error()
		return stats
	}
	stats.Interface = status.Name
	stats.MTU = status.MTU
	var totalRx, totalTx uint64
	for _, p := range status.Peers {
		totalRx += p.RxBytes
		totalTx += p.TxBytes
	}
	stats.RxBytes, stats.TxBytes = totalRx, totalTx
	if !ok {
		return stats
	}
	byKey := map[string]uint32{welcome.Hub.PublicKey: 0}
	for _, peer := range peers {
		byKey[peer.PublicKey] = peer.ID
	}
	for _, p := range status.Peers {
		id, known := byKey[p.PublicKey]
		if !known {
			continue
		}
		stats.PeerStats = append(stats.PeerStats, proto.PeerStat{
			ID:              id,
			PublicKey:       p.PublicKey,
			Endpoint:        p.Endpoint,
			LatestHandshake: unixNanoOrZero(p.LatestHandshake),
			RxBytes:         p.RxBytes,
			TxBytes:         p.TxBytes,
			Direct:          direct[id],
		})
	}
	return stats
}

func (a *Agent) shutdown() {
	if a.opts.KeepInterface {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.backend.Down(ctx, a.opts.Interface); err != nil {
		a.log.Warn("failed to remove wireguard device", "error", err)
	}
}

// dial opens the TLS control channel, pinning the control node certificate.
func (a *Agent) dial(ctx context.Context) (net.Conn, error) {
	host, _, err := net.SplitHostPort(a.opts.ControlEndpoint)
	if err != nil {
		return nil, fmt.Errorf("agent: invalid control endpoint %q: %w", a.opts.ControlEndpoint, err)
	}
	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	switch {
	case a.opts.Insecure:
		tlsCfg.InsecureSkipVerify = true
	case a.opts.Fingerprint != "":
		want, err := normaliseFingerprint(a.opts.Fingerprint)
		if err != nil {
			return nil, err
		}
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("agent: control node presented no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !equalBytes(sum[:], want) {
				return fmt.Errorf("agent: control node certificate does not match the pinned fingerprint (got %s)",
					hex.EncodeToString(sum[:]))
			}
			return nil
		}
	}
	dialer := &net.Dialer{Timeout: a.opts.DialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", a.opts.ControlEndpoint, tlsCfg)
	if err != nil {
		return nil, err
	}
	// The control channel starts life as an HTTP upgrade so it can share the
	// same TLS listener as the web UI.
	if _, err := conn.Write(proto.UpgradeRequest(a.opts.ControlEndpoint)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("agent: control node did not answer the upgrade request: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		_ = conn.Close()
		detail := strings.TrimSpace(string(body))
		if detail == "" {
			detail = response.Status
		}
		return nil, fmt.Errorf("agent: control node refused the control channel (%s): %s", response.Status, firstLine(detail))
	}
	return &bufferedConn{Conn: conn, r: reader}, nil
}

func firstLine(s string) string {
	if index := strings.IndexByte(s, '\n'); index >= 0 {
		return strings.TrimSpace(s[:index])
	}
	return s
}

// bufferedConn keeps using the reader that already buffered the HTTP response.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func normaliseFingerprint(s string) ([]byte, error) {
	raw := strings.TrimSpace(strings.ToLower(s))
	raw = strings.TrimPrefix(raw, "sha256:")
	raw = strings.ReplaceAll(raw, ":", "")
	raw = strings.ReplaceAll(raw, " ", "")
	sum, err := hex.DecodeString(raw)
	if err != nil || len(sum) != sha256.Size {
		return nil, fmt.Errorf("agent: %q is not a sha256 certificate fingerprint", s)
	}
	return sum, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func prefixString(addr string, prefix int) string {
	if addr == "" {
		return ""
	}
	if prefix == 0 {
		prefix = 32
	}
	return fmt.Sprintf("%s/%d", addr, prefix)
}

func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// connWriter serialises writes to the control connection.
type connWriter struct {
	mu   sync.Mutex
	conn net.Conn
}

func (w *connWriter) send(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return proto.WriteJSON(w.conn, v)
}

type rawMessage struct {
	typ string
	raw []byte
}

func readLoop(conn net.Conn, out chan<- rawMessage, errCh chan<- error) {
	for {
		typ, raw, err := proto.ReadRaw(conn)
		if err != nil {
			select {
			case errCh <- err:
			default:
			}
			return
		}
		select {
		case out <- rawMessage{typ: typ, raw: raw}:
		case <-time.After(30 * time.Second):
			// The consumer is not draining; drop the connection rather than
			// growing an unbounded queue.
			select {
			case errCh <- errors.New("agent: control message queue stalled"):
			default:
			}
			return
		}
	}
}
