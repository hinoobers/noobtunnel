package control_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/agent"
	"github.com/noobtunnel/noobtunnel/internal/control"
	"github.com/noobtunnel/noobtunnel/internal/dns"
	"github.com/noobtunnel/noobtunnel/internal/geoip"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/wg"
	"net/http/httptest"
)

func quietLogger() *slog.Logger {
	if os.Getenv("NOOBTUNNEL_TEST_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// harness runs a control node with simulated agents on the loopback interface.
type harness struct {
	t       *testing.T
	server  *control.Server
	network *wg.FakeNetwork
	hub     *wg.FakeBackend
	address string
	dir     string
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	agents  map[uint32]*simAgent
}

type simAgent struct {
	id       uint32
	name     string
	agent    *agent.Agent
	device   *wg.FakeBackend
	runErr   chan error
	stateDir string
}

func newHarness(t *testing.T, direct bool) *harness {
	return newHarnessWith(t, direct, "")
}

// newHarnessWithBinaryDir builds a harness that serves agent binaries from dir.
func newHarnessWithBinaryDir(t *testing.T, binaryDir string) *harness {
	return newHarnessWith(t, true, binaryDir)
}

func newHarnessWith(t *testing.T, direct bool, binaryDir string) *harness {
	return newHarnessOpts(t, direct, binaryDir, nil)
}

// newHarnessWithRunner starts a control node whose host commands go to runner.
func newHarnessWithRunner(t *testing.T, runner wg.Runner) *harness {
	return newHarnessOpts(t, true, "", func(opts *control.Options) {
		opts.Runner = runner
	})
}

// newHarnessWithDNS starts a control node whose DNS client talks to baseURL.
func newHarnessWithDNS(t *testing.T, baseURL string) *harness {
	return newHarnessOpts(t, true, "", func(opts *control.Options) {
		opts.DNSFactory = func(provider store.DNSProvider) (control.DNSClient, error) {
			return &dns.Cloudflare{
				Token:   provider.Token,
				BaseURL: baseURL,
				Client:  &http.Client{Timeout: 5 * time.Second},
				TTL:     1,
			}, nil
		}
	})
}

// addExitNode registers an extra public address and returns its id.
func (h *harness) addExitNode(t *testing.T, name, address string) string {
	t.Helper()
	status, body, _ := h.api("POST", "/api/exitnodes", map[string]any{
		"name": name, "kind": "address", "address": address,
	}, h.login(t))
	if status != http.StatusOK {
		t.Fatalf("adding an exit node returned %d: %s", status, body)
	}
	var created struct {
		ExitNode struct {
			ID string `json:"id"`
		} `json:"exitNode"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	return created.ExitNode.ID
}

func newHarnessOpts(t *testing.T, direct bool, binaryDir string, mutate func(*control.Options)) *harness {
	return newHarnessOnDir(t, direct, binaryDir, "", mutate)
}

// newHarnessOnDir starts a control node in a specific state directory, which is
// how tests simulate restarting the server.
func newHarnessOnDir(t *testing.T, direct bool, binaryDir, stateDir string, mutate func(*control.Options)) *harness {
	t.Helper()
	dir := stateDir
	if dir == "" {
		dir = t.TempDir()
	}
	network := wg.NewFakeNetwork()
	// The hub simulates a VPS with a public address, which is what agents dial.
	hub := &wg.FakeBackend{Network: network, Label: "hub", PublicEndpoint: "203.0.113.1:51820"}
	opts := control.Options{
		StateDir:      dir,
		Listen:        "127.0.0.1:0",
		Backend:       hub,
		Logger:        quietLogger(),
		AdminPassword: "correct-horse-battery-staple",
		SetupSystem:   false,
		PingTimeout:   3 * time.Second,
		BinaryDir:     binaryDir,
	}
	if mutate != nil {
		mutate(&opts)
	}
	server, err := control.New(opts)
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	if err := server.Store().Update(func(st *store.State) error {
		st.Settings.DirectPaths = direct
		st.Settings.DirectProbeSec = 1
		st.Settings.StatsIntervalSec = 1
		return nil
	}); err != nil {
		t.Fatalf("configure settings: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	h := &harness{
		t: t, server: server, network: network, hub: hub,
		cancel: cancel, done: make(chan struct{}), dir: dir, agents: map[uint32]*simAgent{},
	}
	go func() {
		defer close(h.done)
		_ = server.Run(ctx)
	}()
	waitFor(t, "control node to listen", 10*time.Second, func() bool {
		host, port, err := net.SplitHostPort(server.Addr())
		if err != nil || port == "0" || port == "" {
			return false
		}
		if host == "" || host == "::" || host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		address := net.JoinHostPort(host, port)
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		h.address = address
		return true
	})
	return h
}

// stop shuts the control node down and waits for it to release its ports.
func (h *harness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(20 * time.Second):
		h.t.Fatal("the control node did not stop")
	}
}

// addAgent enrolls a simulated machine. reachable=false simulates a symmetric
// NAT that can never be dialled directly.
func (h *harness) addAgent(name string, reachable bool) *simAgent {
	h.t.Helper()
	created, err := h.server.Store().AddAgent(store.AddAgentParams{Name: name})
	if err != nil {
		h.t.Fatalf("AddAgent(%s): %v", name, err)
	}
	device := &wg.FakeBackend{
		Network:   h.network,
		Label:     fmt.Sprintf("agent-%d", created.ID),
		OverlayIP: created.Address,
	}
	if reachable {
		device.PublicEndpoint = fmt.Sprintf("203.0.113.%d:51820", 20+created.ID)
	} else {
		device.NoPublicEndpoint = true
	}
	stateDir := h.t.TempDir()
	instance, err := agent.New(agent.Options{
		ControlEndpoint: h.address,
		Token:           created.Token,
		Fingerprint:     h.server.Cert().Fingerprint,
		Interface:       "noobtest",
		StateDir:        stateDir,
		Name:            created.Name,
		Direct:          h.server.Settings().DirectPaths,
		KeepInterface:   true,
		Logger:          quietLogger(),
		Backend:         device,
	})
	if err != nil {
		h.t.Fatalf("agent.New: %v", err)
	}
	sim := &simAgent{id: created.ID, name: created.Name, agent: instance, device: device, runErr: make(chan error, 1), stateDir: stateDir}
	go func() { sim.runErr <- instance.Run(context.Background()) }()
	h.mu.Lock()
	h.agents[created.ID] = sim
	h.mu.Unlock()
	return sim
}

func (h *harness) agentByID(id uint32) *simAgent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.agents[id]
}

func (h *harness) onlineCount() int { return len(h.server.ConnectedAgentIDs()) }

func (h *harness) client() *http.Client {
	pool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(h.server.Cert().DER)
	if err != nil {
		h.t.Fatalf("parse certificate: %v", err)
	}
	pool.AddCert(cert)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"},
		},
	}
}

func (h *harness) api(method, path string, body any, cookies []*http.Cookie) (int, []byte, []*http.Cookie) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = strings.NewReader(string(raw))
	}
	request, err := http.NewRequest(method, "https://"+h.address+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	request.Header.Set("X-Noobtunnel", "1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := h.client().Do(request)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, raw, response.Cookies()
}

func waitFor(t *testing.T, what string, timeout time.Duration, check func() bool) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		if check() {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
	return ""
}

func TestMeshEnrollmentAndAddressing(t *testing.T) {
	h := newHarness(t, true)
	first := h.addAgent("homelab-nas", true)
	second := h.addAgent("raspberry-pi", true)

	waitFor(t, "both agents to be online", 15*time.Second, func() bool { return h.onlineCount() == 2 })
	waitFor(t, "both agents to be enrolled", 15*time.Second, func() bool {
		a, err := h.server.Store().Agent(first.id)
		if err != nil || a.PublicKey == "" {
			return false
		}
		b, err := h.server.Store().Agent(second.id)
		return err == nil && b.PublicKey != ""
	})

	st := h.server.Store().View()
	addresses := map[string]bool{}
	for _, a := range st.Agents {
		if addresses[a.Address] {
			t.Fatalf("duplicate mesh address %s", a.Address)
		}
		addresses[a.Address] = true
		if a.Address == "10.77.0.1" {
			t.Fatal("an agent must never own the hub address")
		}
	}

	// The hub device must have one peer per enrolled agent, each carrying its
	// /32 and the pairwise preshared key.
	status, err := h.hub.Status(context.Background(), "noobtest")
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Peers) != 2 {
		t.Fatalf("hub has %d peers, want 2", len(status.Peers))
	}
	for _, peer := range status.Peers {
		if !peer.HasPresharedKey {
			t.Fatalf("hub peer %s has no preshared key", peer.PublicKey)
		}
		if len(peer.AllowedIPs) != 1 || !strings.HasSuffix(peer.AllowedIPs[0], "/32") {
			t.Fatalf("hub peer allowed ips = %v", peer.AllowedIPs)
		}
	}
}

func TestDirectPathPromotionAndDistinctAddresses(t *testing.T) {
	h := newHarness(t, true)
	a := h.addAgent("direct-a", true)
	b := h.addAgent("direct-b", true)
	waitFor(t, "both agents online", 15*time.Second, func() bool { return h.onlineCount() == 2 })

	waitFor(t, "agent keys to be learned", 15*time.Second, func() bool {
		agentA, err := h.server.Store().Agent(a.id)
		return err == nil && agentA.PublicKey != ""
	})
	agentB, _ := h.server.Store().Agent(b.id)

	// Once the direct handshake completes, the peer's /32 must move from the
	// hub peer to the direct peer entry.
	waitFor(t, "a direct path to be promoted", 20*time.Second, func() bool {
		return len(a.device.PeerAllowedIPs(agentB.PublicKey)) > 0
	})
	direct := a.device.PeerAllowedIPs(agentB.PublicKey)
	if !containsString(direct, agentB.Address+"/32") {
		t.Fatalf("direct peer should own %s/32, got %v", agentB.Address, direct)
	}
	hubAllowed := a.device.PeerAllowedIPs(h.server.Store().Hub().PublicKey)
	if containsString(hubAllowed, agentB.Address+"/32") {
		t.Fatalf("hub must give up %s/32 once the path is direct, got %v", agentB.Address, hubAllowed)
	}
	if !containsString(hubAllowed, "10.77.0.1/32") {
		t.Fatalf("hub peer should still own the hub address: %v", hubAllowed)
	}

	// Age the handshake: the agent must notice and fall back to the relay.
	a.device.ForceExpireHandshakes(10 * time.Minute)
	waitFor(t, "fallback to the relay", 20*time.Second, func() bool {
		hub := a.device.PeerAllowedIPs(h.server.Store().Hub().PublicKey)
		return containsString(hub, agentB.Address+"/32")
	})
}

func TestSymmetricNATPeerStaysRelayed(t *testing.T) {
	h := newHarness(t, true)
	a := h.addAgent("reachable", true)
	nat := h.addAgent("behind-cgnat", false)
	waitFor(t, "both agents online", 15*time.Second, func() bool { return h.onlineCount() == 2 })
	waitFor(t, "the reachable agent to enroll", 15*time.Second, func() bool {
		got, err := h.server.Store().Agent(a.id)
		return err == nil && got.PublicKey != ""
	})
	natAgent, _ := h.server.Store().Agent(nat.id)

	// Give the agents time to try (and fail) a direct handshake.
	time.Sleep(4 * time.Second)

	if got := a.device.PeerAllowedIPs(natAgent.PublicKey); len(got) != 0 {
		t.Fatalf("a symmetric NAT peer must never claim prefixes, got %v", got)
	}
	hubAllowed := a.device.PeerAllowedIPs(h.server.Store().Hub().PublicKey)
	if !containsString(hubAllowed, natAgent.Address+"/32") {
		t.Fatalf("the hub should carry the unreachable peer, got %v", hubAllowed)
	}
	if !a.device.Established(hubKey(h)) {
		t.Fatal("the reachable agent should have a session with the hub")
	}
	// The control node must not have discovered an endpoint for the NAT'd peer.
	if endpoint := endpointFor(t, h, nat.id); endpoint != "" {
		t.Fatalf("expected no discovered endpoint for the NAT'd peer, got %q", endpoint)
	}
}

func endpointFor(t *testing.T, h *harness, id uint32) string {
	t.Helper()
	st := h.server.StateSnapshot()
	for _, view := range st.Agents {
		if view.ID == id {
			return view.Endpoint
		}
	}
	t.Fatalf("agent %d missing from state", id)
	return ""
}

func TestPeerSessionsAreEstablishedOverTheTunnel(t *testing.T) {
	h := newHarness(t, true)
	a := h.addAgent("tunnel-a", true)
	b := h.addAgent("tunnel-b", true)
	waitFor(t, "both agents online", 15*time.Second, func() bool { return h.onlineCount() == 2 })
	waitFor(t, "hub handshakes", 15*time.Second, func() bool {
		return a.device.Established(hubKey(h)) && b.device.Established(hubKey(h))
	})
	if !a.device.Established(hubKey(h)) {
		t.Fatal("the agent should have a session with the hub")
	}
	if !b.device.Established(hubKey(h)) {
		t.Fatal("the second agent should have a session with the hub")
	}
	// Both agents must see the other's address as a route through the tunnel.
	if !containsString(a.device.Routes(), "10.77.0.0/16") {
		t.Fatalf("mesh route missing: %v", a.device.Routes())
	}
}

func TestRevocationDisconnectsAgent(t *testing.T) {
	h := newHarness(t, true)
	a := h.addAgent("doomed", true)
	waitFor(t, "agent online", 15*time.Second, func() bool { return h.onlineCount() == 1 })

	status, _, _ := h.api("DELETE", fmt.Sprintf("/api/agents/%d", a.id), nil, h.login(t))
	if status != http.StatusOK {
		t.Fatalf("DELETE agent returned %d", status)
	}
	select {
	case err := <-a.runErr:
		if err == nil {
			t.Fatal("the agent should stop after revocation")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the revoked agent kept running")
	}
	if h.onlineCount() != 0 {
		t.Fatalf("revoked agent still has a session")
	}
}

func (h *harness) login(t *testing.T) []*http.Cookie {
	t.Helper()
	status, _, cookies := h.api("POST", "/api/login", map[string]string{"password": "correct-horse-battery-staple"}, nil)
	if status != http.StatusOK {
		t.Fatalf("login returned %d", status)
	}
	if len(cookies) == 0 {
		t.Fatal("login returned no session cookie")
	}
	return cookies
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// hubKey returns the control node's WireGuard public key.
func hubKey(h *harness) string { return h.server.Store().Hub().PublicKey }

// fakeMaxMind serves a GeoLite2 tarball to the control node under test.
type fakeMaxMind struct {
	server *httptest.Server
}

func newFakeMaxMind(t *testing.T) *fakeMaxMind {
	t.Helper()
	archive := testGeoIPTarball(t)
	fake := &fakeMaxMind{}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok && r.URL.Query().Get("license_key") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(archive)
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// attach makes the control node download from the fake instead of MaxMind.
func (f *fakeMaxMind) attach(opts *control.Options) {
	geoip.SetDownloadURLForTest(f.server.URL)
}
