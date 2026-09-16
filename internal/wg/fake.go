package wg

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// randInt is a tiny helper so the fake device can generate plausible counters.
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	return rand.Intn(n)
}

// FakeNodeInfo describes a simulated machine to the fake network.
type FakeNodeInfo struct {
	PublicKey string
	// PublicEndpoint is the address other nodes would use to reach this node,
	// i.e. after NAT translation. Empty means "not directly reachable".
	PublicEndpoint string
	// OverlayIP is the mesh address assigned to the node.
	OverlayIP string
	// Label identifies the owning backend.
	Label string
}

// FakeNetwork is the shared simulation fabric for fake backends. It models
// whether a direct handshake between two endpoints can succeed, which is exactly
// the condition noobtunnel's direct-path logic has to cope with.
type FakeNetwork struct {
	mu       sync.Mutex
	nodes    map[string]*FakeNodeInfo
	backends map[string]*FakeBackend

	// Reachable decides whether `from` can establish a direct session to `to`.
	// When nil every pair with a known endpoint is treated as reachable.
	Reachable func(from, to *FakeNodeInfo) bool
	// HandshakeDelay is how long a successful handshake takes to complete.
	HandshakeDelay time.Duration
	// Now overrides the clock in tests.
	Now func() time.Time
	// OnHandshake is called whenever a handshake completes.
	OnHandshake func(from, to string)
}

// NewFakeNetwork creates a simulation fabric with sane defaults.
func NewFakeNetwork() *FakeNetwork {
	return &FakeNetwork{
		nodes:          map[string]*FakeNodeInfo{},
		backends:       map[string]*FakeBackend{},
		HandshakeDelay: 20 * time.Millisecond,
	}
}

func (n *FakeNetwork) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

func (n *FakeNetwork) reachable(from, to *FakeNodeInfo) bool {
	if from == nil || to == nil || from.PublicEndpoint == "" || to.PublicEndpoint == "" {
		return false
	}
	if n.Reachable == nil {
		return true
	}
	return n.Reachable(from, to)
}

// Register adds or updates a node description.
func (n *FakeNetwork) Register(info FakeNodeInfo) {
	n.mu.Lock()
	defer n.mu.Unlock()
	cp := info
	n.nodes[info.PublicKey] = &cp
}

// RegisterBackend associates a label with a fake device so inbound handshakes
// can be delivered to it.
func (n *FakeNetwork) RegisterBackend(label string, b *FakeBackend) {
	if label == "" {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.backends[label] = b
}

// Unregister removes a node and its backend.
func (n *FakeNetwork) Unregister(publicKey, label string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.nodes, publicKey)
	if label != "" {
		delete(n.backends, label)
	}
}

func (n *FakeNetwork) lookup(publicKey string) *FakeNodeInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.nodes[publicKey]
}

func (n *FakeNetwork) backend(label string) *FakeBackend {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.backends[label]
}

// NodeInfo returns a copy of the fabric's view of a node.
func (n *FakeNetwork) NodeInfo(publicKey string) (FakeNodeInfo, bool) {
	info := n.lookup(publicKey)
	if info == nil {
		return FakeNodeInfo{}, false
	}
	return *info, true
}

// FakeBackend is an in-memory WireGuard device used by tests and --demo mode.
type FakeBackend struct {
	Network *FakeNetwork
	// Label identifies the backend in logs and in the fake fabric.
	Label string
	// PublicEndpoint simulates the NAT-translated address of this device.
	PublicEndpoint string
	// NoPublicEndpoint simulates a device behind a NAT that cannot be reached
	// directly at all (symmetric NAT / CGNAT).
	NoPublicEndpoint bool
	// OverlayIP is the mesh address assigned to this device.
	OverlayIP string
	// ListenPort simulates the local UDP port.
	ListenPort int

	mu         sync.Mutex
	up         bool
	iface      string
	privateKey string
	publicKey  string
	listenPort int
	mtu        int
	addresses  []string
	peers      map[string]*fakePeer
	routes     map[string]bool
}

type fakePeer struct {
	cfg         PeerConfig
	handshakeAt time.Time
	established time.Time
	rx, tx      uint64
	endpoint    string
}

// Name implements Backend.
func (f *FakeBackend) Name() string {
	if f.Label != "" {
		return "fake:" + f.Label
	}
	return "fake"
}

// Up reports whether the simulated interface is up.
func (f *FakeBackend) Up() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up
}

// PublicKey returns the simulated device public key.
func (f *FakeBackend) PublicKey() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.publicKey
}

// EnsureRoutes implements Backend: the simulated device keeps its routes from the
// last Sync, and re-asserting them is a no-op it records honestly.
func (f *FakeBackend) EnsureRoutes(ctx context.Context, iface string, routes []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range routes {
		if !f.routes[r] {
			return fmt.Errorf("wg: %s has no route for %s", iface, r)
		}
	}
	return nil
}

// Sync implements Backend.
func (f *FakeBackend) Sync(ctx context.Context, iface string, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	priv, err := DecodeKey(cfg.Interface.PrivateKey)
	if err != nil {
		return err
	}
	kp, err := KeyPairFromPrivate(priv)
	if err != nil {
		return err
	}

	f.mu.Lock()
	if f.peers == nil {
		f.peers = map[string]*fakePeer{}
	}
	f.up = true
	f.iface = iface
	f.privateKey = kp.Private
	f.publicKey = kp.Public
	f.listenPort = cfg.Interface.ListenPort
	if f.listenPort == 0 {
		f.listenPort = f.ListenPort
	}
	f.mtu = cfg.Interface.MTU
	f.addresses = append([]string(nil), cfg.Interface.Addresses...)
	f.routes = map[string]bool{}
	for _, r := range cfg.Routes {
		f.routes[r] = true
	}

	want := map[string]bool{}
	for _, p := range cfg.Peers {
		want[p.PublicKey] = true
	}
	for key := range f.peers {
		if !want[key] {
			delete(f.peers, key)
		}
	}
	for _, p := range cfg.Peers {
		peer, ok := f.peers[p.PublicKey]
		if !ok {
			peer = &fakePeer{}
			f.peers[p.PublicKey] = peer
		}
		peer.cfg = p
	}
	me := FakeNodeInfo{
		PublicKey:      kp.Public,
		PublicEndpoint: f.endpointLocked(),
		OverlayIP:      f.OverlayIP,
		Label:          f.Label,
	}
	f.mu.Unlock()

	if f.Network != nil {
		f.Network.Register(me)
		f.Network.RegisterBackend(f.Label, f)
		f.attemptHandshakes()
	}
	return nil
}

// endpointLocked must be called with f.mu held.
func (f *FakeBackend) endpointLocked() string {
	if f.NoPublicEndpoint {
		return ""
	}
	if f.PublicEndpoint != "" {
		return f.PublicEndpoint
	}
	if f.OverlayIP == "" {
		return ""
	}
	port := f.listenPort
	if port == 0 {
		port = 51820
	}
	return fmt.Sprintf("%s:%d", f.OverlayIP, port)
}

// Endpoint returns the simulated public endpoint of this device.
func (f *FakeBackend) Endpoint() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.endpointLocked()
}

// attemptHandshakes models WireGuard's behaviour: a configured endpoint makes
// the node send an initiation, and the responder learns the sender's endpoint.
func (f *FakeBackend) attemptHandshakes() {
	net := f.Network
	me, ok := net.NodeInfo(f.PublicKey())
	if !ok {
		return
	}

	f.mu.Lock()
	candidates := make([]PeerConfig, 0, len(f.peers))
	for _, p := range f.peers {
		if p.cfg.Endpoint != "" {
			candidates = append(candidates, p.cfg)
		}
	}
	f.mu.Unlock()

	for _, cfg := range candidates {
		other, ok := net.NodeInfo(cfg.PublicKey)
		if !ok || !net.reachable(&me, &other) {
			continue
		}
		remote := net.backend(other.Label)
		if remote == nil || !remote.Up() {
			continue
		}
		at := net.now().Add(net.HandshakeDelay)

		f.mu.Lock()
		if p, ok := f.peers[cfg.PublicKey]; ok && p.established.IsZero() {
			p.handshakeAt = at
		}
		f.mu.Unlock()

		remote.learnInbound(me.PublicKey, me.PublicEndpoint, at, net)
	}
}

// learnInbound records a session created by an inbound handshake. WireGuard
// roams to whatever endpoint the authenticated packets came from.
func (f *FakeBackend) learnInbound(fromKey, fromEndpoint string, at time.Time, net *FakeNetwork) {
	f.mu.Lock()
	peer, ok := f.peers[fromKey]
	if ok && peer.established.IsZero() {
		peer.handshakeAt = at
		peer.endpoint = fromEndpoint
	}
	f.mu.Unlock()
	if ok && net.OnHandshake != nil {
		go net.OnHandshake(fromKey, f.publicKey)
	}
}

// Status implements Backend.
func (f *FakeBackend) Status(ctx context.Context, iface string) (InterfaceStatus, error) {
	if err := ctx.Err(); err != nil {
		return InterfaceStatus{}, err
	}
	now := time.Now()
	if f.Network != nil {
		now = f.Network.now()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	status := InterfaceStatus{
		Name:       iface,
		Exists:     f.up,
		PublicKey:  f.publicKey,
		ListenPort: f.listenPort,
		MTU:        f.mtu,
		Addresses:  append([]string(nil), f.addresses...),
	}
	if !f.up {
		return status, nil
	}
	keys := make([]string, 0, len(f.peers))
	for k := range f.peers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := f.peers[k]
		if !p.handshakeAt.IsZero() && !now.Before(p.handshakeAt) && p.established.IsZero() {
			p.established = p.handshakeAt
		}
		status.Peers = append(status.Peers, PeerStatus{
			PublicKey:           p.cfg.PublicKey,
			Endpoint:            p.endpoint,
			AllowedIPs:          append([]string(nil), p.cfg.AllowedIPs...),
			LatestHandshake:     p.established,
			RxBytes:             p.rx,
			TxBytes:             p.tx,
			PersistentKeepalive: p.cfg.PersistentKeepalive,
			HasPresharedKey:     p.cfg.PresharedKey != "",
		})
	}
	return status, nil
}

// Down implements Backend.
func (f *FakeBackend) Down(ctx context.Context, iface string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	key, label := f.publicKey, f.Label
	f.up = false
	f.peers = map[string]*fakePeer{}
	f.mu.Unlock()
	if f.Network != nil && key != "" {
		f.Network.Unregister(key, label)
	}
	return nil
}

// SimulateTraffic records transfer counters for a peer, as the kernel would.
func (f *FakeBackend) SimulateTraffic(publicKey string, rx, tx uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.peers[publicKey]; ok {
		p.rx += rx
		p.tx += tx
	}
}

// SimulateRandomTraffic bumps counters for a random peer, for --demo mode.
func (f *FakeBackend) SimulateRandomTraffic() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.peers) == 0 {
		return
	}
	keys := make([]string, 0, len(f.peers))
	for k := range f.peers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	p := f.peers[keys[randInt(len(keys))]]
	p.rx += uint64(20_000 + randInt(400_000))
	p.tx += uint64(20_000 + randInt(400_000))
}

// Established reports whether a session to the peer has completed.
func (f *FakeBackend) Established(publicKey string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.peers[publicKey]; ok {
		return !p.established.IsZero()
	}
	return false
}

// Routes returns the currently installed kernel routes.
func (f *FakeBackend) Routes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.routes))
	for r := range f.routes {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// PeerAllowedIPs returns the AllowedIPs currently programmed for a peer.
func (f *FakeBackend) PeerAllowedIPs(publicKey string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.peers[publicKey]; ok {
		return append([]string(nil), p.cfg.AllowedIPs...)
	}
	return nil
}

// ForceExpireHandshakes ages every established session, which lets tests drive
// the direct-path timeout logic without sleeping.
func (f *FakeBackend) ForceExpireHandshakes(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.peers {
		if !p.established.IsZero() {
			p.established = p.established.Add(-d)
			p.handshakeAt = p.established
		}
	}
}
