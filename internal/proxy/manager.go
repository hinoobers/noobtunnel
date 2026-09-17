// Package proxy publishes services that live behind mesh agents on the control
// node's public addresses: raw TCP and UDP forwards, an HTTP reverse proxy that
// routes by Host header, and TLS passthrough that routes by SNI so the service
// keeps its own certificate.
//
// A resource can have several targets; connections are spread over them with
// round-robin or failover, and any target that cannot be dialled is skipped.
package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/access"
)

// Protocol names understood by the manager.
const (
	ProtoHTTP  = "http"
	ProtoHTTPS = "https"
	// ProtoHTTPSPassthrough keeps TLS end to end and routes by SNI.
	ProtoHTTPSPassthrough = "https-passthrough"
	ProtoTCP              = "tcp"
	ProtoUDP              = "udp"
)

// Load balancing strategies.
const (
	StrategyRoundRobin = "round-robin"
	StrategyFailover   = "failover"
)

// ControlResourceID is the reserved resource id of the control node's own route
// on the shared HTTPS port. Stored resources start at 1, so it cannot clash.
const ControlResourceID uint32 = 0

// TargetSpec is one backend of a resource.
type TargetSpec struct {
	ID   uint32
	Host string
	Port int
	// DialAddr overrides where the connection is made. It is set for a service
	// that only listens on its agent's loopback: `127.0.0.1` means the machine
	// that dials it, so the agent carries it on its mesh address instead.
	DialAddr string
	// AgentID is the agent the target belongs to.
	AgentID uint32
}

// Address renders the address a connection to this backend is made to.
func (t TargetSpec) Address() string {
	if t.DialAddr != "" {
		return t.DialAddr
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Published is how the backend is described to an operator: the address they
// configured, not the one the control node dials on their behalf.
func (t TargetSpec) Published() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Spec is one resource the manager should publish.
type Spec struct {
	ID       uint32
	Name     string
	Protocol string
	Targets  []TargetSpec
	Strategy string
	// BindAddr is the exit node address to listen on; empty means every address.
	BindAddr   string
	ListenPort int
	Domain     string
	Enabled    bool
	// ProxyProtocol is "", "v1" or "v2" and adds a header to forwarded streams.
	ProxyProtocol string
	// Identity requires a control node account before a request is forwarded.
	Identity bool
	// WebSockets allows protocol upgrades (WebSockets) through an HTTP or HTTPS
	// resource.
	WebSockets bool
	// Rules decide who may reach the resource, evaluated in order.
	Rules []access.Rule
	// Control marks the control node's own UI route. Requests for it are answered
	// by the control node itself instead of being dialled through an agent, so
	// the shared HTTPS port can serve it next to published resources.
	Control bool
}

// counters is one set of traffic counters.
type counters struct {
	active atomic.Int64
	total  atomic.Uint64
	rx     atomic.Uint64
	tx     atomic.Uint64
}

// TargetStats is the live state of one backend.
type TargetStats struct {
	Active    int64  `json:"active"`
	Total     uint64 `json:"total"`
	RxBytes   uint64 `json:"rxBytes"`
	TxBytes   uint64 `json:"txBytes"`
	LastError string `json:"lastError,omitempty"`
}

// Stats is the live state of one published resource.
type Stats struct {
	Active    int64                  `json:"active"`
	Total     uint64                 `json:"total"`
	RxBytes   uint64                 `json:"rxBytes"`
	TxBytes   uint64                 `json:"txBytes"`
	Listening bool                   `json:"listening"`
	LastError string                 `json:"lastError,omitempty"`
	Since     time.Time              `json:"since"`
	Targets   map[uint32]TargetStats `json:"targets,omitempty"`
}

// targetStats tracks one backend.
type targetStats struct {
	id  uint32
	set counters

	mu   sync.Mutex
	fail string
}

func (t *targetStats) setError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err == nil {
		t.fail = ""
		return
	}
	t.fail = err.Error()
}

func (t *targetStats) snapshot() TargetStats {
	t.mu.Lock()
	fail := t.fail
	t.mu.Unlock()
	return TargetStats{
		Active:    t.set.active.Load(),
		Total:     t.set.total.Load(),
		RxBytes:   t.set.rx.Load(),
		TxBytes:   t.set.tx.Load(),
		LastError: fail,
	}
}

// resourceStats holds the counters of one resource and its targets.
type resourceStats struct {
	set       counters
	listening atomic.Bool
	since     time.Time

	mu      sync.Mutex
	fail    string
	targets map[uint32]*targetStats
}

func (s *resourceStats) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.fail = ""
		return
	}
	s.fail = err.Error()
}

// targetFor returns (creating if needed) the stats of one backend.
func (s *resourceStats) targetFor(id uint32) *targetStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.targets == nil {
		s.targets = map[uint32]*targetStats{}
	}
	if t, ok := s.targets[id]; ok {
		return t
	}
	t := &targetStats{id: id}
	s.targets[id] = t
	return t
}

func (s *resourceStats) snapshot() Stats {
	s.mu.Lock()
	fail := s.fail
	targets := make(map[uint32]TargetStats, len(s.targets))
	for id, t := range s.targets {
		targets[id] = t.snapshot()
	}
	s.mu.Unlock()
	return Stats{
		Active:    s.set.active.Load(),
		Total:     s.set.total.Load(),
		RxBytes:   s.set.rx.Load(),
		TxBytes:   s.set.tx.Load(),
		Listening: s.listening.Load(),
		LastError: fail,
		Since:     s.since,
		Targets:   targets,
	}
}

// resource is a spec plus its counters.
type resource struct {
	spec Spec
	stat *resourceStats
	// rotation spreads round-robin over the targets.
	rotation atomic.Uint64
}

// candidates returns the targets to try, in order, for the next connection.
func (r *resource) candidates() []TargetSpec {
	if len(r.spec.Targets) == 0 {
		return nil
	}
	out := make([]TargetSpec, 0, len(r.spec.Targets))
	if r.spec.Strategy == StrategyFailover {
		return append(out, r.spec.Targets...)
	}
	start := int(r.rotation.Add(1)-1) % len(r.spec.Targets)
	for i := 0; i < len(r.spec.Targets); i++ {
		out = append(out, r.spec.Targets[(start+i)%len(r.spec.Targets)])
	}
	return out
}

// Manager owns every resource listener and reconciles them with the store.
type Manager struct {
	log *slog.Logger
	// DialTimeout bounds connecting through the tunnel.
	DialTimeout time.Duration
	// Certificates serves the TLS certificates for terminated HTTPS resources.
	Certificates CertificateProvider
	// IdentityCheck validates a control node account for identity controlled
	// resources. Returning nil allows the request.
	IdentityCheck func(username, password string) error
	// CountryOf resolves a client address to an ISO country code, or "" when the
	// information is unavailable.
	CountryOf func(addr netip.Addr) string
	// CountryOfFast is the same answer without waiting for it: it returns what is
	// already known and starts a lookup in the background. It is what the request
	// log uses, so a slow lookup never holds up a request.
	CountryOfFast func(addr netip.Addr) string
	// ACMEChallenge serves /.well-known/acme-challenge/ when ACME is enabled.
	ACMEChallenge http.Handler
	// ControlDomain publishes the control node's own UI on the shared HTTPS
	// listener, so https://domain reaches the control node without giving the
	// whole port up to it. Empty disables the route.
	ControlDomain string
	// ControlHandler answers that route: the control node's HTTP handler,
	// including the agent channel upgrade path.
	ControlHandler http.Handler
	// ControlPort is the port that route listens on. Zero means 443.
	ControlPort int
	// ControlBindAddr limits the route to a single address; empty means every
	// address, which is what a real deployment wants.
	ControlBindAddr string
	// OnRequest is called for every request a resource handles or refuses.
	OnRequest func(RequestEvent)

	// brandName is what the operator calls this deployment. It appears in the
	// plain text error pages a published service can return, so the name in the
	// UI and the name on the wire never disagree. It is swapped while requests
	// are in flight, hence the atomic.
	brandName atomic.Value // string

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	groups map[string]*group
	stats  map[uint32]*resourceStats
	closed bool
	// started records that the first reconcile has run, so a caller can tell
	// "nothing is listening" from "the listeners were never started in this
	// process" - which is what a short-lived report looks like.
	started atomic.Bool
}

// New creates a manager.
func New(log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager := &Manager{
		log:         log,
		groups:      map[string]*group{},
		stats:       map[uint32]*resourceStats{},
		ctx:         ctx,
		cancel:      cancel,
		DialTimeout: 10 * time.Second,
	}
	manager.SetBrandName("noobtunnel")
	return manager
}

// SetBrandName records the display name used in messages this manager writes.
func (m *Manager) SetBrandName(name string) {
	m.brandName.Store(sanitizeBrand(name))
}

// brand is the display name for messages this manager writes.
func (m *Manager) brand() string {
	name, _ := m.brandName.Load().(string)
	if name == "" {
		return "noobtunnel"
	}
	return name
}

// sanitizeBrand trims a display name and refuses anything that would break a
// plain text response or an HTTP header value.
func sanitizeBrand(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return -1
		case r == '"' || r == '\\':
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" {
		return "noobtunnel"
	}
	if runes := []rune(name); len(runes) > 40 {
		name = strings.TrimSpace(string(runes[:40]))
	}
	return name
}

// groupKey identifies a listening socket: protocol, bound address and port. The
// same port on two exit nodes is two different listeners.
func groupKey(proto, bindAddr string, port int) string {
	return strings.ToLower(proto) + "|" + bindAddr + "|" + strconv.Itoa(port)
}

// Reconcile makes the running listeners match specs. Calling it often is cheap:
// listeners that are already running only have their routing table swapped.
func (m *Manager) Reconcile(specs []Spec) {
	desired := map[string][]*resource{}
	present := map[uint32]bool{}

	m.mu.Lock()
	for _, spec := range specs {
		present[spec.ID] = true
		stat := m.statForLocked(spec.ID)
		if !spec.Enabled || len(spec.Targets) == 0 {
			stat.listening.Store(false)
			stat.setError(nil)
			continue
		}
		key := groupKey(spec.Protocol, spec.BindAddr, spec.ListenPort)
		desired[key] = append(desired[key], &resource{spec: spec, stat: stat})
	}
	// The control node's own route is appended last so it owns the hostname it is
	// published on, even if a resource claims the same name by mistake.
	if control, ok := m.controlSpec(); ok {
		present[control.ID] = true
		key := groupKey(control.Protocol, control.BindAddr, control.ListenPort)
		desired[key] = append(desired[key], &resource{spec: control, stat: m.statForLocked(control.ID)})
	}
	for id := range m.stats {
		if !present[id] {
			delete(m.stats, id)
		}
	}

	if m.closed {
		m.mu.Unlock()
		return
	}
	for key, g := range m.groups {
		if _, ok := desired[key]; ok {
			continue
		}
		g.close()
		delete(m.groups, key)
	}
	for key, resources := range desired {
		if g, ok := m.groups[key]; ok {
			g.setTargets(resources)
			for _, r := range resources {
				r.stat.listening.Store(true)
				r.stat.setError(nil)
			}
			continue
		}
		g, err := m.startGroup(key, resources)
		if err != nil {
			for _, r := range resources {
				r.stat.listening.Store(false)
				r.stat.setError(err)
			}
			m.log.Warn("could not publish resource", "listen", key, "error", err)
			continue
		}
		m.groups[key] = g
		for _, r := range resources {
			r.stat.listening.Store(true)
			r.stat.setError(nil)
		}
		var names []string
		for _, r := range resources {
			names = append(names, r.spec.Name)
		}
		m.log.Info("published resource", "listen", key, "resources", strings.Join(names, ", "))
	}
	m.mu.Unlock()
	m.started.Store(true)
}

// Started reports whether this manager has ever run a reconcile pass. The
// listeners are started by the running control node's resource loop, so a
// process that only reads the state (a report, a one-off command) has not
// started any of them and cannot say whether they are up.
func (m *Manager) Started() bool { return m.started.Load() }

// controlSpec is the synthetic resource that serves the control node's own UI.
// It deliberately has no targets: those requests never leave this process.
func (m *Manager) controlSpec() (Spec, bool) {
	domain := strings.ToLower(strings.TrimSpace(m.ControlDomain))
	if domain == "" || m.ControlHandler == nil {
		return Spec{}, false
	}
	port := m.ControlPort
	if port <= 0 {
		port = 443
	}
	return Spec{
		ID:         ControlResourceID,
		Name:       "control node",
		Protocol:   ProtoHTTPS,
		Domain:     domain,
		BindAddr:   m.ControlBindAddr,
		ListenPort: port,
		Enabled:    true,
		Control:    true,
	}, true
}

func (m *Manager) statForLocked(id uint32) *resourceStats {
	if s, ok := m.stats[id]; ok {
		return s
	}
	s := &resourceStats{since: time.Now()}
	m.stats[id] = s
	return s
}

func (m *Manager) startGroup(key string, resources []*resource) (*group, error) {
	first := resources[0].spec
	g := &group{
		manager: m,
		log:     m.log,
		key:     key,
		proto:   first.Protocol,
		bind:    first.BindAddr,
		port:    first.ListenPort,
		routes:  map[string]*resource{},
	}
	g.setTargets(resources)
	if err := g.start(m.dialTimeout()); err != nil {
		g.close()
		return nil, err
	}
	return g, nil
}

func (m *Manager) dialTimeout() time.Duration {
	if m.DialTimeout <= 0 {
		return 10 * time.Second
	}
	return m.DialTimeout
}

// Stats returns a snapshot for every known resource.
func (m *Manager) Stats() map[uint32]Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[uint32]Stats, len(m.stats))
	for id, s := range m.stats {
		out[id] = s.snapshot()
	}
	return out
}

// ListeningPorts reports what is currently bound, for diagnostics.
func (m *Manager) ListeningPorts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.groups))
	for key, g := range m.groups {
		if addr := g.addr(); addr != "" {
			out = append(out, key+" → "+addr)
		}
	}
	sort.Strings(out)
	return out
}

// Close stops every listener.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	groups := make([]*group, 0, len(m.groups))
	for _, g := range m.groups {
		groups = append(groups, g)
	}
	m.groups = map[string]*group{}
	m.mu.Unlock()

	m.cancel()
	for _, g := range groups {
		g.close()
	}
}
