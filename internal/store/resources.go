package store

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/access"
)

// Protocol is how a resource is published on the control node.
type Protocol string

const (
	// ProtocolHTTP proxies plain HTTP, routing by the Host header.
	ProtocolHTTP Protocol = "http"
	// ProtocolHTTPS terminates TLS on the control node with a certificate it
	// manages, then proxies to the service over plain HTTP. This is the default
	// way to publish something over HTTPS.
	ProtocolHTTPS Protocol = "https"
	// ProtocolHTTPSPassthrough forwards TLS untouched, routing by SNI, so the
	// service behind the tunnel keeps its own certificate. Advanced: not offered
	// in the UI, but accepted by the API.
	ProtocolHTTPSPassthrough Protocol = "https-passthrough"
	// ProtocolTCP forwards a raw TCP stream.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP forwards datagrams with per-client sessions.
	ProtocolUDP Protocol = "udp"
)

// ValidProtocol reports whether p is supported.
func ValidProtocol(p Protocol) bool {
	switch p {
	case ProtocolHTTP, ProtocolHTTPS, ProtocolTCP, ProtocolUDP:
		return true
	case ProtocolHTTPSPassthrough:
		return true
	default:
		return false
	}
}

// DefaultListenPort returns the port a resource uses when none is given.
func DefaultListenPort(p Protocol) int {
	switch p {
	case ProtocolHTTP:
		return 80
	case ProtocolHTTPS, ProtocolHTTPSPassthrough:
		return 443
	default:
		return 0
	}
}

// SharedPort reports whether several resources of this kind can share one listen
// port (HTTP and HTTPS route by name, so they can).
func (p Protocol) SharedPort() bool {
	return p == ProtocolHTTP || p == ProtocolHTTPS || p == ProtocolHTTPSPassthrough
}

// TerminatesTLS reports whether the control node serves HTTPS itself, which means
// it needs a certificate for the resource's domain.
func (p Protocol) TerminatesTLS() bool { return p == ProtocolHTTPS }

// ByName reports whether clients reach this resource by domain name.
func (p Protocol) ByName() bool {
	return p == ProtocolHTTP || p == ProtocolHTTPS || p == ProtocolHTTPSPassthrough
}

// ResourceTarget is one backend behind a resource. A resource can have several,
// which is how one published service fronts two servers, for example.
type ResourceTarget struct {
	ID      uint32 `json:"id"`
	AgentID uint32 `json:"agentId"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
}

// Target renders the address this target forwards to.
func (t ResourceTarget) Target() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Strategy decides which target a new connection is sent to.
type Strategy string

const (
	// StrategyRoundRobin rotates through the enabled targets.
	StrategyRoundRobin Strategy = "round-robin"
	// StrategyFailover prefers the first enabled target and only moves on when it
	// cannot be reached.
	StrategyFailover Strategy = "failover"
)

// NormaliseStrategy validates a load balancing strategy.
func NormaliseStrategy(raw string) (Strategy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "roundrobin", "round-robin", "rr":
		return StrategyRoundRobin, nil
	case "failover", "priority", "first":
		return StrategyFailover, nil
	default:
		return "", fmt.Errorf("%w: strategy must be round-robin or failover", ErrBadResource)
	}
}

// Resource publishes a service that lives behind one or more agents.
type Resource struct {
	ID       uint32           `json:"id"`
	Name     string           `json:"name"`
	Protocol Protocol         `json:"protocol"`
	Targets  []ResourceTarget `json:"targets"`
	Strategy Strategy         `json:"strategy"`
	// ExitNodeID is the public address resources listen on. Empty means the
	// control node itself.
	ExitNodeID string `json:"exitNodeId,omitempty"`
	// ListenPort is the port on the control node. Zero means the protocol
	// default (80 for http, 443 for https).
	ListenPort int    `json:"listenPort"`
	Domain     string `json:"domain,omitempty"`
	Enabled    bool   `json:"enabled"`
	// ProxyProtocol prepends a PROXY protocol header ("v1" or "v2") to every
	// connection forwarded to the service, so it can see the real client address.
	ProxyProtocol string `json:"proxyProtocol,omitempty"`
	// Identity requires a control node account before a request is forwarded.
	Identity bool `json:"identity,omitempty"`
	// Rules decide who may reach the resource, evaluated in order.
	Rules     []access.Rule `json:"rules,omitempty"`
	CreatedAt time.Time     `json:"createdAt"`
	Notes     string        `json:"notes,omitempty"`

	// AgentID, TargetHost and TargetPort exist only to migrate resources created
	// before a resource could hold several targets.
	AgentID    uint32 `json:"agentId,omitempty"`
	TargetHost string `json:"targetHost,omitempty"`
	TargetPort int    `json:"targetPort,omitempty"`
}

// EffectiveListenPort is the port the resource actually listens on.
func (r Resource) EffectiveListenPort() int {
	if r.ListenPort > 0 {
		return r.ListenPort
	}
	return DefaultListenPort(r.Protocol)
}

// Domain is a hostname published on the control node.
// DomainKind is how a domain is used by resources.
type DomainKind string

const (
	// DomainDirect is used as-is: the resource is published on exactly this name.
	DomainDirect DomainKind = "direct"
	// DomainWildcard is a suffix: a resource called "app" is published on
	// app.<suffix>, and one wildcard record covers all of them.
	DomainWildcard DomainKind = "wildcard"
)

type Domain struct {
	Hostname  string     `json:"hostname"`
	Kind      DomainKind `json:"kind,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	Notes     string     `json:"notes,omitempty"`
	// ProviderID is the DNS provider that manages this name, empty for manual.
	ProviderID string `json:"providerId,omitempty"`
	// Address is the last address the control node published for this name.
	Address   string    `json:"address,omitempty"`
	LastSync  time.Time `json:"lastSync,omitempty"`
	LastError string    `json:"lastError,omitempty"`
}

// Pattern renders the domain the way an operator writes it, including the
// leading "*." of a wildcard.
func (d Domain) Pattern() string {
	if d.Kind == DomainWildcard {
		return "*." + d.Hostname
	}
	return d.Hostname
}

// RecordName is the name the DNS record must use.
func (d Domain) RecordName() string { return d.Pattern() }

// Covers reports whether a resource hostname belongs to this domain.
func (d Domain) Covers(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if d.Kind == DomainWildcard {
		return strings.HasSuffix(hostname, "."+d.Hostname)
	}
	return hostname == d.Hostname
}

// HostnameFor builds the hostname a resource gets from this domain.
func (d Domain) HostnameFor(label string) string {
	if d.Kind == DomainWildcard {
		return label + "." + d.Hostname
	}
	return d.Hostname
}

// DomainKindOf reports the kind stored for a domain.
func (d Domain) KindOrDefault() DomainKind {
	if d.Kind == DomainWildcard {
		return DomainWildcard
	}
	return DomainDirect
}

// ResourceInput is the caller supplied description of a resource.
// ResourceTargetInput is one backend in a resource description.
type ResourceTargetInput struct {
	AgentID uint32
	Host    string
	Port    int
	Enabled *bool
}

type ResourceInput struct {
	Name          string
	Protocol      Protocol
	Targets       []ResourceTargetInput
	Strategy      string
	ExitNodeID    string
	ListenPort    int
	Domain        string
	Enabled       *bool
	ProxyProtocol string
	Identity      bool
	Rules         []access.Rule
	Notes         string
}

// ProxyProtocolVersion is a PROXY protocol version selector.
type ProxyProtocolVersion string

const (
	// ProxyProtocolNone disables the PROXY protocol header.
	ProxyProtocolNone ProxyProtocolVersion = ""
	// ProxyProtocolV1 is the human readable version defined by HAProxy.
	ProxyProtocolV1 ProxyProtocolVersion = "v1"
	// ProxyProtocolV2 is the binary version.
	ProxyProtocolV2 ProxyProtocolVersion = "v2"
)

// NormaliseProxyProtocol validates a PROXY protocol selection.
func NormaliseProxyProtocol(raw string) (ProxyProtocolVersion, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "none", "off", "false":
		return ProxyProtocolNone, nil
	case "v1", "1":
		return ProxyProtocolV1, nil
	case "v2", "2":
		return ProxyProtocolV2, nil
	default:
		return "", fmt.Errorf("%w: PROXY protocol must be none, v1 or v2", ErrBadResource)
	}
}

var (
	// ErrBadResource means the resource description is not usable.
	ErrBadResource = errors.New("store: invalid resource")
	// ErrPortInUse means two resources would fight over the same listen port.
	ErrPortInUse = errors.New("store: that listen port is already used by another resource")
	// ErrDomainInUse means a domain is still referenced by a resource.
	ErrDomainInUse = errors.New("store: that domain is still used by a resource")
)

// Resources lists resources sorted by name.
func (s *Store) Resources() []Resource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Resource, 0, len(s.st.Resources))
	for _, r := range s.st.Resources {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Resource returns one resource.
func (s *Store) Resource(id uint32) (Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := findResource(s.st, id)
	if r == nil {
		return Resource{}, ErrNotFound
	}
	return *r, nil
}

func findResource(st *State, id uint32) *Resource {
	for _, r := range st.Resources {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// AddResource creates a published service.
func (s *Store) AddResource(in ResourceInput) (Resource, error) {
	var created Resource
	err := s.Update(func(st *State) error {
		resource, err := s.buildResource(st, 0, in)
		if err != nil {
			return err
		}
		if st.NextResourceID == 0 {
			st.NextResourceID = 1
		}
		resource.ID = st.NextResourceID
		resource.CreatedAt = time.Now().UTC()
		if err := checkPortConflicts(st, resource, nil); err != nil {
			return err
		}
		st.NextResourceID++
		st.Resources = append(st.Resources, &resource)
		if resource.Domain != "" {
			ensureDomainLocked(st, resource.Domain)
		}
		created = resource
		return nil
	})
	return created, err
}

// UpdateResource applies a change to a resource.
func (s *Store) UpdateResource(id uint32, in ResourceInput) (Resource, error) {
	var updated Resource
	err := s.Update(func(st *State) error {
		existing := findResource(st, id)
		if existing == nil {
			return ErrNotFound
		}
		candidate, err := s.buildResource(st, id, in)
		if err != nil {
			return err
		}
		candidate.ID = existing.ID
		candidate.CreatedAt = existing.CreatedAt
		if err := checkPortConflicts(st, candidate, existing); err != nil {
			return err
		}
		*existing = candidate
		if candidate.Domain != "" {
			ensureDomainLocked(st, candidate.Domain)
		}
		updated = candidate
		return nil
	})
	return updated, err
}

// RemoveResource deletes a published service.
func (s *Store) RemoveResource(id uint32) error {
	return s.Update(func(st *State) error {
		out := st.Resources[:0]
		found := false
		for _, r := range st.Resources {
			if r.ID == id {
				found = true
				continue
			}
			out = append(out, r)
		}
		if !found {
			return ErrNotFound
		}
		st.Resources = out
		return nil
	})
}

// buildResource validates input against the current state.
func (s *Store) buildResource(st *State, id uint32, in ResourceInput) (Resource, error) {
	if !ValidProtocol(in.Protocol) {
		return Resource{}, fmt.Errorf("%w: protocol must be http, https, tcp or udp", ErrBadResource)
	}
	targets, err := buildTargets(st, in.Targets)
	if err != nil {
		return Resource{}, err
	}
	strategy, err := NormaliseStrategy(in.Strategy)
	if err != nil {
		return Resource{}, err
	}
	exitNodeID, err := resolveExitNodeID(st, in.ExitNodeID)
	if err != nil {
		return Resource{}, err
	}
	domain := ""
	if strings.TrimSpace(in.Domain) != "" {
		domain, err = NormaliseHostname(in.Domain)
		if err != nil {
			return Resource{}, err
		}
		if in.Protocol == ProtocolTCP || in.Protocol == ProtocolUDP {
			return Resource{}, fmt.Errorf("%w: domains only apply to http and https resources", ErrBadResource)
		}
	}
	if in.Protocol == ProtocolHTTPS && domain == "" {
		return Resource{}, fmt.Errorf("%w: an https resource needs a domain, because the control node issues the certificate for it", ErrBadResource)
	}
	if in.Identity && !in.Protocol.ByName() {
		return Resource{}, fmt.Errorf("%w: identity control needs http or https, because %s cannot ask for a login",
			ErrBadResource, in.Protocol)
	}
	if len(in.Rules) > 0 && !in.Protocol.ByName() {
		return Resource{}, fmt.Errorf("%w: access rules need http or https, because %s cannot read a country or hostname",
			ErrBadResource, in.Protocol)
	}
	rules := append([]access.Rule(nil), in.Rules...)
	for i := range rules {
		if err := rules[i].Validate(); err != nil {
			return Resource{}, fmt.Errorf("%w: rule %d: %v", ErrBadResource, i+1, err)
		}
	}
	resource := Resource{
		Name:       strings.TrimSpace(in.Name),
		Protocol:   in.Protocol,
		Targets:    targets,
		Strategy:   strategy,
		ExitNodeID: exitNodeID,
		ListenPort: in.ListenPort,
		Domain:     domain,
		Enabled:    true,
		Identity:   in.Identity,
		Rules:      rules,
		Notes:      strings.TrimSpace(in.Notes),
	}
	proxyProtocol, err := NormaliseProxyProtocol(in.ProxyProtocol)
	if err != nil {
		return Resource{}, err
	}
	resource.ProxyProtocol = string(proxyProtocol)
	if in.Enabled != nil {
		resource.Enabled = *in.Enabled
	}
	if resource.Name == "" {
		resource.Name = fmt.Sprintf("%s-%d", resource.Protocol, targets[0].Port)
	}
	// HTTPS is always published on 443: the control node answers with its own
	// certificate, so there is nothing for the operator to choose.
	if resource.Protocol == ProtocolHTTPS {
		resource.ListenPort = 443
	}
	if resource.ListenPort != 0 && (resource.ListenPort < 1 || resource.ListenPort > 65535) {
		return Resource{}, fmt.Errorf("%w: listen port must be between 1 and 65535", ErrBadResource)
	}
	if resource.EffectiveListenPort() == 0 {
		return Resource{}, fmt.Errorf("%w: choose a listen port on the control node for %s resources", ErrBadResource, resource.Protocol)
	}
	if err := s.checkReservedPorts(st, resource); err != nil {
		return Resource{}, err
	}
	return resource, nil
}

// maxTargets bounds how many backends one resource may front.
const maxTargets = 16

// buildTargets validates every backend of a resource.
func buildTargets(st *State, inputs []ResourceTargetInput) ([]ResourceTarget, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("%w: add at least one target", ErrBadResource)
	}
	if len(inputs) > maxTargets {
		return nil, fmt.Errorf("%w: a resource can have at most %d targets", ErrBadResource, maxTargets)
	}
	targets := make([]ResourceTarget, 0, len(inputs))
	for index, in := range inputs {
		agent := findAgent(st, in.AgentID)
		if agent == nil {
			return nil, fmt.Errorf("%w: target %d has no agent selected", ErrBadResource, index+1)
		}
		if agent.PublicKey == "" {
			return nil, fmt.Errorf("%w: target %d uses %s, which has not enrolled yet",
				ErrBadResource, index+1, agent.Name)
		}
		host, err := normaliseTargetHost(in.Host)
		if err != nil {
			return nil, fmt.Errorf("target %d: %w", index+1, err)
		}
		if !targetReachable(agent, host) {
			return nil, fmt.Errorf("%w: target %d (%s) is not reachable through %s. "+
				"Use the agent's mesh address or a network it advertises", ErrBadResource, index+1, host, agent.Name)
		}
		if in.Port < 1 || in.Port > 65535 {
			return nil, fmt.Errorf("%w: target %d needs a port between 1 and 65535", ErrBadResource, index+1)
		}
		target := ResourceTarget{
			ID:      uint32(index + 1),
			AgentID: in.AgentID,
			Host:    host,
			Port:    in.Port,
			Enabled: true,
		}
		if in.Enabled != nil {
			target.Enabled = *in.Enabled
		}
		targets = append(targets, target)
	}
	enabled := 0
	for _, t := range targets {
		if t.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return nil, fmt.Errorf("%w: at least one target must be enabled", ErrBadResource)
	}
	return targets, nil
}

// resolveExitNodeID checks the chosen exit node and normalises the default.
func resolveExitNodeID(st *State, raw string) (string, error) {
	id := strings.TrimSpace(raw)
	if id == "" || id == ControlExitNodeID {
		node, ok := findExitNode(st, ControlExitNodeID)
		if !ok {
			return "", fmt.Errorf("%w: the control node exit node is missing", ErrBadResource)
		}
		if !node.Enabled {
			return "", fmt.Errorf("%w: exit node %s is disabled, enable it or publish on another one", ErrBadResource, node.Name)
		}
		return "", nil
	}
	node, ok := findExitNode(st, id)
	if !ok {
		return "", fmt.Errorf("%w: that exit node does not exist", ErrBadResource)
	}
	if !node.Enabled {
		return "", fmt.Errorf("%w: exit node %s is disabled", ErrBadResource, node.Name)
	}
	return node.ID, nil
}

// checkReservedPorts keeps resources away from the control node's own listeners.
func (s *Store) checkReservedPorts(st *State, r Resource) error {
	port := r.EffectiveListenPort()
	if port == st.Settings.WGListenPort {
		return fmt.Errorf("%w: port %d is the WireGuard port", ErrBadResource, port)
	}
	_, controlPort, err := net.SplitHostPort(st.Settings.ControlListenAddr)
	if err == nil {
		if n, convErr := strconv.Atoi(controlPort); convErr == nil && n == port {
			return fmt.Errorf("%w: port %d is used by the control node's web UI", ErrBadResource, port)
		}
	}
	return nil
}

// checkPortConflicts rejects ambiguous listener sharing. HTTP and HTTPS route by
// name so they may share a port, as long as every resource on it has a domain.
func checkPortConflicts(st *State, candidate Resource, ignore *Resource) error {
	port := candidate.EffectiveListenPort()
	if !candidate.Enabled {
		return nil
	}
	for _, other := range st.Resources {
		if ignore != nil && other.ID == ignore.ID {
			continue
		}
		if !other.Enabled || other.EffectiveListenPort() != port {
			continue
		}
		// The same port on two different exit nodes is fine: they are different
		// public addresses.
		if other.ExitNodeID != candidate.ExitNodeID {
			continue
		}
		shared := candidate.Protocol.SharedPort() && other.Protocol == candidate.Protocol &&
			candidate.Domain != "" && other.Domain != "" && candidate.Domain != other.Domain
		if shared {
			continue
		}
		if candidate.Protocol == other.Protocol && candidate.Domain == other.Domain && candidate.Domain != "" {
			return fmt.Errorf("%w: %s already listens on %d for %s",
				ErrPortInUse, other.Name, port, other.Domain)
		}
		return fmt.Errorf("%w: %s already listens on %d", ErrPortInUse, other.Name, port)
	}
	return nil
}

// normaliseTargetHost accepts a bare IPv4 address.
func normaliseTargetHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: a target address is required", ErrBadResource)
	}
	// The port has its own field: "10.77.0.2:4547" here is a common slip, and
	// "not an IP address" does not tell anyone what to do about it.
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return "", fmt.Errorf("%w: %q is an address with a port; put the address here and the port in the port field",
			ErrBadResource, raw)
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		raw = prefix.Addr().String()
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not an IP address", ErrBadResource, raw)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("%w: only IPv4 targets are supported for now", ErrBadResource)
	}
	return addr.String(), nil
}

// targetReachable reports whether the agent can plausibly route to host: either
// its own overlay address, or a network it advertises.
func targetReachable(agent *Agent, host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if agent.Address == host {
		return true
	}
	for _, raw := range agent.Advertise {
		if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// NormaliseHostname lowercases and validates a DNS name.
func NormaliseHostname(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if colon := strings.IndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	if host == "" {
		return "", fmt.Errorf("%w: a domain name is required", ErrBadResource)
	}
	if len(host) > 253 || !strings.Contains(host, ".") {
		return "", fmt.Errorf("%w: %q does not look like a domain name", ErrBadResource, raw)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("%w: %q is not a valid domain name", ErrBadResource, raw)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return "", fmt.Errorf("%w: %q contains an invalid character", ErrBadResource, raw)
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%w: %q has a label starting or ending with a dash", ErrBadResource, raw)
		}
	}
	return host, nil
}

// Domains lists configured domains sorted by hostname.
func (s *Store) Domains() []Domain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Domain(nil), s.st.Domains...)
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// AddDomain registers a hostname.
func (s *Store) AddDomain(hostname string) (Domain, error) {
	host, kind, err := NormaliseDomainPattern(hostname)
	if err != nil {
		return Domain{}, err
	}
	var created Domain
	err = s.Update(func(st *State) error {
		for _, d := range st.Domains {
			if d.Hostname == host {
				return fmt.Errorf("store: %s is already configured", host)
			}
		}
		domain := Domain{Hostname: host, Kind: kind, CreatedAt: time.Now().UTC()}
		st.Domains = append(st.Domains, domain)
		created = domain
		return nil
	})
	return created, err
}

// NormaliseDomainPattern accepts "example.com" or "*.example.com".
func NormaliseDomainPattern(raw string) (string, DomainKind, error) {
	value := strings.TrimSpace(raw)
	kind := DomainDirect
	if strings.HasPrefix(value, "*.") {
		kind = DomainWildcard
		value = strings.TrimPrefix(value, "*.")
	} else if strings.HasPrefix(value, "*") {
		return "", "", fmt.Errorf("%w: write a wildcard as *.example.com", ErrBadResource)
	}
	host, err := NormaliseHostname(value)
	if err != nil {
		return "", "", err
	}
	return host, kind, nil
}

// RemoveDomain deletes a hostname that no resource uses.
func (s *Store) RemoveDomain(hostname string) error {
	host, err := NormaliseHostname(hostname)
	if err != nil {
		return err
	}
	return s.Update(func(st *State) error {
		for _, r := range st.Resources {
			if r.Domain == host {
				return fmt.Errorf("%w: %s is used by resource %q", ErrDomainInUse, host, r.Name)
			}
		}
		out := st.Domains[:0]
		found := false
		for _, d := range st.Domains {
			if d.Hostname == host {
				found = true
				continue
			}
			out = append(out, d)
		}
		if !found {
			return ErrNotFound
		}
		st.Domains = out
		return nil
	})
}

func ensureDomainLocked(st *State, hostname string) {
	host := strings.ToLower(strings.TrimSpace(hostname))
	// A name already covered by a wildcard domain needs no entry of its own.
	for _, d := range st.Domains {
		if d.Covers(host) {
			return
		}
	}
	for _, d := range st.Domains {
		if d.Hostname == host {
			return
		}
	}
	st.Domains = append(st.Domains, Domain{Hostname: host, Kind: DomainDirect, CreatedAt: time.Now().UTC()})
}
