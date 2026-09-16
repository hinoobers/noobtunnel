// Package topology turns enrolled agents into WireGuard configurations.
//
// The interesting part is route ownership. Every mesh address and every
// advertised subnet is owned by exactly one WireGuard peer entry:
//
//   - a peer reachable directly owns its own prefixes, or
//   - the control node's hub peer owns them on the agent's behalf.
//
// WireGuard picks the longest matching AllowedIPs entry, so overlapping entries
// between the hub and a direct peer would break the relay fallback. Keeping
// ownership exclusive avoids that entirely: moving a prefix between the hub peer
// and a direct peer is an atomic switch from relayed to direct and back.
package topology

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// Member is one node of the mesh, as needed to build a configuration.
type Member struct {
	ID        uint32
	Name      string
	Address   netip.Addr
	PublicKey string
	// Endpoint is the last public endpoint the control node observed for this
	// member. An empty endpoint means "only reachable through the hub".
	Endpoint  string
	Advertise []netip.Prefix
	Online    bool
	Enabled   bool
}

// HubMember is the control node itself.
type HubMember struct {
	Address      netip.Addr
	PublicKey    string
	Endpoint     string
	PresharedKey string
}

// Mesh holds the network wide parameters.
type Mesh struct {
	CIDR          netip.Prefix
	MTU           int
	KeepaliveSec  int
	DirectEnabled bool
}

// Rejected explains why an advertised prefix was not accepted.
type Rejected struct {
	MemberID uint32
	Name     string
	Prefix   string
	Reason   string
}

// Sanitise filters advertised prefixes that must never be routed.
//
// An agent must not be able to hijack the overlay itself, the hub, another
// member's own address, or a prefix the receiving node already owns.
func (m Mesh) Sanitise(advertised []netip.Prefix, self Member, extraProtected []netip.Prefix) ([]netip.Prefix, []Rejected) {
	var ok []netip.Prefix
	var rejected []Rejected
	for _, p := range advertised {
		p = p.Masked()
		switch {
		case !p.Addr().Is4():
			rejected = append(rejected, Rejected{MemberID: self.ID, Prefix: p.String(), Reason: "not IPv4"})
			continue
		case p.Bits() == 0:
			rejected = append(rejected, Rejected{MemberID: self.ID, Prefix: p.String(), Reason: "default route cannot be advertised"})
			continue
		case p.Overlaps(m.CIDR):
			rejected = append(rejected, Rejected{MemberID: self.ID, Prefix: p.String(), Reason: "overlaps the mesh range"})
			continue
		case p.Addr().IsLoopback() || p.Addr().IsMulticast() || p.Addr().IsLinkLocalUnicast():
			rejected = append(rejected, Rejected{MemberID: self.ID, Prefix: p.String(), Reason: "not a routable unicast range"})
			continue
		case prefixContains(self.Address, p):
			rejected = append(rejected, Rejected{MemberID: self.ID, Prefix: p.String(), Reason: "would capture this node's own address"})
			continue
		}
		conflict := false
		for _, protected := range extraProtected {
			if p.Overlaps(protected) {
				rejected = append(rejected, Rejected{MemberID: self.ID, Prefix: p.String(), Reason: "overlaps " + protected.String()})
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		ok = append(ok, p)
	}
	return ok, rejected
}

func prefixContains(addr netip.Addr, p netip.Prefix) bool {
	return addr.IsValid() && p.Contains(addr)
}

// claims returns the prefixes owned by a member: its own /32 plus its accepted
// advertised subnets.
func (m Member) claims() []netip.Prefix {
	out := make([]netip.Prefix, 0, 1+len(m.Advertise))
	if m.Address.IsValid() {
		out = append(out, netip.PrefixFrom(m.Address, 32))
	}
	out = append(out, m.Advertise...)
	return out
}

// ResolveAdvertise reconciles advertised routes across all members. Ties are
// broken by member id so every node computes the same answer.
func (m Mesh) ResolveAdvertise(members []Member) (map[uint32][]netip.Prefix, []Rejected) {
	owners := map[uint32][]netip.Prefix{}
	var rejected []Rejected

	ordered := append([]Member(nil), members...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	type claim struct {
		member uint32
		prefix netip.Prefix
	}
	var taken []claim

	for _, mem := range ordered {
		var accepted []netip.Prefix
		for _, p := range mem.Advertise {
			p = p.Masked()
			if p.Bits() == 0 || !p.Addr().Is4() || p.Overlaps(m.CIDR) {
				rejected = append(rejected, Rejected{MemberID: mem.ID, Name: mem.Name, Prefix: p.String(), Reason: "not a routable prefix for this mesh"})
				continue
			}
			clash := false
			for _, c := range taken {
				if c.prefix.Overlaps(p) {
					rejected = append(rejected, Rejected{
						MemberID: mem.ID, Name: mem.Name, Prefix: p.String(),
						Reason: fmt.Sprintf("overlaps %s advertised by member %d", c.prefix, c.member),
					})
					clash = true
					break
				}
			}
			if clash {
				continue
			}
			taken = append(taken, claim{member: mem.ID, prefix: p})
			accepted = append(accepted, p)
		}
		owners[mem.ID] = accepted
	}
	return owners, rejected
}

// HubInput describes everything needed to build the control node's device.
type HubInput struct {
	Mesh          Mesh
	HubAddress    netip.Addr
	PrivateKey    string
	WGPort        int
	Members       []Member // agents only, no hub entry
	HubPSKs       map[uint32]string
	DiscoveredEPs map[uint32]string
}

// BuildHubConfig renders the WireGuard configuration for the control node.
//
// The hub does not need endpoints for its peers: every agent dials in and keeps
// the session alive, which also makes the hub work from behind any NAT.
func BuildHubConfig(in HubInput) (wg.Config, []Rejected) {
	routes, rejected := in.Mesh.ResolveAdvertise(in.Members)

	cfg := wg.Config{
		Interface: wg.InterfaceConfig{
			PrivateKey: in.PrivateKey,
			Addresses:  []string{netip.PrefixFrom(in.HubAddress, 32).String()},
			ListenPort: in.WGPort,
			MTU:        in.Mesh.MTU,
		},
	}
	cfg.Routes = append(cfg.Routes, in.Mesh.CIDR.String())

	seenRoute := map[string]bool{in.Mesh.CIDR.String(): true}
	ordered := append([]Member(nil), in.Members...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, mem := range ordered {
		if !mem.Enabled || mem.PublicKey == "" {
			continue
		}
		allowed := []string{}
		if mem.Address.IsValid() {
			allowed = append(allowed, netip.PrefixFrom(mem.Address, 32).String())
		}
		for _, p := range routes[mem.ID] {
			allowed = append(allowed, p.String())
			if !seenRoute[p.String()] {
				seenRoute[p.String()] = true
				cfg.Routes = append(cfg.Routes, p.String())
			}
		}
		if len(allowed) == 0 {
			continue
		}
		peer := wg.PeerConfig{
			PublicKey:    mem.PublicKey,
			PresharedKey: in.HubPSKs[mem.ID],
			AllowedIPs:   allowed,
		}
		if ep := in.DiscoveredEPs[mem.ID]; ep != "" {
			peer.Endpoint = ep
		}
		cfg.Peers = append(cfg.Peers, peer)
	}
	sort.Strings(cfg.Routes)
	return cfg, rejected
}

// AgentInput describes everything needed to build an agent's device.
type AgentInput struct {
	Mesh     Mesh
	Self     Member
	Hub      HubMember
	Peers    []Member
	PairKeys map[uint32]string
	// PrivateKey is the agent's own WireGuard private key.
	PrivateKey string
	// Direct marks peers whose direct path is currently healthy.
	Direct map[uint32]bool
	// KnownEndpoints lets a peer without a discovered endpoint still be probed
	// (not used yet, kept for explicit configuration).
	KnownEndpoints map[uint32]string
}

// BuildAgentConfig renders the WireGuard configuration for an agent.
func BuildAgentConfig(in AgentInput) (wg.Config, []Rejected) {
	// A peer must not be able to claim this node's own address, the hub, or the
	// mesh range itself. Anything it is not allowed to route is dropped here,
	// before it can win a prefix in the ownership resolution below.
	var rejected []Rejected
	protected := []netip.Prefix{netip.PrefixFrom(in.Hub.Address, 32)}
	sanitised := make([]Member, 0, len(in.Peers))
	for _, peer := range in.Peers {
		accepted, peerRejected := in.Mesh.Sanitise(peer.Advertise, in.Self, protected)
		for i := range peerRejected {
			peerRejected[i].Name = peer.Name
			peerRejected[i].MemberID = peer.ID
		}
		rejected = append(rejected, peerRejected...)
		peer.Advertise = accepted
		sanitised = append(sanitised, peer)
	}
	advertiseOwners, conflicts := in.Mesh.ResolveAdvertise(sanitised)
	rejected = append(rejected, conflicts...)

	cfg := wg.Config{
		Interface: wg.InterfaceConfig{
			PrivateKey: in.PrivateKey,
			Addresses:  []string{netip.PrefixFrom(in.Self.Address, 32).String()},
			MTU:        in.Mesh.MTU,
		},
	}

	meshRoute := in.Mesh.CIDR.String()
	cfg.Routes = append(cfg.Routes, meshRoute)
	seenRoute := map[string]bool{meshRoute: true}

	var relayed []string
	ordered := append([]Member(nil), in.Peers...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	for _, peer := range ordered {
		if !peer.Enabled || peer.PublicKey == "" || peer.Address == in.Self.Address {
			continue
		}
		owned := []netip.Prefix{}
		if peer.Address.IsValid() {
			owned = append(owned, netip.PrefixFrom(peer.Address, 32))
		}
		owned = append(owned, advertiseOwners[peer.ID]...)

		// Kernel routes always point at the WireGuard interface; WireGuard then
		// decides whether the packet leaves directly or through the hub.
		for _, p := range owned {
			s := p.String()
			if !seenRoute[s] {
				seenRoute[s] = true
				cfg.Routes = append(cfg.Routes, s)
			}
		}

		endpoint := peer.Endpoint
		if endpoint == "" {
			endpoint = in.KnownEndpoints[peer.ID]
		}
		direct := in.Mesh.DirectEnabled && endpoint != "" && in.Direct[peer.ID]

		if direct {
			allowed := make([]string, 0, len(owned))
			for _, p := range owned {
				allowed = append(allowed, p.String())
			}
			cfg.Peers = append(cfg.Peers, wg.PeerConfig{
				PublicKey:           peer.PublicKey,
				PresharedKey:        in.PairKeys[peer.ID],
				Endpoint:            endpoint,
				AllowedIPs:          allowed,
				PersistentKeepalive: in.Mesh.KeepaliveSec,
			})
			continue
		}

		// Not direct (yet): the hub carries this peer's traffic.
		for _, p := range owned {
			relayed = append(relayed, p.String())
		}
		if in.Mesh.DirectEnabled && endpoint != "" {
			// Keep probing without claiming any prefix, so a working direct path
			// can be promoted later without ever black-holing traffic.
			cfg.Peers = append(cfg.Peers, wg.PeerConfig{
				PublicKey:           peer.PublicKey,
				PresharedKey:        in.PairKeys[peer.ID],
				Endpoint:            endpoint,
				PersistentKeepalive: in.Mesh.KeepaliveSec,
			})
		}
	}

	// The hub peer always exists and always carries everything not owned by a
	// healthy direct path, including the hub's own address.
	hubAllowed := []string{netip.PrefixFrom(in.Hub.Address, 32).String()}
	hubAllowed = append(hubAllowed, relayed...)
	cfg.Peers = append(cfg.Peers, wg.PeerConfig{
		PublicKey:           in.Hub.PublicKey,
		PresharedKey:        in.Hub.PresharedKey,
		Endpoint:            in.Hub.Endpoint,
		AllowedIPs:          dedupeStrings(hubAllowed),
		PersistentKeepalive: in.Mesh.KeepaliveSec,
	})
	sort.Strings(cfg.Routes)
	return cfg, rejected
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Describe renders the ownership decision for logs and the UI.
func Describe(self Member, peers []Member, direct map[uint32]bool) string {
	var parts []string
	for _, p := range peers {
		mode := "relay"
		if direct[p.ID] {
			mode = "direct"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", p.Name, mode))
	}
	if len(parts) == 0 {
		return "no peers"
	}
	return strings.Join(parts, ", ")
}
