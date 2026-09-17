// Package topology turns enrolled agents into WireGuard configurations.
//
// Two different jobs live here, and keeping them apart is what makes the mesh
// predictable:
//
//   - an *agent* only ever carries mesh addresses. It reaches every other
//     agent's overlay address, directly when that path is healthy and through the
//     hub otherwise, and it carries nothing else. Networks behind a machine are
//     not the other machines' business, and leaving them out is what lets two
//     machines run the same private range without having to fight over it.
//
//   - the *control node* carries the networks behind each agent, because it is
//     the node that dials published targets. A network is routed to exactly one
//     agent there (a prefix belongs to one peer entry, which is what keeps the
//     relay fallback correct), and a published target's own address is pinned as
//     a /32 to the agent the resource names, so it wins over whatever range
//     another machine advertises around it.
//
// For the mesh addresses themselves, WireGuard picks the longest matching
// AllowedIPs entry, so ownership is kept exclusive on the hub: moving an address
// between the hub peer and a direct peer is an atomic switch from relayed to
// direct and back.
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
	// Pinned are host addresses the mesh must deliver to this member because a
	// published resource names it as their owner.
	//
	// An address is only ambiguous while nothing says whose it is: two machines
	// both have a 172.18.0.5, and each of their resources means its own. A
	// published target does say whose it is, so its /32 is added as the most
	// specific entry for that peer and wins over any advertised prefix - which is
	// exactly the scoping the overlay cannot express by prefix alone.
	Pinned  []netip.Prefix
	Online  bool
	Enabled bool
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
		// Pinned addresses come after the advertised routes but beat them: the
		// kernel and WireGuard both route by the most specific match.
		for _, p := range mem.Pinned {
			p = p.Masked()
			if !p.Addr().IsValid() || !p.Addr().Is4() || p.Bits() != 32 || p.Overlaps(in.Mesh.CIDR) {
				continue
			}
			entry := p.String()
			allowed = append(allowed, entry)
			if !seenRoute[entry] {
				seenRoute[entry] = true
				cfg.Routes = append(cfg.Routes, entry)
			}
		}
		if len(allowed) == 0 {
			continue
		}
		peer := wg.PeerConfig{
			PublicKey:    mem.PublicKey,
			PresharedKey: in.HubPSKs[mem.ID],
			AllowedIPs:   allowed,
			// The hub keeps its own sessions warm too. Without this, an idle peer's
			// session expires and the packet that arrives next waits for a new
			// handshake - and if the agent's UDP mapping has moved since, that
			// handshake goes to a stale port and is only retried five seconds later.
			// That is the whole of the "the first request takes seconds, the next
			// one is instant" behaviour.
			PersistentKeepalive: in.Mesh.KeepaliveSec,
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
	Mesh Mesh
	Self Member
	Hub  HubMember
	// WGPort is the agent's stable local UDP port. A stable five-tuple avoids
	// landing on a different cloud/NAT path every time the process restarts.
	WGPort   int
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
	// An agent carries exactly one thing for the rest of the mesh: its own mesh
	// address. Networks a machine offers are reachable by the *control node*,
	// which is the node that dials published targets and routes them - agents do
	// not need each other's LANs, and not installing them here is what keeps two
	// machines with the same private range from having to fight over it.
	var rejected []Rejected
	cfg := wg.Config{
		Interface: wg.InterfaceConfig{
			PrivateKey: in.PrivateKey,
			Addresses:  []string{netip.PrefixFrom(in.Self.Address, 32).String()},
			ListenPort: in.WGPort,
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
