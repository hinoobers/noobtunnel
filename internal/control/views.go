package control

import (
	"sort"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/ipam"
	"github.com/noobtunnel/noobtunnel/internal/proto"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/topology"
)

// LinkView is one agent-to-agent path as reported by the agent itself.
type LinkView struct {
	PeerID        uint32     `json:"peerId"`
	PeerName      string     `json:"peerName"`
	Direct        bool       `json:"direct"`
	Endpoint      string     `json:"endpoint,omitempty"`
	LastHandshake *time.Time `json:"lastHandshake,omitempty"`
	RxBytes       uint64     `json:"rxBytes"`
	TxBytes       uint64     `json:"txBytes"`
}

// AgentView is the UI/API representation of one agent.
type AgentView struct {
	ID             uint32                   `json:"id"`
	Name           string                   `json:"name"`
	MeshDNS        string                   `json:"meshDns,omitempty"`
	Address        string                   `json:"address"`
	Prefix         string                   `json:"prefix"`
	PublicKey      string                   `json:"publicKey,omitempty"`
	Advertise      []string                 `json:"advertise,omitempty"`
	AdvertiseAll   bool                     `json:"advertiseAll,omitempty"`
	Enabled        bool                     `json:"enabled"`
	Online         bool                     `json:"online"`
	Endpoint       string                   `json:"endpoint,omitempty"`
	LastSeen       *time.Time               `json:"lastSeen,omitempty"`
	LastHandshake  *time.Time               `json:"lastHandshake,omitempty"`
	LatencyMs      *int64                   `json:"latencyMs,omitempty"`
	RxBytes        uint64                   `json:"rxBytes"`
	TxBytes        uint64                   `json:"txBytes"`
	UptimeSec      int64                    `json:"uptimeSec,omitempty"`
	Version        string                   `json:"version,omitempty"`
	OS             string                   `json:"os,omitempty"`
	InstallMethod  string                   `json:"installMethod,omitempty"`
	Arch           string                   `json:"arch,omitempty"`
	Hostname       string                   `json:"hostname,omitempty"`
	Backend        string                   `json:"backend,omitempty"`
	LastError      string                   `json:"lastError,omitempty"`
	CreatedAt      time.Time                `json:"createdAt"`
	ExpiresAt      *time.Time               `json:"expiresAt,omitempty"`
	EnrolledAt     *time.Time               `json:"enrolledAt,omitempty"`
	Token          string                   `json:"token,omitempty"`
	InstallCommand string                   `json:"installCommand,omitempty"`
	Links          []LinkView               `json:"links"`
	DirectCount    int                      `json:"directCount"`
	RelayCount     int                      `json:"relayCount"`
	Routes         []string                 `json:"routes,omitempty"`
	Networks       []proto.NetworkCandidate `json:"networks,omitempty"`
	StatsAt        *time.Time               `json:"statsAt,omitempty"`
}

// Summary is the dashboard headline.
type Summary struct {
	Agents       int    `json:"agents"`
	Online       int    `json:"online"`
	Reachable    int    `json:"reachable"`
	DirectLinks  int    `json:"directLinks"`
	RelayedLinks int    `json:"relayedLinks"`
	RxBytes      uint64 `json:"rxBytes"`
	TxBytes      uint64 `json:"txBytes"`
	MeshCIDR     string `json:"meshCidr"`
	MeshCapacity int    `json:"meshCapacity"`
}

// StateView is the complete snapshot the UI renders.
type StateView struct {
	Server   map[string]any      `json:"server"`
	Settings store.Settings      `json:"settings"`
	Agents   []AgentView         `json:"agents"`
	Summary  Summary             `json:"summary"`
	Health   []Check             `json:"health"`
	Rejected []topology.Rejected `json:"rejected,omitempty"`
	Events   []Event             `json:"events"`
	// Errors are the recent failures, for Logs → Errors: what went wrong, with
	// the detail and the fix where the control node knows one.
	Errors       []ErrorEntry      `json:"errors"`
	Tokens       []store.APIToken  `json:"apiTokens,omitempty"`
	Resources    []ResourceView    `json:"resources"`
	Domains      []DomainView      `json:"domains"`
	ExitNodes    []ExitNodeView    `json:"exitNodes"`
	DNSProviders []DNSProviderView `json:"dnsProviders"`
}

// notNil turns a nil slice into an empty one. A nil slice marshals to JSON null,
// and the web UI reads these fields as arrays, so an empty mesh must arrive as
// [] rather than null (a mesh with no agents left used to break the whole page
// with "cannot read properties of null").
func notNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

// StateSnapshot builds the current view of the mesh.
func (s *Server) StateSnapshot() *StateView {
	st := s.store.View()
	settings := st.Settings

	s.mu.Lock()
	sessions := make(map[uint32]*Session, len(s.sessions))
	for id, sess := range s.sessions {
		sessions[id] = sess
	}
	endpoints := make(map[uint32]string, len(s.endpoints))
	for id, ep := range s.endpoints {
		endpoints[id] = ep
	}
	peerStats := make(map[uint32]map[uint32]proto.PeerStat, len(s.peerStats))
	for id, stats := range s.peerStats {
		cp := make(map[uint32]proto.PeerStat, len(stats))
		for k, v := range stats {
			cp[k] = v
		}
		peerStats[id] = cp
	}
	hubStatus := s.hubStatus
	rejected := append([]topology.Rejected(nil), s.rejected...)
	s.mu.Unlock()

	names := map[uint32]string{}
	for _, a := range st.Agents {
		names[a.ID] = a.Name
	}

	view := &StateView{
		Server:       s.RuntimeInfo(),
		Settings:     settings,
		Agents:       []AgentView{},
		Health:       notNil(s.Checks()),
		Events:       notNil(s.events.recent()),
		Errors:       notNil(s.errors.recent()),
		Tokens:       notNil(s.auth.APITokens()),
		Rejected:     notNil(rejected),
		Resources:    notNil(s.resourceViews()),
		Domains:      notNil(s.domainViews()),
		ExitNodes:    notNil(s.exitNodeViews()),
		DNSProviders: notNil(s.dnsProviderViews()),
	}
	if pool, err := ipam.New(settings.MeshCIDR); err == nil {
		view.Server["hubAddress"] = pool.HubAddress().String()
	}

	byKey := map[string]uint32{}
	for _, a := range st.Agents {
		if a.PublicKey != "" {
			byKey[a.PublicKey] = a.ID
		}
	}
	handshakes := map[uint32]*time.Time{}
	hubRx := map[uint32]uint64{}
	hubTx := map[uint32]uint64{}
	for _, peer := range hubStatus.Peers {
		id, ok := byKey[peer.PublicKey]
		if !ok {
			continue
		}
		if !peer.LatestHandshake.IsZero() {
			t := peer.LatestHandshake.UTC()
			handshakes[id] = &t
		}
		hubRx[id] = peer.RxBytes
		hubTx[id] = peer.TxBytes
	}

	now := s.now()
	for _, agent := range st.Agents {
		sess, online := sessions[agent.ID]
		prefix, _ := agent.AddressPrefix()
		av := AgentView{
			ID:            agent.ID,
			Name:          agent.Name,
			MeshDNS:       agent.MeshDNS,
			Address:       agent.Address,
			Prefix:        prefix.String(),
			PublicKey:     agent.PublicKey,
			Advertise:     agent.Advertise,
			AdvertiseAll:  agent.AdvertiseAll,
			Enabled:       agent.Enabled,
			Online:        online,
			Endpoint:      endpoints[agent.ID],
			Version:       agent.Version,
			OS:            agent.OS,
			InstallMethod: agent.InstallMethod,
			Arch:          agent.Arch,
			Hostname:      agent.Hostname,
			CreatedAt:     agent.CreatedAt,
			ExpiresAt:     agent.ExpiresAt,
			EnrolledAt:    agent.EnrolledAt,
			Token:         agent.Token,
			Links:         []LinkView{},
		}
		if !agent.LastSeen.IsZero() {
			t := agent.LastSeen.UTC()
			av.LastSeen = &t
		}
		if hs, ok := handshakes[agent.ID]; ok {
			av.LastHandshake = hs
		}
		if online {
			stats, statsAt, _, latency, _ := sess.snapshot()
			if !statsAt.IsZero() {
				av.StatsAt = &statsAt
			}
			av.Networks = stats.Networks
			av.RxBytes, av.TxBytes = stats.RxBytes, stats.TxBytes
			av.UptimeSec = stats.UptimeSec
			av.Backend = stats.Backend
			av.Routes = stats.Routes
			av.LastError = stats.LastError
			if latency > 0 {
				ms := latency.Milliseconds()
				if ms == 0 {
					ms = 1
				}
				av.LatencyMs = &ms
			}
		}
		for _, ps := range peerStats[agent.ID] {
			if ps.ID == 0 {
				continue
			}
			link := LinkView{
				PeerID:   ps.ID,
				PeerName: names[ps.ID],
				Direct:   ps.Direct,
				Endpoint: ps.Endpoint,
				RxBytes:  ps.RxBytes,
				TxBytes:  ps.TxBytes,
			}
			if ps.LatestHandshake > 0 {
				t := time.Unix(0, ps.LatestHandshake).UTC()
				link.LastHandshake = &t
			}
			if link.Direct {
				av.DirectCount++
			} else if link.Endpoint != "" || link.LastHandshake != nil {
				av.RelayCount++
			}
			av.Links = append(av.Links, link)
		}
		sort.Slice(av.Links, func(i, j int) bool { return av.Links[i].PeerID < av.Links[j].PeerID })
		if av.RxBytes == 0 && av.TxBytes == 0 {
			av.RxBytes = hubRx[agent.ID]
			av.TxBytes = hubTx[agent.ID]
		}
		view.Agents = append(view.Agents, av)

		view.Summary.Agents++
		if online {
			view.Summary.Online++
		}
		if av.LastHandshake != nil && now.Sub(*av.LastHandshake) < 3*time.Minute {
			view.Summary.Reachable++
		}
		view.Summary.RxBytes += av.RxBytes
		view.Summary.TxBytes += av.TxBytes
	}

	pairDirect := map[[2]uint32]bool{}
	for _, av := range view.Agents {
		for _, link := range av.Links {
			key := [2]uint32{av.ID, link.PeerID}
			if key[0] > key[1] {
				key[0], key[1] = key[1], key[0]
			}
			if direct, seen := pairDirect[key]; seen {
				pairDirect[key] = direct && link.Direct
			} else {
				pairDirect[key] = link.Direct
			}
		}
	}
	for _, direct := range pairDirect {
		if direct {
			view.Summary.DirectLinks++
		} else {
			view.Summary.RelayedLinks++
		}
	}
	view.Summary.MeshCIDR = settings.MeshCIDR
	if pool, err := ipam.New(settings.MeshCIDR); err == nil {
		view.Summary.MeshCapacity = pool.Capacity()
	}
	sort.Slice(view.Agents, func(i, j int) bool { return view.Agents[i].Name < view.Agents[j].Name })
	return view
}

// StateSnapshotFor only includes the account's own mesh. The original admin
// owns legacy agents, which have meshSlot zero in persisted state.
func (s *Server) StateSnapshotFor(who principal) *StateView {
	view := s.StateSnapshot()
	if who.UserID == "" && !who.ViaToken {
		return &StateView{}
	}
	agents := make([]AgentView, 0, len(view.Agents))
	for _, agent := range view.Agents {
		stored, err := s.store.Agent(agent.ID)
		if err != nil || !ownsAgent(who, stored) {
			continue
		}
		agents = append(agents, agent)
	}
	view.Agents = agents
	visibleResources := make([]ResourceView, 0)
	for _, resource := range view.Resources {
		stored, err := s.store.Resource(resource.ID)
		if err == nil && ownsMeshObject(who, stored.OwnerID, stored.MeshSlot) {
			visibleResources = append(visibleResources, resource)
		}
	}
	view.Resources = visibleResources
	delete(view.Server, "requests")
	view.Errors = s.errorsFor(who)
	view.Events = s.eventsFor(who)
	allowed := make(map[uint32]bool, len(agents))
	for _, agent := range agents {
		allowed[agent.ID] = true
	}
	visibleRejected := make([]topology.Rejected, 0)
	for _, rejected := range view.Rejected {
		if allowed[rejected.MemberID] {
			visibleRejected = append(visibleRejected, rejected)
		}
	}
	view.Rejected = visibleRejected
	for i := range view.Agents {
		links := view.Agents[i].Links[:0]
		for _, link := range view.Agents[i].Links {
			if allowed[link.PeerID] {
				links = append(links, link)
			}
		}
		view.Agents[i].Links = links
	}
	capacity := view.Summary.MeshCapacity
	view.Summary = Summary{MeshCIDR: view.Settings.MeshCIDR, MeshCapacity: capacity}
	for _, agent := range agents {
		view.Summary.Agents++
		if agent.Online {
			view.Summary.Online++
		}
		view.Summary.DirectLinks += agent.DirectCount
		view.Summary.RelayedLinks += agent.RelayCount
		view.Summary.RxBytes += agent.RxBytes
		view.Summary.TxBytes += agent.TxBytes
	}
	if prefix, err := store.TenantPrefix(view.Settings.MeshCIDR, who.MeshSlot); err == nil {
		if who.MeshSlot > 0 {
			view.Settings.MeshCIDR = prefix.String()
		}
		view.Summary.MeshCIDR = prefix.String()
		view.Summary.MeshCapacity = 253
	}
	if who.MeshSlot > 0 {
		view.Server = map[string]any{
			"version":        view.Server["version"],
			"domain":         view.Server["domain"],
			"publicURL":      view.Server["publicURL"],
			"publicEndpoint": view.Server["publicEndpoint"],
			"fingerprint":    view.Server["fingerprint"],
			"hubAddress":     view.Server["hubAddress"],
			"brandName":      view.Server["brandName"],
		}
		view.Health = []Check{}
		view.Events = []Event{}
		view.Tokens = []store.APIToken{}
		view.Rejected = []topology.Rejected{}
		visibleDomains := make([]DomainView, 0)
		for _, domain := range view.Domains {
			for _, stored := range s.store.Domains() {
				if stored.Hostname == domain.Hostname && (stored.OwnerID == who.UserID || stored.PublicPool) {
					used := make([]string, 0)
					for _, resource := range visibleResources {
						if stored.Covers(resource.Domain) {
							used = append(used, resource.Name)
						}
					}
					domain.Resources = used
					if stored.PublicPool {
						domain.ProviderID = ""
						domain.LastError = ""
					}
					visibleDomains = append(visibleDomains, domain)
					break
				}
			}
		}
		view.Domains = visibleDomains
		visibleNodes := make([]ExitNodeView, 0)
		for _, node := range view.ExitNodes {
			stored, err := s.store.ExitNode(node.ID)
			if err == nil && stored.PublicPool {
				used := make([]string, 0)
				for _, resource := range visibleResources {
					if resource.ExitNodeID == node.ID || (node.Kind == string(store.ExitNodeControl) && resource.ExitNodeID == "") {
						used = append(used, resource.Name)
					}
				}
				node.Resources = used
				node.Setup = SetupCommands{}
				visibleNodes = append(visibleNodes, node)
			}
		}
		view.ExitNodes = visibleNodes
		view.DNSProviders = []DNSProviderView{}
	} else {
		visibleDomains := make([]DomainView, 0, len(view.Domains))
		for _, domain := range view.Domains {
			for _, stored := range s.store.Domains() {
				if stored.Hostname == domain.Hostname && (stored.OwnerID == "" || stored.OwnerID == who.UserID || stored.PublicPool) {
					visibleDomains = append(visibleDomains, domain)
					break
				}
			}
		}
		view.Domains = visibleDomains
	}
	// Domain and exit-node cards include resource names, so scope those
	// embedded lists even for administrators on the original mesh.
	visibleNames := make(map[string]bool, len(visibleResources))
	for _, resource := range visibleResources {
		visibleNames[resource.Name] = true
	}
	for i := range view.Domains {
		used := make([]string, 0)
		for _, name := range view.Domains[i].Resources {
			if visibleNames[name] {
				used = append(used, name)
			}
		}
		view.Domains[i].Resources = used
	}
	for i := range view.ExitNodes {
		used := make([]string, 0)
		for _, name := range view.ExitNodes[i].Resources {
			if visibleNames[name] {
				used = append(used, name)
			}
		}
		view.ExitNodes[i].Resources = used
	}
	return view
}
