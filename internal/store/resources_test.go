package store

import (
	"errors"
	"strings"
	"testing"
)

// resourceFixture creates a store with one enrolled agent.
func resourceFixture(t *testing.T) (*Store, *Agent) {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	agent, err := st.AddAgent(AddAgentParams{Name: "homelab", Advertise: []string{"192.168.1.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAgent(agent.ID, func(a *Agent) error {
		a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	agent, _ = st.Agent(agent.ID)
	return st, agent
}

// oneTarget is the common single backend case.
func oneTarget(agentID uint32, host string, port int) []ResourceTargetInput {
	return []ResourceTargetInput{{AgentID: agentID, Host: host, Port: port}}
}

func TestAddResourceDefaults(t *testing.T) {
	st, agent := resourceFixture(t)
	resource, err := st.AddResource(ResourceInput{
		Name:     "home assistant",
		Protocol: ProtocolHTTPS,
		Targets:  oneTarget(agent.ID, agent.Address, 8123),
		Domain:   "Home.Example.COM",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resource.EffectiveListenPort() != 443 {
		t.Fatalf("https resources should default to 443, got %d", resource.EffectiveListenPort())
	}
	if resource.Domain != "home.example.com" {
		t.Fatalf("domain should be normalised, got %q", resource.Domain)
	}
	if resource.Strategy != StrategyRoundRobin {
		t.Fatalf("default strategy = %q, want round-robin", resource.Strategy)
	}
	if resource.ExitNodeID != "" {
		t.Fatalf("resources default to the control node exit node, got %q", resource.ExitNodeID)
	}
	if !resource.Enabled {
		t.Fatal("resources are enabled by default")
	}
	if len(resource.Targets) != 1 || resource.Targets[0].Host != agent.Address {
		t.Fatalf("targets = %+v", resource.Targets)
	}
	if domains := st.Domains(); len(domains) != 1 || domains[0].Hostname != "home.example.com" {
		t.Fatalf("creating a resource should register its domain, got %+v", domains)
	}
	if _, err := st.AddResource(ResourceInput{
		Name: "nas", Protocol: ProtocolTCP,
		Targets: oneTarget(agent.ID, "192.168.1.10", 5000), ListenPort: 5000,
	}); err != nil {
		t.Fatalf("advertised LAN targets should be allowed: %v", err)
	}
}

func TestCommonExploitFilterOnlyAppliesToWebResources(t *testing.T) {
	st, agent := resourceFixture(t)
	resource, err := st.AddResource(ResourceInput{
		Name: "web", Protocol: ProtocolHTTP, Domain: "web.example.com",
		Targets: oneTarget(agent.ID, agent.Address, 8080), BlockExploits: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resource.BlockExploits {
		t.Fatal("filter setting was not stored")
	}
	_, err = st.AddResource(ResourceInput{
		Name: "ssh", Protocol: ProtocolTCP, Targets: oneTarget(agent.ID, agent.Address, 22),
		ListenPort: 2222, BlockExploits: true,
	})
	if err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("TCP exploit filter should be rejected, got %v", err)
	}
}

func TestResourceWithSeveralTargets(t *testing.T) {
	st, agent := resourceFixture(t)
	resource, err := st.AddResource(ResourceInput{
		Name: "web cluster", Protocol: ProtocolHTTP, Domain: "app.example.com",
		Strategy: "failover",
		Targets: []ResourceTargetInput{
			{AgentID: agent.ID, Host: agent.Address, Port: 8080},
			{AgentID: agent.ID, Host: agent.Address, Port: 8081},
			{AgentID: agent.ID, Host: "192.168.1.30", Port: 8080},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resource.Targets) != 3 {
		t.Fatalf("expected three targets, got %d", len(resource.Targets))
	}
	if resource.Strategy != StrategyFailover {
		t.Fatalf("strategy = %q", resource.Strategy)
	}
	seen := map[uint32]bool{}
	for _, target := range resource.Targets {
		if target.ID == 0 || seen[target.ID] {
			t.Fatalf("target ids must be unique and set: %+v", resource.Targets)
		}
		seen[target.ID] = true
		if !target.Enabled {
			t.Fatalf("targets are enabled by default: %+v", target)
		}
	}
}

func TestResourceTargetValidation(t *testing.T) {
	st, agent := resourceFixture(t)
	cases := []struct {
		name    string
		targets []ResourceTargetInput
		want    string
	}{
		{"none", nil, "at least one target"},
		{"unknown agent", []ResourceTargetInput{{AgentID: 999, Host: agent.Address, Port: 80}}, "no agent"},
		// Any address on the agent's own network is its to publish; only an
		// address of the overlay itself is not a target.
		{"overlay address", oneTarget(agent.ID, "10.77.0.9", 80), "mesh range"},
		{"bad host", oneTarget(agent.ID, "not-an-ip", 80), "IP address"},
		{"host with a port", oneTarget(agent.ID, agent.Address+":4547", 4547), "port field"},
		{"bad port", oneTarget(agent.ID, agent.Address, 0), "port"},
		{"all disabled", []ResourceTargetInput{
			{AgentID: agent.ID, Host: agent.Address, Port: 80, Enabled: boolPtr(false)},
		}, "at least one target must be enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.AddResource(ResourceInput{
				Name: "x", Protocol: ProtocolTCP, Targets: tc.targets, ListenPort: 1234,
			})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("error %q should mention %q", err, tc.want)
			}
		})
	}
	// A pending (not yet enrolled) agent is refused too.
	pending, err := st.AddAgent(AddAgentParams{Name: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.AddResource(ResourceInput{
		Name: "too early", Protocol: ProtocolTCP,
		Targets: oneTarget(pending.ID, pending.Address, 80), ListenPort: 1234,
	})
	if err == nil || !strings.Contains(err.Error(), "enrolled") {
		t.Fatalf("expected an enrollment error, got %v", err)
	}
}

// TestALoopbackTargetIsKeptForTheAgentToCarry covers the address a service bound
// to localhost has. It is not routed anywhere - the kernel resolves 127.0.0.0/8
// locally before any route - so the agent carries it instead, and nothing pins it
// to a peer.
func TestALoopbackTargetIsKeptForTheAgentToCarry(t *testing.T) {
	st, agent := resourceFixture(t)
	if _, err := st.AddResource(ResourceInput{
		Name: "mysql", Protocol: ProtocolTCP, ListenPort: 3306,
		Targets: oneTarget(agent.ID, "127.0.0.1", 3306),
	}); err != nil {
		t.Fatalf("a service on the agent's own loopback should be publishable: %v", err)
	}
	if pinned := st.PinnedHosts(agent.ID); len(pinned) != 0 {
		t.Fatalf("a loopback address is not routed to a peer, got %v", pinned)
	}
}

// TestALoopbackUDPTargetIsRefusedForNow says what is not supported, instead of
// publishing something that cannot work: only TCP services are carried from an
// agent's loopback so far.
func TestALoopbackUDPTargetIsRefusedForNow(t *testing.T) {
	st, agent := resourceFixture(t)
	_, err := st.AddResource(ResourceInput{
		Name: "dns", Protocol: ProtocolUDP, ListenPort: 5353,
		Targets: oneTarget(agent.ID, "127.0.0.1", 53),
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be carried yet") {
		t.Fatalf("a udp loopback target should be refused with the reason, got %v", err)
	}
}

func boolPtr(v bool) *bool { return &v }

// TestADomainOnATCPResourceIsAllowed covers the name an operator expects to be
// able to give any published service. For http and https the domain decides how
// requests are routed; for tcp and udp there is no name inside the stream, so it
// is what the domain is used for instead: the DNS record, and a name to show.
func TestADomainOnATCPResourceIsAllowed(t *testing.T) {
	st, agent := resourceFixture(t)
	resource, err := st.AddResource(ResourceInput{
		Name: "mail", Protocol: ProtocolTCP, ListenPort: 2525,
		Domain:  "mail.example.com",
		Targets: oneTarget(agent.ID, agent.Address, 25),
	})
	if err != nil {
		t.Fatalf("a tcp resource with a domain should be allowed: %v", err)
	}
	if resource.Domain != "mail.example.com" {
		t.Fatalf("the domain should be kept, got %q", resource.Domain)
	}
	// The name is registered like any other, so the Domains tab offers it and the
	// DNS automation can create the record.
	if !containsDomain(st.Domains(), "mail.example.com") {
		t.Fatalf("the domain should be registered: %v", st.Domains())
	}
}

func containsDomain(domains []Domain, hostname string) bool {
	for _, domain := range domains {
		if domain.Hostname == hostname {
			return true
		}
	}
	return false
}

func TestResourceValidation(t *testing.T) {
	st, agent := resourceFixture(t)
	cases := []struct {
		name string
		in   ResourceInput
		want string
	}{
		{"bad protocol", ResourceInput{Protocol: "smtp", Targets: oneTarget(agent.ID, agent.Address, 25), ListenPort: 2525}, "protocol"},
		{"bad strategy", ResourceInput{Protocol: ProtocolTCP, Strategy: "random", Targets: oneTarget(agent.ID, agent.Address, 25), ListenPort: 2525}, "strategy"},
		{"tcp needs a port", ResourceInput{Protocol: ProtocolTCP, Targets: oneTarget(agent.ID, agent.Address, 25)}, "listen port"},
		{"passthrough needs a domain", ResourceInput{Protocol: ProtocolHTTPSPassthrough, Targets: oneTarget(agent.ID, agent.Address, 443), ListenPort: 8443}, "needs a domain"},
		{"bad domain", ResourceInput{Protocol: ProtocolHTTP, Targets: oneTarget(agent.ID, agent.Address, 80), Domain: "not a domain"}, "domain"},
		{"wireguard port", ResourceInput{Protocol: ProtocolTCP, Targets: oneTarget(agent.ID, agent.Address, 25), ListenPort: 51820}, "WireGuard"},
		{"unknown exit node", ResourceInput{Protocol: ProtocolTCP, Targets: oneTarget(agent.ID, agent.Address, 25), ListenPort: 2525, ExitNodeID: "nope"}, "exit node"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.AddResource(tc.in)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

func TestResourcePortConflicts(t *testing.T) {
	st, agent := resourceFixture(t)
	if _, err := st.AddResource(ResourceInput{
		Name: "ssh", Protocol: ProtocolTCP,
		Targets: oneTarget(agent.ID, agent.Address, 22), ListenPort: 2222,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := st.AddResource(ResourceInput{
		Name: "rdp", Protocol: ProtocolTCP,
		Targets: oneTarget(agent.ID, agent.Address, 3389), ListenPort: 2222,
	})
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("two tcp resources must not share a port, got %v", err)
	}
	// The same port on a different exit node is a different public address.
	node, err := st.AddExitNode(ExitNodeInput{Name: "second ip", Kind: "address", Address: "203.0.113.44"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddResource(ResourceInput{
		Name: "ssh on the second ip", Protocol: ProtocolTCP, ExitNodeID: node.ID,
		Targets: oneTarget(agent.ID, agent.Address, 22), ListenPort: 2222,
	}); err != nil {
		t.Fatalf("the same port on another exit node should be allowed: %v", err)
	}
	// HTTP resources with different domains share port 80.
	if _, err := st.AddResource(ResourceInput{
		Name: "site a", Protocol: ProtocolHTTP, Domain: "a.example.com",
		Targets: oneTarget(agent.ID, agent.Address, 8080),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddResource(ResourceInput{
		Name: "site b", Protocol: ProtocolHTTP, Domain: "b.example.com",
		Targets: oneTarget(agent.ID, agent.Address, 8081),
	}); err != nil {
		t.Fatalf("http resources with distinct domains should share port 80: %v", err)
	}
	_, err = st.AddResource(ResourceInput{
		Name: "site a again", Protocol: ProtocolHTTP, Domain: "a.example.com",
		Targets: oneTarget(agent.ID, agent.Address, 8082),
	})
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("a duplicate domain on one port must be rejected, got %v", err)
	}

	// A game server publishes one port for both transports: the UDP resource on
	// the same number must be allowed next to the TCP one, and a second TCP
	// resource on it must not.
	if _, err := st.AddResource(ResourceInput{
		Name: "game udp", Protocol: ProtocolUDP,
		Targets: oneTarget(agent.ID, agent.Address, 2222), ListenPort: 2222,
	}); err != nil {
		t.Fatalf("udp next to tcp on the same port should be allowed: %v", err)
	}
	_, err = st.AddResource(ResourceInput{
		Name: "game tcp again", Protocol: ProtocolTCP,
		Targets: oneTarget(agent.ID, agent.Address, 2222), ListenPort: 2222,
	})
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("a second tcp resource on one port must be rejected, got %v", err)
	}
}

// TestWebSocketsDefaultAndToggle covers the switch: resources allow protocol
// upgrades unless they turn them off, and the setting is meaningless for the
// protocols that cannot carry one.
func TestWebSocketsDefaultAndToggle(t *testing.T) {
	st, agent := resourceFixture(t)
	off := false
	chat, err := st.AddResource(ResourceInput{
		Name: "chat", Protocol: ProtocolHTTP, Domain: "chat.example.com", ListenPort: 80,
		Targets: oneTarget(agent.ID, agent.Address, 3000), WebSockets: &off,
	})
	if err != nil {
		t.Fatal(err)
	}
	if chat.AllowsWebSockets() {
		t.Fatal("an explicit false should disable upgrades")
	}
	plain, err := st.AddResource(ResourceInput{
		Name: "plain", Protocol: ProtocolHTTP, Domain: "plain.example.com", ListenPort: 80,
		Targets: oneTarget(agent.ID, agent.Address, 3001),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plain.AllowsWebSockets() {
		t.Fatal("a resource that does not mention it should allow upgrades")
	}
	on := true
	ssh, err := st.AddResource(ResourceInput{
		Name: "ssh", Protocol: ProtocolTCP, ListenPort: 2222,
		Targets: oneTarget(agent.ID, agent.Address, 22), WebSockets: &on,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ssh.WebSockets != nil {
		t.Fatal("a tcp resource has no upgrade to allow, so nothing should be stored")
	}
}

func TestResourceUpdateAndRemove(t *testing.T) {
	st, agent := resourceFixture(t)
	resource, err := st.AddResource(ResourceInput{
		Name: "grafana", Protocol: ProtocolHTTP, Domain: "grafana.example.com",
		Targets: oneTarget(agent.ID, agent.Address, 3000),
	})
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	updated, err := st.UpdateResource(resource.ID, ResourceInput{
		Name: "grafana", Protocol: ProtocolHTTP, Domain: "grafana.example.com",
		Targets: []ResourceTargetInput{
			{AgentID: agent.ID, Host: agent.Address, Port: 3001},
			{AgentID: agent.ID, Host: "192.168.1.44", Port: 3000},
		},
		Enabled: &disabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Targets) != 2 || updated.Targets[0].Port != 3001 || updated.Enabled {
		t.Fatalf("update did not apply: %+v", updated)
	}
	if updated.ID != resource.ID || !updated.CreatedAt.Equal(resource.CreatedAt) {
		t.Fatal("update must preserve identity and creation time")
	}
	if err := st.RemoveResource(resource.ID); err != nil {
		t.Fatal(err)
	}
	if len(st.Resources()) != 0 {
		t.Fatal("resource was not removed")
	}
	if err := st.RemoveResource(resource.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing twice should report not found, got %v", err)
	}
}

func TestDomains(t *testing.T) {
	st, agent := resourceFixture(t)
	if _, err := st.AddDomain("App.Example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddDomain("app.example.com"); err == nil {
		t.Fatal("duplicate domains must be rejected")
	}
	if _, err := st.AddDomain("nope"); err == nil {
		t.Fatal("a bare label is not a domain")
	}
	resource, err := st.AddResource(ResourceInput{
		Name: "app", Protocol: ProtocolHTTP, Domain: "app.example.com",
		Targets: oneTarget(agent.ID, agent.Address, 8080),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveDomain("app.example.com"); !errors.Is(err, ErrDomainInUse) {
		t.Fatalf("a domain in use must not be deleted, got %v", err)
	}
	if err := st.RemoveResource(resource.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveDomain("app.example.com"); err != nil {
		t.Fatalf("the domain should be removable now: %v", err)
	}
}

func TestNormaliseHostname(t *testing.T) {
	good := map[string]string{
		"Example.COM":           "example.com",
		"https://a.example.com": "a.example.com",
		"a.example.com:8443":    "a.example.com",
		"a.example.com/path":    "a.example.com",
		"a.example.com.":        "a.example.com",
		" sub.example.co.uk ":   "sub.example.co.uk",
	}
	for in, want := range good {
		got, err := NormaliseHostname(in)
		if err != nil || got != want {
			t.Errorf("NormaliseHostname(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "nodot", "-bad.example.com", "bad-.example.com", "a_b.example.com", strings.Repeat("a", 64) + ".com"} {
		if got, err := NormaliseHostname(bad); err == nil {
			t.Errorf("NormaliseHostname(%q) should fail, got %q", bad, got)
		}
	}
}

func TestProxyProtocolSelection(t *testing.T) {
	for raw, want := range map[string]ProxyProtocolVersion{
		"":     ProxyProtocolNone,
		"none": ProxyProtocolNone,
		"off":  ProxyProtocolNone,
		"v1":   ProxyProtocolV1,
		"1":    ProxyProtocolV1,
		"V2":   ProxyProtocolV2,
		" 2 ":  ProxyProtocolV2,
	} {
		got, err := NormaliseProxyProtocol(raw)
		if err != nil || got != want {
			t.Errorf("NormaliseProxyProtocol(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := NormaliseProxyProtocol("v3"); err == nil {
		t.Fatal("an unknown PROXY protocol version must be rejected")
	}

	st, agent := resourceFixture(t)
	resource, err := st.AddResource(ResourceInput{
		Name: "with proxy protocol", Protocol: ProtocolTCP,
		Targets: oneTarget(agent.ID, agent.Address, 22), ListenPort: 2222, ProxyProtocol: "v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resource.ProxyProtocol != string(ProxyProtocolV2) {
		t.Fatalf("proxy protocol = %q", resource.ProxyProtocol)
	}
	updated, err := st.UpdateResource(resource.ID, ResourceInput{
		Name: resource.Name, Protocol: ProtocolTCP,
		Targets: oneTarget(agent.ID, agent.Address, 22), ListenPort: 2222, ProxyProtocol: "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ProxyProtocol != string(ProxyProtocolV1) {
		t.Fatalf("proxy protocol after update = %q", updated.ProxyProtocol)
	}
	if _, err := st.AddResource(ResourceInput{
		Name: "bad", Protocol: ProtocolTCP,
		Targets: oneTarget(agent.ID, agent.Address, 22), ListenPort: 2223, ProxyProtocol: "v9",
	}); err == nil {
		t.Fatal("an invalid PROXY protocol version must be rejected")
	}
}

// TestLegacyResourceMigration covers resources written before targets existed.
func TestLegacyResourceMigration(t *testing.T) {
	st, agent := resourceFixture(t)
	// Write a resource in the old shape directly into the state file.
	if err := st.Update(func(state *State) error {
		state.Resources = append(state.Resources, &Resource{
			ID: 99, Name: "legacy", Protocol: ProtocolTCP,
			AgentID: agent.ID, TargetHost: agent.Address, TargetPort: 22,
			ListenPort: 2222, Enabled: true,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Re-open: the migration should turn it into a single target.
	reopened, err := Open(st.Path()[:len(st.Path())-len("state.json")])
	if err != nil {
		t.Fatal(err)
	}
	resource, err := reopened.Resource(99)
	if err != nil {
		t.Fatal(err)
	}
	if len(resource.Targets) != 1 {
		t.Fatalf("legacy resource should gain one target, got %+v", resource.Targets)
	}
	target := resource.Targets[0]
	if target.AgentID != agent.ID || target.Host != agent.Address || target.Port != 22 || !target.Enabled {
		t.Fatalf("migrated target = %+v", target)
	}
	if resource.TargetHost != "" || resource.AgentID != 0 {
		t.Fatalf("legacy fields should be cleared: %+v", resource)
	}
	if resource.Strategy != StrategyRoundRobin {
		t.Fatalf("legacy resource strategy = %q", resource.Strategy)
	}
}
