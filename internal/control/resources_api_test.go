package control_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// enrolledAgent enrolls a simulated agent and waits until it has a public key.
func (h *harness) enrolledAgent(t *testing.T, name string) *simAgent {
	t.Helper()
	sim := h.addAgent(name, true)
	waitFor(t, name+" to enroll", 20*time.Second, func() bool {
		agent, err := h.server.Store().Agent(sim.id)
		return err == nil && agent.PublicKey != ""
	})
	return sim
}

// advertise grants an agent an extra route directly in the store, which is how a
// homelab agent exposes its LAN to the control node.
func (h *harness) advertise(t *testing.T, id uint32, prefixes ...string) {
	t.Helper()
	if err := h.server.Store().UpdateAgent(id, func(a *store.Agent) error {
		a.Advertise = prefixes
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) agentAddress(t *testing.T, id uint32) string {
	t.Helper()
	agent, err := h.server.Store().Agent(id)
	if err != nil {
		t.Fatal(err)
	}
	return agent.Address
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// resourceBody builds the wire form of a resource with a single target.
func resourceBody(name, protocol string, agentID uint32, host string, port, listenPort int, extra map[string]any) map[string]any {
	body := map[string]any{
		"name":     name,
		"protocol": protocol,
		"targets": []map[string]any{
			{"agentId": agentID, "host": host, "port": port},
		},
		"listenPort": listenPort,
	}
	for key, value := range extra {
		body[key] = value
	}
	return body
}

func TestAdminResourceEmailLookupIsExplicitAndExact(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	owner, err := h.server.Auth().AddUserWithEmail("lookupowner", "lookup@example.com", "private-password-123", store.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	regular, err := h.server.Auth().AddUserWithEmail("otherowner", "", "private-password-123", store.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	regularSession := h.loginAs(t, regular.Username, "private-password-123")
	if status, body, _ := h.api("PATCH", "/api/exitnodes/control", map[string]any{"publicPool": true}, admin); status != http.StatusOK {
		t.Fatalf("enable public exit: %d %s", status, body)
	}
	for _, entry := range []struct {
		name, ownerID string
		slot          uint16
	}{
		{"admin-service", "", 0},
		{"lookup-service", owner.ID, owner.MeshSlot},
	} {
		agent, err := h.server.Store().AddAgent(store.AddAgentParams{Name: entry.name + "-agent", OwnerID: entry.ownerID, MeshSlot: entry.slot})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.server.Store().UpdateAgent(agent.ID, func(a *store.Agent) error {
			a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		_, err = h.server.Store().AddResource(store.ResourceInput{
			OwnerID: entry.ownerID, MeshSlot: entry.slot, Name: entry.name,
			Protocol: store.ProtocolTCP, ExitNodeID: "control", ListenPort: freePort(t),
			Targets: []store.ResourceTargetInput{{AgentID: agent.ID, Host: agent.Address, Port: 8080}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if status, body, _ := h.api("GET", "/api/resources", nil, admin); status != http.StatusOK || strings.Contains(string(body), "lookup-service") {
		t.Fatalf("default admin list exposed another account: %d %s", status, body)
	}
	path := "/api/resources?email=LOOKUP%40EXAMPLE.COM"
	if status, body, _ := h.api("GET", path, nil, admin); status != http.StatusOK || !strings.Contains(string(body), "lookup-service") || !strings.Contains(string(body), "lookup-service-agent") || strings.Contains(string(body), "admin-service") {
		t.Fatalf("explicit lookup returned wrong resources: %d %s", status, body)
	}
	if status, _, _ := h.api("GET", path, nil, regularSession); status != http.StatusForbidden {
		t.Fatalf("regular account looked up resources: %d", status)
	}
}

func TestAdminCanCreateUncappedResource(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"unlimited", "tcp", 0, "127.0.0.1", 8080, freePort(t), map[string]any{"uncapped": true}), admin)
	if status != http.StatusOK {
		t.Fatalf("create uncapped resource: %d %s", status, body)
	}
	var created struct {
		Resource struct {
			Uncapped bool   `json:"uncapped"`
			Quota    uint64 `json:"monthlyQuotaBytes"`
			Speed    uint64 `json:"sustainedBps"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if !created.Resource.Uncapped || created.Resource.Quota != 0 || created.Resource.Speed != 0 {
		t.Fatalf("uncapped limits were not saved: %+v", created.Resource)
	}
}

func TestRegularResourceLimit(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	if status, body, _ := h.api("PATCH", "/api/exitnodes/control", map[string]any{"publicPool": true}, admin); status != http.StatusOK {
		t.Fatalf("enable public exit node: %d %s", status, body)
	}
	owner, err := h.server.Auth().AddUserWithEmail("resourceowner", "", "private-password-123", store.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	user := h.loginAs(t, owner.Username, "private-password-123")
	agent, err := h.server.Store().AddAgent(store.AddAgentParams{Name: "private target", OwnerID: owner.ID, MeshSlot: owner.MeshSlot})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.Store().UpdateAgent(agent.ID, func(a *store.Agent) error {
		a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var firstID uint32
	for i := 0; i < store.RegularResourceLimit; i++ {
		protocol := "tcp"
		if i == 1 {
			protocol = "udp"
		}
		status, body, _ := h.api("POST", "/api/resources", resourceBody(
			fmt.Sprintf("private-%d", i), protocol, agent.ID, agent.Address, 8080, 0, nil), user)
		if status != http.StatusOK {
			t.Fatalf("resource %d: %d %s", i+1, status, body)
		}
		var created struct {
			Resource struct {
				ID         uint32 `json:"id"`
				ListenPort int    `json:"listenPort"`
			} `json:"resource"`
		}
		if err := json.Unmarshal(body, &created); err != nil {
			t.Fatal(err)
		}
		if created.Resource.ListenPort < 49152 || created.Resource.ListenPort > 65535 || created.Resource.ListenPort == 51820 {
			t.Fatalf("automatic %s port is outside the safe range: %d", protocol, created.Resource.ListenPort)
		}
		if i == 0 {
			firstID = created.Resource.ID
		}
	}
	if status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"sixth", "tcp", agent.ID, agent.Address, 8080, 0, nil), user); status != http.StatusConflict || !strings.Contains(string(body), "up to 5 resources") {
		t.Fatalf("sixth resource: %d %s", status, body)
	}
	if status, body, _ := h.api("DELETE", fmt.Sprintf("/api/resources/%d", firstID), nil, user); status != http.StatusOK {
		t.Fatalf("delete resource: %d %s", status, body)
	}
	if status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"replacement", "tcp", agent.ID, agent.Address, 8080, 0, nil), user); status != http.StatusOK {
		t.Fatalf("replacement resource: %d %s", status, body)
	}
	for i := 0; i < store.RegularResourceLimit+1; i++ {
		status, body, _ := h.api("POST", "/api/resources", resourceBody(
			fmt.Sprintf("admin-%d", i), "tcp", 0, "127.0.0.1", 8080, freePort(t), nil), admin)
		if status != http.StatusOK {
			t.Fatalf("admin resource %d: %d %s", i+1, status, body)
		}
	}
}

func TestWildcardDomainListsResourcesItCovers(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	if status, body, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "*.demo.example.com"}, admin); status != http.StatusOK {
		t.Fatalf("add wildcard returned %d: %s", status, body)
	}
	for index, hostname := range []string{"shop.demo.example.com", "status.demo.example.com"} {
		status, body, _ := h.api("POST", "/api/resources", resourceBody(
			"resource-"+strconv.Itoa(index+1), "http", agent.id, h.agentAddress(t, agent.id), 8080+index, 80,
			map[string]any{"domain": hostname}), admin)
		if status != http.StatusOK {
			t.Fatalf("publish %s returned %d: %s", hostname, status, body)
		}
	}
	status, body, _ := h.api("GET", "/api/domains", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("list domains returned %d: %s", status, body)
	}
	var result struct {
		Domains []struct {
			Pattern   string   `json:"pattern"`
			Resources []string `json:"resources"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	for _, domain := range result.Domains {
		if domain.Pattern == "*.demo.example.com" {
			if len(domain.Resources) != 2 {
				t.Fatalf("wildcard domain should list both resources: %+v", domain.Resources)
			}
			return
		}
	}
	t.Fatalf("wildcard domain missing from response: %s", body)
}

// localIPv4 is this machine's own address, which a test can use as a target that
// is not loopback: publishing through an agent reaches it the way a service on
// that machine's network is reached.
func localIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		return ip4.String()
	}
	t.Skip("this machine has no address to publish a service on")
	return ""
}

// tcpEchoService starts a service that answers "service:<payload>".
func tcpEchoService(t *testing.T) (string, int) {
	t.Helper()
	// Bound to every interface and addressed by this machine's own address: a
	// loopback target is carried by its agent now, so a target used to stand in
	// for "a service on the agent's network" has to be a normal address.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("service:" + string(buf[:n])))
			}(conn)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = localIPv4(t)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestResourceLifecycleThroughTheAPI(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	h.advertise(t, agent.id, "192.168.1.0/24")

	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"home assistant", "https", agent.id, "192.168.1.10", 8123, 0,
		map[string]any{"domain": "Home.Example.com", "blockExploits": true}), admin)
	if status != http.StatusOK {
		t.Fatalf("creating a resource returned %d: %s", status, body)
	}
	var created struct {
		Resource struct {
			ID            uint32 `json:"id"`
			Name          string `json:"name"`
			Protocol      string `json:"protocol"`
			ListenPort    int    `json:"listenPort"`
			Public        string `json:"public"`
			Domain        string `json:"domain"`
			Strategy      string `json:"strategy"`
			ExitNodeName  string `json:"exitNodeName"`
			BlockExploits bool   `json:"blockExploits"`
			Targets       []struct {
				AgentName string `json:"agentName"`
				Address   string `json:"address"`
			} `json:"targets"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Resource.ListenPort != 443 {
		t.Fatalf("https should default to 443, got %d", created.Resource.ListenPort)
	}
	if created.Resource.Public != "https://home.example.com" {
		t.Fatalf("public address = %q", created.Resource.Public)
	}
	if len(created.Resource.Targets) != 1 || created.Resource.Targets[0].AgentName != "homelab" {
		t.Fatalf("unexpected targets: %+v", created.Resource.Targets)
	}
	if created.Resource.Domain != "home.example.com" || created.Resource.Strategy != "round-robin" {
		t.Fatalf("unexpected resource: %+v", created.Resource)
	}
	if created.Resource.ExitNodeName == "" {
		t.Fatal("the resource should name its exit node")
	}
	if !created.Resource.BlockExploits {
		t.Fatal("the common exploit filter setting should round-trip through the API")
	}

	// The domain is registered automatically and reports what uses it.
	status, body, _ = h.api("GET", "/api/domains", nil, admin)
	if status != http.StatusOK || !strings.Contains(string(body), "home.example.com") ||
		!strings.Contains(string(body), "home assistant") {
		t.Fatalf("domains list returned %d: %s", status, body)
	}

	// State carries resources and domains for the dashboard.
	status, body, _ = h.api("GET", "/api/state", nil, admin)
	var view struct {
		Resources []struct {
			Name string `json:"name"`
		} `json:"resources"`
		Domains []struct {
			Hostname string `json:"hostname"`
		} `json:"domains"`
	}
	if status != http.StatusOK {
		t.Fatalf("/api/state returned %d", status)
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Resources) != 1 || view.Resources[0].Name != "home assistant" {
		t.Fatalf("resources in state: %+v", view.Resources)
	}
	if len(view.Domains) != 1 || view.Domains[0].Hostname != "home.example.com" {
		t.Fatalf("domains in state: %+v", view.Domains)
	}

	// Disable, then delete.
	status, body, _ = h.api("PATCH", fmt.Sprintf("/api/resources/%d", created.Resource.ID), resourceBody(
		"home assistant", "https", agent.id, "192.168.1.10", 8123, 0,
		map[string]any{"domain": "home.example.com", "enabled": false}), admin)
	if status != http.StatusOK || !strings.Contains(string(body), `"enabled":false`) {
		t.Fatalf("disable returned %d: %s", status, body)
	}
	if status, body, _ := h.api("DELETE", fmt.Sprintf("/api/resources/%d", created.Resource.ID), nil, admin); status != http.StatusOK {
		t.Fatalf("deleting a resource returned %d: %s", status, body)
	}
	if resources := h.server.Store().Resources(); len(resources) != 0 {
		t.Fatalf("resource still present: %+v", resources)
	}
}

func TestResourceValidationThroughTheAPI(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	address := h.agentAddress(t, agent.id)

	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		// An address on an agent's own network is its to publish, whoever else
		// happens to use the same range; only an address of the overlay is not a
		// target at all.
		{"overlay address", resourceBody("x", "tcp", agent.id, "10.77.0.9", 22, freePort(t), nil), "mesh range"},
		{"bad protocol", resourceBody("x", "gre", agent.id, address, 22, freePort(t), nil), "protocol"},
		{"missing agent", resourceBody("x", "tcp", 4242, address, 22, freePort(t), nil), "no agent"},
		{"tcp without a port", resourceBody("x", "tcp", agent.id, address, 22, 0, nil), "listen port"},
		{"no targets", map[string]any{"name": "x", "protocol": "tcp", "listenPort": freePort(t)}, "at least one target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := h.api("POST", "/api/resources", tc.body, admin)
			if status != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", status, body)
			}
			if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(tc.want)) {
				t.Fatalf("error %q should mention %q", body, tc.want)
			}
		})
	}
}

func TestViewersCannotManageResources(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	h.createViewer(t, admin, "reader")
	viewer := h.loginAs(t, "reader", "viewer-password-1")

	if status, _, _ := h.api("GET", "/api/resources", nil, viewer); status != http.StatusOK {
		t.Fatalf("a separate account read global resources: %d", status)
	}
	status, body, _ := h.api("POST", "/api/resources",
		resourceBody("sneaky", "tcp", agent.id, h.agentAddress(t, agent.id), 22, freePort(t), nil), viewer)
	if status != http.StatusBadRequest {
		t.Fatalf("a viewer created a resource: %d %s", status, body)
	}
	if status, _, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "x.example.com"}, viewer); status != http.StatusOK {
		t.Fatalf("a viewer added a domain: %d", status)
	}
	if status, _, _ := h.api("DELETE", "/api/resources/1", nil, viewer); status != http.StatusNotFound {
		t.Fatalf("a viewer deleted a resource: %d", status)
	}
}

func TestDomainLifecycleThroughTheAPI(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	if status, body, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "app.example.com"}, admin); status != http.StatusOK {
		t.Fatalf("adding a domain returned %d: %s", status, body)
	}
	if status, body, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "not a domain"}, admin); status != http.StatusBadRequest {
		t.Fatalf("an invalid domain returned %d: %s", status, body)
	}
	if status, body, _ := h.api("DELETE", "/api/domains/app.example.com", nil, admin); status != http.StatusOK {
		t.Fatalf("deleting a domain returned %d: %s", status, body)
	}
}

// TestPublishedServiceUsesAgentForward checks the API, listener and selected
// agent mapping. Fake WireGuard devices do not create OS mesh addresses, so
// packet forwarding itself is covered by the agent and proxy tests.
func TestPublishedServiceUsesAgentForward(t *testing.T) {
	listenPort := freePort(t)
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	status, body, _ := h.api("POST", "/api/resources",
		resourceBody("tcp echo", "tcp", agent.id, "192.168.4.2", 8080, listenPort, nil), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}
	forwards := h.server.Forwards(agent.id)
	if len(forwards) != 1 || forwards[0].Target != "192.168.4.2:8080" {
		t.Fatalf("agent forwards = %+v", forwards)
	}
	specs := h.server.ResourceSpecs()
	if len(specs) != 1 || len(specs[0].Targets) != 1 ||
		specs[0].Targets[0].Address() != net.JoinHostPort(h.agentAddress(t, agent.id), strconv.Itoa(forwards[0].Port)) {
		t.Fatalf("proxy specs = %+v", specs)
	}
	waitFor(t, "resource to listen", 5*time.Second, func() bool {
		status, body, _ = h.api("GET", "/api/state", nil, admin)
		var view struct {
			Resources []struct {
				Listening bool `json:"listening"`
			} `json:"resources"`
		}
		return status == http.StatusOK && json.Unmarshal(body, &view) == nil && len(view.Resources) == 1 && view.Resources[0].Listening
	})
}
