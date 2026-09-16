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

// tcpEchoService starts a service that answers "service:<payload>".
func tcpEchoService(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
		map[string]any{"domain": "Home.Example.com"}), admin)
	if status != http.StatusOK {
		t.Fatalf("creating a resource returned %d: %s", status, body)
	}
	var created struct {
		Resource struct {
			ID           uint32 `json:"id"`
			Name         string `json:"name"`
			Protocol     string `json:"protocol"`
			ListenPort   int    `json:"listenPort"`
			Public       string `json:"public"`
			Domain       string `json:"domain"`
			Strategy     string `json:"strategy"`
			ExitNodeName string `json:"exitNodeName"`
			Targets      []struct {
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
		t.Fatalf("a viewer should be able to read resources: %d", status)
	}
	status, body, _ := h.api("POST", "/api/resources",
		resourceBody("sneaky", "tcp", agent.id, h.agentAddress(t, agent.id), 22, freePort(t), nil), viewer)
	if status != http.StatusForbidden {
		t.Fatalf("a viewer created a resource: %d %s", status, body)
	}
	if status, _, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "x.example.com"}, viewer); status != http.StatusForbidden {
		t.Fatalf("a viewer added a domain: %d", status)
	}
	if status, _, _ := h.api("DELETE", "/api/resources/1", nil, viewer); status != http.StatusForbidden {
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

// TestPublishedServiceForwardsTraffic is the feature end to end: a service behind
// an agent is published through the control node's API and real traffic flows
// through the proxy the control node runs.
func TestPublishedServiceForwardsTraffic(t *testing.T) {
	targetHost, targetPort := tcpEchoService(t)
	listenPort := freePort(t)

	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	// The agent routes loopback, which stands in for a homelab LAN.
	h.advertise(t, agent.id, targetHost+"/32")

	status, body, _ := h.api("POST", "/api/resources",
		resourceBody("tcp echo", "tcp", agent.id, targetHost, targetPort, listenPort, nil), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}

	// Connect to the published port and talk to the service.
	var conn net.Conn
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("the published port never accepted connections: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no answer through the tunnel: %v", err)
	}
	if got := string(buf[:n]); got != "service:ping" {
		t.Fatalf("forwarded %q, want %q", got, "service:ping")
	}

	// The dashboard must show the published resource as listening with traffic.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, body, _ = h.api("GET", "/api/state", nil, admin)
		var view struct {
			Resources []struct {
				Listening bool   `json:"listening"`
				Total     uint64 `json:"total"`
				Public    string `json:"public"`
			} `json:"resources"`
		}
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && len(view.Resources) == 1 {
			if view.Resources[0].Listening && view.Resources[0].Total >= 1 {
				if !strings.Contains(view.Resources[0].Public, strconv.Itoa(listenPort)) {
					t.Fatalf("public address %q should mention the port", view.Resources[0].Public)
				}
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the resource was never reported as listening: %s", body)
}
