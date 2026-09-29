package control_test

import (
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// TestLoopbackTargetIsCarriedByItsAgent covers the mapping that makes a service
// bound to localhost publishable: `127.0.0.1` means the machine that dials it, so
// the control node reaches the agent's mesh address and the agent passes the
// connection to its own loopback.
func TestLoopbackTargetIsCarriedByItsAgent(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")

	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"mysql", "tcp", agent.id, "127.0.0.1", 3306, freePort(t), nil), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}

	address := h.agentAddress(t, agent.id)

	forwards := h.server.Forwards(agent.id)
	if len(forwards) != 1 || forwards[0].Port == 0 || forwards[0].Target != "127.0.0.1:3306" {
		t.Fatalf("the agent should carry the loopback service, got %+v", forwards)
	}
	for _, resource := range h.server.Store().Resources() {
		if resource.Name != "mysql" {
			continue
		}
		for _, target := range resource.Targets {
			if got := h.server.DialAddress(resource.ID, target); got != address+":"+itoaTest(forwards[0].Port) {
				t.Fatalf("the control node should dial the agent forward, got %q", got)
			}
		}
	}

	// A normal private address is also dialled through its selected agent.
	if _, err := h.server.Store().AddResource(store.ResourceInput{
		Name: "lan", Protocol: store.ProtocolTCP, ListenPort: freePort(t),
		Targets: []store.ResourceTargetInput{{AgentID: agent.id, Host: "192.168.50.9", Port: 80}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, resource := range h.server.Store().Resources() {
		if resource.Name != "lan" {
			continue
		}
		for _, target := range resource.Targets {
			if got := h.server.DialAddress(resource.ID, target); got == "192.168.50.9:80" {
				t.Fatalf("a normal target should be carried by its selected agent, got %q", got)
			}
		}
	}
}

func itoaTest(port int) string { return strconv.Itoa(port) }

func TestSamePrivateAddressUsesSelectedAgent(t *testing.T) {
	h := newHarness(t, true)
	a := h.enrolledAgent(t, "one")
	b := h.enrolledAgent(t, "two")
	for _, agent := range []uint32{a.id, b.id} {
		_, err := h.server.Store().AddResource(store.ResourceInput{
			Name:     "service-" + strconv.FormatUint(uint64(agent), 10),
			Protocol: store.ProtocolTCP, ListenPort: freePort(t),
			Targets: []store.ResourceTargetInput{{AgentID: agent, Host: "192.168.4.2", Port: 8080}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, resource := range h.server.Store().Resources() {
		target := resource.Targets[0]
		dial := h.server.DialAddress(resource.ID, target)
		wantHost := h.agentAddress(t, target.AgentID)
		host, _, err := net.SplitHostPort(dial)
		if err != nil || host != wantHost {
			t.Fatalf("target for agent %d dialled %q, want host %q", target.AgentID, dial, wantHost)
		}
		forwards := h.server.Forwards(target.AgentID)
		if len(forwards) != 1 || forwards[0].Target != "192.168.4.2:8080" {
			t.Fatalf("agent %d forwards = %+v", target.AgentID, forwards)
		}
	}
}
