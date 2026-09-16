package control_test

import (
	"net/http"
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
	want := address + ":3306"
	forwards := h.server.Forwards(agent.id)
	if len(forwards) != 1 || forwards[0].Port != 3306 || forwards[0].Target != "127.0.0.1:3306" {
		t.Fatalf("the agent should carry the loopback service, got %+v", forwards)
	}
	for _, resource := range h.server.Store().Resources() {
		if resource.Name != "mysql" {
			continue
		}
		for _, target := range resource.Targets {
			if got := h.server.DialAddress(target); got != want {
				t.Fatalf("the control node should dial %q, got %q", want, got)
			}
		}
	}

	// A normal address is dialled as the operator wrote it.
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
			if got := h.server.DialAddress(target); got != "192.168.50.9:80" {
				t.Fatalf("a normal target should be dialled directly, got %q", got)
			}
		}
	}
}
