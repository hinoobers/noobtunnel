package control_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestDiagnoseExplainsAnUnreachableTarget covers the "diagnose" action: the
// control node reports each step of the path to a target, so the operator does not
// have to SSH in to find out which side is broken.
func TestDiagnoseExplainsAnUnreachableTarget(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	listenPort := freePort(t)
	address := fmt.Sprintf("%s:%d", h.agentAddress(t, agent.id), freePort(t))
	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"phpmyadmin", "tcp", agent.id, h.agentAddress(t, agent.id), freePort(t), listenPort, nil), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}
	var created struct {
		Resource struct {
			ID      uint32 `json:"id"`
			Targets []struct {
				ID uint32 `json:"id"`
			} `json:"targets"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Resource.Targets) == 0 {
		t.Fatal("the resource has no targets")
	}

	status, body, _ = h.api("POST", "/api/diagnose", map[string]any{
		"resourceId": created.Resource.ID,
		"targetId":   created.Resource.Targets[0].ID,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("diagnose returned %d: %s", status, body)
	}
	var result struct {
		Target        string `json:"target"`
		Resource      string `json:"resource"`
		Verdict       string `json:"verdict"`
		VerdictStatus string `json:"verdictStatus"`
		Steps         []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Detail string `json:"detail"`
			Hint   string `json:"hint"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Resource != "phpmyadmin" {
		t.Fatalf("diagnose answered about %q", result.Resource)
	}
	// Every step the operator needs to see is there, in the order a connection
	// takes them.
	// "Mesh routing" sits between the route and the connection: it says whose
	// address this is, which is what makes two machines with the same private
	// range work at once.
	wanted := []string{"WireGuard backend", "Hub interface", "Tunnel handshake", "Route from the control node", "Mesh routing", "Connect to the target"}
	// The agent is asked about its own side too: that is the half the control
	// node cannot see, and the answer decides what the operator does next.
	wanted = append(wanted, "Reach the target from the agent")
	if len(result.Steps) != len(wanted) {
		t.Fatalf("expected %d steps, got %d: %+v", len(wanted), len(result.Steps), result.Steps)
	}
	for i, name := range wanted {
		if result.Steps[i].Name != name {
			t.Fatalf("step %d = %q, want %q", i, result.Steps[i].Name, name)
		}
		if result.Steps[i].Detail == "" {
			t.Fatalf("step %q has no detail: %+v", name, result.Steps[i])
		}
	}
	if result.Verdict == "" {
		t.Fatal("the diagnosis should end with a verdict")
	}
	// The harness runs the simulated backend, so this is the case that looks like
	// a broken service and is not.
	if result.VerdictStatus != "fail" || !strings.Contains(result.Verdict, "simulated") {
		t.Fatalf("the verdict should name the simulated backend: %+v", result)
	}
	if result.Steps[0].Hint == "" {
		t.Fatalf("the failing step should say what to do: %+v", result.Steps[0])
	}
	_ = address
}
