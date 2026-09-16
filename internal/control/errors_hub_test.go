package control_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestSimulatedBackendIsReportedInTheErrorsView covers the case that looks like a
// broken service and is not: a control node running with the simulated backend
// (the demo flags) enrols agents and hands out addresses, but no WireGuard device
// exists on the host at all, so every target fails with "no route to host" while
// the dashboard otherwise looks healthy.
func TestSimulatedBackendIsReportedInTheErrorsView(t *testing.T) {
	h := newHarness(t, true) // the test harness runs the simulated backend
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	listenPort := freePort(t)
	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"phpmyadmin", "tcp", agent.id, h.agentAddress(t, agent.id), freePort(t), listenPort, nil), admin)
	if status != 200 {
		t.Fatalf("publishing returned %d: %s", status, body)
	}
	var created struct {
		Resource struct {
			ID uint32 `json:"id"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	// Force a reconcile so the report appears without waiting for the loop.
	if status, _, _ := h.api("PATCH", "/api/resources/"+fmt.Sprint(created.Resource.ID), resourceBody(
		"phpmyadmin", "tcp", agent.id, h.agentAddress(t, agent.id), freePort(t), listenPort, nil), admin); status != 200 {
		t.Fatal("updating the resource failed")
	}

	deadline := time.Now().Add(10 * time.Second)
	var seen []string
	for time.Now().Before(deadline) {
		_, state, _ := h.api("GET", "/api/state", nil, admin)
		var view struct {
			Errors []struct {
				Source  string `json:"source"`
				Message string `json:"message"`
				Detail  string `json:"detail"`
				Hint    string `json:"hint"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(state, &view); err != nil {
			t.Fatal(err)
		}
		seen = seen[:0]
		for _, entry := range view.Errors {
			seen = append(seen, entry.Source+": "+entry.Message)
			if entry.Source != "wireguard" || !strings.Contains(entry.Message, "simulated") {
				continue
			}
			if entry.Detail == "" || entry.Hint == "" {
				t.Fatalf("the entry should explain itself: %+v", entry)
			}
			if !strings.Contains(entry.Hint, "--backend fake") {
				t.Fatalf("the hint should name the fix: %+v", entry)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the simulated backend was never reported, entries: %v", seen)
}
