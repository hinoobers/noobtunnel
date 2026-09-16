package control_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestTargetErrorsReachTheErrorsView covers the report "my targets show an error
// under Resources, yet there is nothing in Logs -> Errors". The Errors view only
// knew about resource level failures, so a single unreachable target (the other
// one still serving) had nowhere to appear.
func TestTargetErrorsReachTheErrorsView(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	listenPort := freePort(t)
	// Nothing listens on this port behind the agent, so dialling it fails.
	deadPort := freePort(t)
	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"dead-service", "tcp", agent.id, h.agentAddress(t, agent.id), deadPort, listenPort, nil), admin)
	if status != http.StatusOK {
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

	// One connection makes the proxy try the target, which is what records the
	// per target error the Resources tab shows.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err == nil {
		_ = conn.Close()
	}
	// Force a reconcile so the failure is picked up without waiting for the loop.
	if status, body, _ := h.api("PATCH", "/api/resources/"+fmt.Sprint(created.Resource.ID), resourceBody(
		"dead-service", "tcp", agent.id, h.agentAddress(t, agent.id), deadPort, listenPort, nil), admin); status != http.StatusOK {
		t.Fatalf("updating the resource returned %d: %s", status, body)
	}

	deadline := time.Now().Add(10 * time.Second)
	var entries []struct {
		Source  string `json:"source"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
		Hint    string `json:"hint"`
	}
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
		entries = view.Errors
		for _, entry := range entries {
			if entry.Source == "target" {
				if !strings.Contains(entry.Message, "dead-service") || !strings.Contains(entry.Message, "not reachable") {
					t.Fatalf("unexpected target error: %+v", entry)
				}
				if entry.Detail == "" || entry.Hint == "" {
					t.Fatalf("the target error should carry the reason and what to check: %+v", entry)
				}
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the target failure never reached the Errors view, entries: %+v", entries)
}
