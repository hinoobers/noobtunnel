package control_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestControlExitNodeCanBeDisabled proves the built-in exit node can be switched
// off, so resources have to live on additional addresses.
func TestControlExitNodeCanBeDisabled(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)

	status, body, _ := h.api("PATCH", "/api/exitnodes/control",
		map[string]any{"name": "Control node", "enabled": false}, admin)
	if status != http.StatusOK {
		t.Fatalf("disabling the control node returned %d: %s", status, body)
	}
	var updated struct {
		ExitNode struct {
			Enabled bool `json:"enabled"`
		} `json:"exitNode"`
	}
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ExitNode.Enabled {
		t.Fatal("the control node should be disabled")
	}

	// It still cannot be renamed, moved or deleted.
	if status, _, _ := h.api("PATCH", "/api/exitnodes/control",
		map[string]any{"name": "renamed", "enabled": true}, admin); status != http.StatusBadRequest {
		t.Fatalf("renaming the control node returned %d", status)
	}
	if status, _, _ := h.api("PATCH", "/api/exitnodes/control",
		map[string]any{"address": "203.0.113.5", "enabled": true}, admin); status != http.StatusBadRequest {
		t.Fatalf("moving the control node returned %d", status)
	}
	if status, _, _ := h.api("DELETE", "/api/exitnodes/control", nil, admin); status != http.StatusBadRequest {
		t.Fatalf("deleting the control node returned %d", status)
	}

	// A resource may no longer be published on it.
	agent := h.enrolledAgent(t, "homelab")
	status, body, _ = h.api("POST", "/api/resources", resourceBody(
		"on the control node", "tcp", agent.id, h.agentAddress(t, agent.id), 22, freePort(t), nil), admin)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "disabled") {
		t.Fatalf("publishing on a disabled control node returned %d: %s", status, body)
	}
}

// TestResourceStopsWhenItsExitNodeIsDisabled covers an existing resource.
func TestResourceStopsWhenItsExitNodeIsDisabled(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	listenPort := freePort(t)

	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"ssh", "tcp", agent.id, h.agentAddress(t, agent.id), 22, listenPort, nil), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}
	if status, body, _ := h.api("PATCH", "/api/exitnodes/control",
		map[string]any{"name": "Control node", "enabled": false}, admin); status != http.StatusOK {
		t.Fatalf("disabling the control node returned %d: %s", status, body)
	}

	// The resource reports why it stopped rather than looking broken.
	deadline := 20
	for i := 0; i < deadline; i++ {
		status, body, _ = h.api("GET", "/api/state", nil, admin)
		var view struct {
			Resources []struct {
				Listening bool   `json:"listening"`
				LastError string `json:"lastError"`
			} `json:"resources"`
		}
		if json.Unmarshal(body, &view) == nil && len(view.Resources) == 1 {
			res := view.Resources[0]
			if !res.Listening && strings.Contains(res.LastError, "disabled") {
				break
			}
		}
		sleepBriefly()
	}
	var view struct {
		Resources []struct {
			Listening bool   `json:"listening"`
			LastError string `json:"lastError"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if view.Resources[0].Listening || !strings.Contains(view.Resources[0].LastError, "disabled") {
		t.Fatalf("a resource on a disabled exit node should stop and say so: %+v", view.Resources[0])
	}

	// Re-enabling brings it back.
	if status, body, _ := h.api("PATCH", "/api/exitnodes/control",
		map[string]any{"name": "Control node", "enabled": true}, admin); status != http.StatusOK {
		t.Fatalf("re-enabling returned %d: %s", status, body)
	}
	deadline = 20
	for i := 0; i < deadline; i++ {
		status, body, _ = h.api("GET", "/api/state", nil, admin)
		if json.Unmarshal(body, &view) == nil && len(view.Resources) == 1 && view.Resources[0].Listening {
			return
		}
		sleepBriefly()
	}
	t.Fatalf("the resource did not come back: %s", body)
}
