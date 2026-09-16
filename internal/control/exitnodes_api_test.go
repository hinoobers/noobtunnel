package control_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// fakeRunner records the host commands the control node tries to run.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, line)
	return "", nil
}

func (f *fakeRunner) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func TestExitNodeDefaultAndCrud(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)

	// The control node is always present and cannot be removed.
	status, body, _ := h.api("GET", "/api/exitnodes", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("listing exit nodes returned %d", status)
	}
	var list struct {
		ExitNodes []struct {
			ID        string `json:"id"`
			Kind      string `json:"kind"`
			Deletable bool   `json:"deletable"`
			Status    string `json:"status"`
		} `json:"exitNodes"`
		LocalAddresses []string `json:"localAddresses"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.ExitNodes) != 1 || list.ExitNodes[0].Kind != "control" || list.ExitNodes[0].Deletable {
		t.Fatalf("expected exactly one built-in exit node: %+v", list.ExitNodes)
	}
	if list.ExitNodes[0].Status != "ready" {
		t.Fatalf("the control node exit node should be ready: %+v", list.ExitNodes[0])
	}
	if len(list.LocalAddresses) == 0 {
		t.Fatal("the API should report the host's local addresses")
	}
	status, body, _ = h.api("DELETE", "/api/exitnodes/control", nil, admin)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "control node") {
		t.Fatalf("deleting the built-in exit node returned %d: %s", status, body)
	}

	// Add a second address.
	status, body, _ = h.api("POST", "/api/exitnodes", map[string]any{
		"name": "second public ip", "kind": "address", "address": "203.0.113.44", "interface": "lo",
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("adding an exit node returned %d: %s", status, body)
	}
	var created struct {
		ExitNode struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Public string `json:"public"`
			Setup  struct {
				Local []string `json:"local"`
			} `json:"setup"`
		} `json:"exitNode"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ExitNode.Public != "203.0.113.44" {
		t.Fatalf("public address = %q", created.ExitNode.Public)
	}
	// The test host does not own that address, so it needs setup.
	if created.ExitNode.Status != "not-configured" {
		t.Fatalf("status = %q, want not-configured", created.ExitNode.Status)
	}
	if len(created.ExitNode.Setup.Local) == 0 {
		t.Fatal("an unconfigured exit node should come with setup commands")
	}
	if !strings.Contains(strings.Join(created.ExitNode.Setup.Local, " "), "203.0.113.44") {
		t.Fatalf("setup commands should mention the address: %v", created.ExitNode.Setup.Local)
	}

	// Invalid input is refused.
	if status, body, _ := h.api("POST", "/api/exitnodes", map[string]any{
		"name": "bad", "kind": "address", "address": "not-an-ip",
	}, admin); status != http.StatusBadRequest {
		t.Fatalf("an invalid address returned %d: %s", status, body)
	}

	// Delete it again.
	if status, body, _ := h.api("DELETE", "/api/exitnodes/"+created.ExitNode.ID, nil, admin); status != http.StatusOK {
		t.Fatalf("deleting returned %d: %s", status, body)
	}
}

func TestResourceOnAnExtraExitNode(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")

	status, body, _ := h.api("POST", "/api/exitnodes", map[string]any{
		"name": "second ip", "kind": "address", "address": "203.0.113.77", "interface": "lo",
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("adding an exit node returned %d: %s", status, body)
	}
	var created struct {
		ExitNode struct {
			ID string `json:"id"`
		} `json:"exitNode"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}

	listenPort := freePort(t)
	status, body, _ = h.api("POST", "/api/resources", resourceBody("on the second ip", "tcp",
		agent.id, h.agentAddress(t, agent.id), 22, listenPort,
		map[string]any{"exitNodeId": created.ExitNode.ID}), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing on an exit node returned %d: %s", status, body)
	}
	var published struct {
		Resource struct {
			ID           uint32 `json:"id"`
			ExitNodeName string `json:"exitNodeName"`
			ExitNodeAddr string `json:"exitNodeAddress"`
			Public       string `json:"public"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &published); err != nil {
		t.Fatal(err)
	}
	if published.Resource.ExitNodeName != "second ip" || published.Resource.ExitNodeAddr != "203.0.113.77" {
		t.Fatalf("resource should name its exit node: %+v", published.Resource)
	}
	if !strings.Contains(published.Resource.Public, "203.0.113.77") {
		t.Fatalf("public address should use the exit node: %q", published.Resource.Public)
	}

	// The address is not on this host, so the listener cannot bind and that must
	// be visible instead of silent.
	deadline := 20
	for i := 0; i < deadline; i++ {
		status, body, _ = h.api("GET", "/api/state", nil, admin)
		var view struct {
			Resources []struct {
				Listening bool   `json:"listening"`
				LastError string `json:"lastError"`
			} `json:"resources"`
		}
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && len(view.Resources) == 1 {
			if view.Resources[0].LastError != "" {
				if !strings.Contains(view.Resources[0].LastError, "203.0.113.77") {
					t.Fatalf("the bind error should mention the address: %q", view.Resources[0].LastError)
				}
				break
			}
		}
		sleepBriefly()
	}

	// The exit node is in use, so it cannot be removed.
	status, body, _ = h.api("DELETE", "/api/exitnodes/"+created.ExitNode.ID, nil, admin)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "published") {
		t.Fatalf("deleting an exit node in use returned %d: %s", status, body)
	}
}

func TestExitNodeSetupRunsThroughTheRunner(t *testing.T) {
	runner := &fakeRunner{}
	h := newHarnessWithRunner(t, runner)
	admin := h.login(t)

	status, body, _ := h.api("POST", "/api/exitnodes", map[string]any{
		"name": "gre carried", "kind": "gre",
		"address":            "203.0.113.60",
		"localEndpoint":      "198.51.100.1",
		"peerEndpoint":       "198.51.100.2",
		"localTunnelAddress": "10.99.0.1",
		"peerTunnelAddress":  "10.99.0.2",
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("adding a GRE exit node returned %d: %s", status, body)
	}
	var created struct {
		ExitNode struct {
			ID    string `json:"id"`
			Setup struct {
				Local  []string `json:"local"`
				Remote []string `json:"remote"`
			} `json:"setup"`
		} `json:"exitNode"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	// Both ends get commands, and they mirror each other.
	if len(created.ExitNode.Setup.Local) < 3 || len(created.ExitNode.Setup.Remote) < 3 {
		t.Fatalf("a GRE node needs commands for both ends: %+v", created.ExitNode.Setup)
	}
	local := strings.Join(created.ExitNode.Setup.Local, "\n")
	if !strings.Contains(local, "ip tunnel add") || !strings.Contains(local, "198.51.100.2") {
		t.Fatalf("local setup should create the tunnel towards the peer:\n%s", local)
	}
	remote := strings.Join(created.ExitNode.Setup.Remote, "\n")
	if !strings.Contains(remote, "198.51.100.1") {
		t.Fatalf("remote setup should point back at this host:\n%s", remote)
	}

	// Applying runs the local commands only.
	status, body, _ = h.api("POST", fmt.Sprintf("/api/exitnodes/%s/apply", created.ExitNode.ID), map[string]any{}, admin)
	if status != http.StatusOK {
		t.Fatalf("applying returned %d: %s", status, body)
	}
	if strings.Contains(string(body), `"ok":false`) {
		t.Fatalf("apply should succeed with a working runner: %s", body)
	}
	calls := runner.recorded()
	if len(calls) == 0 {
		t.Fatal("no commands were run")
	}
	for _, call := range calls {
		if !strings.HasPrefix(call, "ip ") {
			t.Fatalf("unexpected command: %q", call)
		}
	}
	if !strings.Contains(strings.Join(calls, "\n"), "ip tunnel add") {
		t.Fatalf("the tunnel creation command was not run: %v", calls)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "203.0.113.60") {
		t.Fatalf("the address was never assigned: %v", calls)
	}
}

func TestViewersCannotManageExitNodes(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	h.createViewer(t, admin, "reader")
	viewer := h.loginAs(t, "reader", "viewer-password-1")

	if status, _, _ := h.api("GET", "/api/exitnodes", nil, viewer); status != http.StatusOK {
		t.Fatalf("a viewer should be able to read exit nodes: %d", status)
	}
	if status, _, _ := h.api("POST", "/api/exitnodes", map[string]any{
		"name": "sneaky", "kind": "address", "address": "203.0.113.90",
	}, viewer); status != http.StatusForbidden {
		t.Fatalf("a viewer added an exit node: %d", status)
	}
	if status, _, _ := h.api("DELETE", "/api/exitnodes/control", nil, viewer); status != http.StatusForbidden {
		t.Fatalf("a viewer deleted an exit node: %d", status)
	}
}
