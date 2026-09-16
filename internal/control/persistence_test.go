package control_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/control"
)

// TestPasswordChangeSurvivesRestart reproduces a real report: changing the
// password in the UI, then restarting the server with the same --admin-password
// flag, silently reverted the password.
func TestPasswordChangeSurvivesRestart(t *testing.T) {
	const (
		original = "correct-horse-battery-staple"
		changed  = "a-much-longer-password"
	)
	dir := t.TempDir()
	withPassword := func(opts *control.Options) { opts.AdminPassword = original }

	first := newHarnessOnDir(t, true, "", dir, withPassword)
	admin := first.login(t)
	status, body, _ := first.api("POST", "/api/password", map[string]any{
		"current": original, "password": changed,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("changing the password returned %d: %s", status, body)
	}
	// The new password works straight away.
	first.loginAs(t, "admin", changed)
	first.stop()

	// Restarting with the same command must not touch the stored password.
	second := newHarnessOnDir(t, true, "", dir, withPassword)
	defer second.stop()
	status, body, _ = second.api("POST", "/api/login", map[string]string{
		"username": "admin", "password": original,
	}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("the old password still works after a restart (%d): %s", status, body)
	}
	status, body, _ = second.api("POST", "/api/login", map[string]string{
		"username": "admin", "password": changed,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("the changed password was lost on restart (%d): %s", status, body)
	}
}

// TestStateSurvivesRestart covers the rest of the configuration the same way.
func TestStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	first := newHarnessOnDir(t, true, "", dir, nil)
	admin := first.login(t)

	if status, body, _ := first.api("POST", "/api/domains", map[string]any{"hostname": "keep.example.com"}, admin); status != http.StatusOK {
		t.Fatalf("adding a domain returned %d: %s", status, body)
	}
	if status, body, _ := first.api("POST", "/api/exitnodes", map[string]any{
		"name": "second ip", "kind": "address", "address": "203.0.113.99",
	}, admin); status != http.StatusOK {
		t.Fatalf("adding an exit node returned %d: %s", status, body)
	}
	agent := first.enrolledAgent(t, "homelab")
	if status, body, _ := first.api("POST", "/api/resources",
		resourceBody("keep me", "tcp", agent.id, first.agentAddress(t, agent.id), 22, freePort(t), nil), admin); status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}
	first.stop()

	second := newHarnessOnDir(t, true, "", dir, nil)
	defer second.stop()
	admin2 := second.login(t)
	status, body, _ := second.api("GET", "/api/state", nil, admin2)
	if status != http.StatusOK {
		t.Fatalf("/api/state returned %d", status)
	}
	var view struct {
		Domains []struct {
			Hostname string `json:"hostname"`
		} `json:"domains"`
		ExitNodes []struct {
			Name string `json:"name"`
		} `json:"exitNodes"`
		Resources []struct {
			Name string `json:"name"`
		} `json:"resources"`
		Agents []struct {
			Address string `json:"address"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Domains) != 1 || view.Domains[0].Hostname != "keep.example.com" {
		t.Fatalf("domains were lost: %+v", view.Domains)
	}
	if len(view.ExitNodes) != 2 {
		t.Fatalf("exit nodes were lost: %+v", view.ExitNodes)
	}
	if len(view.Resources) != 1 || view.Resources[0].Name != "keep me" {
		t.Fatalf("resources were lost: %+v", view.Resources)
	}
	if len(view.Agents) != 1 {
		t.Fatalf("agents were lost: %+v", view.Agents)
	}
}
