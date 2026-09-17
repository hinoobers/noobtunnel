package control_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func TestAPIRequiresAuthentication(t *testing.T) {
	h := newHarness(t, true)
	status, _, _ := h.api("GET", "/api/state", nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/state returned %d, want 401", status)
	}
	if status, _, _ := h.api("GET", "/api/health", nil, nil); status != http.StatusOK {
		t.Fatalf("health check returned %d, want 200", status)
	}
}

func TestLoginAndSessionLifecycle(t *testing.T) {
	h := newHarness(t, true)
	status, _, _ := h.api("POST", "/api/login", map[string]string{"password": "wrong"}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("bad password returned %d, want 401", status)
	}
	cookies := h.login(t)
	status, body, _ := h.api("GET", "/api/state", nil, cookies)
	if status != http.StatusOK {
		t.Fatalf("authenticated /api/state returned %d", status)
	}
	var view map[string]any
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("state is not JSON: %v", err)
	}
	for _, key := range []string{"server", "settings", "agents", "summary", "health"} {
		if _, ok := view[key]; !ok {
			t.Fatalf("state is missing %q", key)
		}
	}
	if status, _, _ := h.api("POST", "/api/logout", map[string]any{}, cookies); status != http.StatusOK {
		t.Fatalf("logout returned %d", status)
	}
}

func TestMutatingRequestsNeedTheGuardHeader(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)
	// Same cookie, but without the custom header: a cross-site form post.
	request, err := http.NewRequest("POST", "https://"+h.address+"/api/agents", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := h.client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("request without the guard header returned %d, want 403", response.StatusCode)
	}
}

func TestAddAgentReturnsUsableInstallCommand(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)
	status, body, _ := h.api("POST", "/api/agents", map[string]any{
		"name": "new box", "advertise": []string{"192.168.44.0/24"}, "ttlHours": 24,
	}, cookies)
	if status != http.StatusOK {
		t.Fatalf("add agent returned %d: %s", status, body)
	}
	var result struct {
		Agent struct {
			ID        uint32   `json:"id"`
			Name      string   `json:"name"`
			Address   string   `json:"address"`
			Prefix    string   `json:"prefix"`
			Token     string   `json:"token"`
			Advertise []string `json:"advertise"`
		} `json:"agent"`
		InstallCommand string `json:"installCommand"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Agent.Name != "new box" {
		t.Fatalf("name = %q", result.Agent.Name)
	}
	if !strings.HasSuffix(result.Agent.Prefix, "/32") {
		t.Fatalf("prefix = %q, want a /32 assignment", result.Agent.Prefix)
	}
	if len(result.Agent.Advertise) != 1 || result.Agent.Advertise[0] != "192.168.44.0/24" {
		t.Fatalf("advertise = %v", result.Agent.Advertise)
	}
	command := result.InstallCommand
	for _, want := range []string{
		"/install.sh", "--token", result.Agent.Token, "--fingerprint",
		h.server.Cert().Fingerprint, "--name", "--advertise",
		"pinnedpubkey", "sha256//" + h.server.Cert().Pin,
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("install command is missing %q:\n%s", want, command)
		}
	}
	if !strings.HasPrefix(command, "curl ") {
		t.Fatalf("install command should start with curl: %s", command)
	}
	if strings.ContainsAny(result.Agent.Name, "'\"") {
		t.Fatal("test name should be unquoted-safe")
	}
}

func TestAgentLifecycleThroughAPI(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)
	sim := h.addAgent("lifecycle", true)
	waitFor(t, "agent online", 15*time.Second, func() bool { return h.onlineCount() == 1 })

	status, body, _ := h.api("GET", fmt.Sprintf("/api/agents/%d", sim.id), nil, cookies)
	if status != http.StatusOK {
		t.Fatalf("get agent returned %d", status)
	}
	if !strings.Contains(string(body), "lifecycle") {
		t.Fatalf("agent detail is missing the name: %s", body)
	}

	status, _, _ = h.api("PATCH", fmt.Sprintf("/api/agents/%d", sim.id),
		map[string]any{"name": "renamed", "advertise": []string{"10.9.0.0/16"}}, cookies)
	if status != http.StatusOK {
		t.Fatalf("rename returned %d", status)
	}
	updated, err := h.server.Store().Agent(sim.id)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "renamed" || len(updated.Advertise) != 1 {
		t.Fatalf("agent was not updated: %+v", updated)
	}

	status, body, _ = h.api("POST", fmt.Sprintf("/api/agents/%d/ping", sim.id), map[string]any{}, cookies)
	if status != http.StatusOK || !strings.Contains(string(body), `"online":true`) {
		t.Fatalf("ping returned %d: %s", status, body)
	}

	status, _, _ = h.api("PATCH", fmt.Sprintf("/api/agents/%d", sim.id), map[string]any{"enabled": false}, cookies)
	if status != http.StatusOK {
		t.Fatalf("disable returned %d", status)
	}
	select {
	case <-sim.runErr:
	case <-time.After(15 * time.Second):
		t.Fatal("disabling the agent should end its session")
	}

	status, _, _ = h.api("DELETE", fmt.Sprintf("/api/agents/%d", sim.id), nil, cookies)
	if status != http.StatusOK {
		t.Fatalf("delete returned %d", status)
	}
	if _, err := h.server.Store().Agent(sim.id); err == nil {
		t.Fatal("agent should be gone after delete")
	}
}

func TestSettingsValidation(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)
	status, body, _ := h.api("POST", "/api/settings", map[string]any{
		"meshName": "broken", "meshCidr": "not-a-cidr", "mtu": 1420, "keepaliveSec": 25,
		"directPaths": true, "wgListenPort": 51820,
	}, cookies)
	if status != http.StatusBadRequest {
		t.Fatalf("invalid CIDR returned %d: %s", status, body)
	}
	settings := h.server.Settings()
	body2, _ := json.Marshal(settings)
	var payload map[string]any
	_ = json.Unmarshal(body2, &payload)
	payload["meshName"] = "renamed-mesh"
	payload["meshCidr"] = "10.88.0.0/16"
	status, _, _ = h.api("POST", "/api/settings", payload, cookies)
	if status != http.StatusOK {
		t.Fatalf("valid settings returned %d", status)
	}
	if got := h.server.Settings().MeshCIDR; got != "10.88.0.0/16" {
		t.Fatalf("mesh CIDR = %s", got)
	}
}

func TestInstallScriptAndDownloads(t *testing.T) {
	h := newHarness(t, true)
	status, script, _ := h.api("GET", "/install.sh", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("/install.sh returned %d", status)
	}
	text := string(script)
	for _, want := range []string{"#!/bin/sh", "--token", "wireguard-tools", "systemd", "--uninstall", "noobtunnel_linux_"} {
		if !strings.Contains(text, want) {
			t.Fatalf("installer is missing %q", want)
		}
	}
	status, cert, _ := h.api("GET", "/cert.pem", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(cert), "BEGIN CERTIFICATE") {
		t.Fatalf("cert.pem returned %d", status)
	}
	// No binaries configured: the manifest is empty but well formed.
	status, manifest, _ := h.api("GET", "/download/manifest.json", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(manifest), `"binaries"`) {
		t.Fatalf("manifest returned %d: %s", status, manifest)
	}
	if status, _, _ := h.api("GET", "/download/nonexistent", nil, nil); status != http.StatusNotFound {
		t.Fatalf("unknown artifact returned %d, want 404", status)
	}
	if status, _, _ := h.api("GET", "/download/..%2fstate.json", nil, nil); status == http.StatusOK {
		t.Fatal("path traversal must be rejected")
	}
}

// TestUIAssetsAreServed guards the "blank page" failure: the UI is useless if
// the embedded scripts are not reachable.
func TestUIAssetsAreServed(t *testing.T) {
	h := newHarness(t, true)
	status, index, _ := h.api("GET", "/", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(index), "/assets/app.js") {
		t.Fatalf("index returned %d with %d bytes", status, len(index))
	}
	for _, name := range []string{"app.js", "views.js", "style.css"} {
		status, body, _ := h.api("GET", "/assets/"+name, nil, nil)
		if status != http.StatusOK || len(body) < 200 {
			t.Fatalf("/assets/%s returned %d with %d bytes", name, status, len(body))
		}
	}
	status, icon, _ := h.api("GET", "/favicon.svg", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(icon), "<svg") {
		t.Fatalf("favicon returned %d", status)
	}
	// Unknown paths must not leak the SPA shell.
	// Tab URLs (and any other path) serve the app so a browser refresh works.
	for _, path := range []string{"/settings", "/resources", "/resources/42", "/domains", "/agents", "/some/deep/path"} {
		status, body, _ := h.api("GET", path, nil, nil)
		if status != http.StatusOK || !strings.Contains(string(body), "/assets/app.js") {
			t.Fatalf("GET %s returned %d, it should serve the app so refreshes work", path, status)
		}
	}
	// A mutation on an unknown path is still refused.
	if status, _, _ := h.api("POST", "/settings", map[string]any{}, nil); status == http.StatusOK {
		t.Fatal("POST to an unknown path should not succeed")
	}
}

// TestServedLogsTabsSitAtPageLevel checks the page the control node actually
// serves: the Logs tab row belongs to the view itself, above the cards, exactly
// the way the Settings tabs are laid out. A stale or restructured template that
// buries the row inside a panel fails here.
func TestServedLogsTabsSitAtPageLevel(t *testing.T) {
	h := newHarness(t, true)
	status, index, _ := h.api("GET", "/", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("index returned %d", status)
	}
	page := string(index)
	start := strings.Index(page, `data-view-panel="activity"`)
	if start < 0 {
		t.Fatal("the served page has no Logs view")
	}
	end := strings.Index(page[start:], "</section>")
	if end < 0 {
		t.Fatal("the served Logs view is not closed")
	}
	section := page[start : start+end]
	nav := strings.Index(section, `<nav class="tabs"`)
	if nav < 0 {
		t.Fatal("the served Logs view has no tab row")
	}
	if strings.Contains(section[:nav], `<div class="panel`) {
		t.Fatal("the Logs tab row is nested inside a panel; it should sit on the view like Settings")
	}
	for _, panel := range []string{"requests", "activity"} {
		if !strings.Contains(section, `data-tab-panel="`+panel+`"`) {
			t.Fatalf("the served Logs view has no %q panel", panel)
		}
	}
}

func TestDownloadServesConfiguredBinary(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("#!/bin/sh\necho fake agent\n")
	if err := os.WriteFile(filepath.Join(dir, "noobtunnel_linux_amd64"), payload, 0o755); err != nil {
		t.Fatal(err)
	}
	h := newHarnessWithBinaryDir(t, dir)
	status, body, _ := h.api("GET", "/download/noobtunnel_linux_amd64", nil, nil)
	if status != http.StatusOK || string(body) != string(payload) {
		t.Fatalf("binary download returned %d with %d bytes", status, len(body))
	}
	status, manifest, _ := h.api("GET", "/download/manifest.json", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(manifest), "noobtunnel_linux_amd64") {
		t.Fatalf("manifest should list the binary: %s", manifest)
	}
	if !strings.Contains(string(manifest), `"sha256":`) {
		t.Fatal("manifest should carry a checksum")
	}
	checks := h.server.RunChecks(t.Context())
	found := false
	for _, check := range checks {
		if check.ID == "binaries" && check.Status == "ok" {
			found = true
		}
	}
	if !found {
		t.Fatal("the binaries check should pass once binaries are present")
	}
}

func TestAPITokens(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)
	status, body, _ := h.api("POST", "/api/tokens", map[string]any{"name": "ci"}, cookies)
	if status != http.StatusOK {
		t.Fatalf("create token returned %d: %s", status, body)
	}
	var created struct {
		Token string `json:"token"`
		Meta  struct {
			ID string `json:"id"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, "ntapi_") {
		t.Fatalf("token = %q", created.Token)
	}

	// Use the bearer token instead of a session cookie.
	request, err := http.NewRequest("GET", "https://"+h.address+"/api/state", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+created.Token)
	response, err := h.client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bearer token was rejected with %d", response.StatusCode)
	}

	if status, _, _ := h.api("DELETE", "/api/tokens/"+created.Meta.ID, nil, cookies); status != http.StatusOK {
		t.Fatalf("revoke returned %d", status)
	}
	request2, _ := http.NewRequest("GET", "https://"+h.address+"/api/state", nil)
	request2.Header.Set("Authorization", "Bearer "+created.Token)
	response2, err := h.client().Do(request2)
	if err != nil {
		t.Fatal(err)
	}
	defer response2.Body.Close()
	if response2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token still worked: %d", response2.StatusCode)
	}
}

func TestAddedAgentIsVisibleInState(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)
	if status, _, _ := h.api("POST", "/api/agents", map[string]any{"name": "visible"}, cookies); status != http.StatusOK {
		t.Fatal("could not add agent")
	}
	status, body, _ := h.api("GET", "/api/state", nil, cookies)
	if status != http.StatusOK {
		t.Fatalf("state returned %d", status)
	}
	var view struct {
		Agents []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"agents"`
		Summary struct {
			Agents int `json:"agents"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Agents) != 1 || view.Agents[0].Name != "visible" {
		t.Fatalf("agents = %+v", view.Agents)
	}
	if view.Agents[0].Address != "10.77.0.2" {
		t.Fatalf("address = %s", view.Agents[0].Address)
	}
	if view.Summary.Agents != 1 {
		t.Fatalf("summary = %+v", view.Summary)
	}
}

// TestStoreRoundTrip covers persistence of enrollments across restarts.
func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	first, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := first.AddAgent(store.AddAgentParams{Name: "persisted", Advertise: []string{"192.168.9.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	hub := first.Hub()
	second, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := second.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Token != agent.Token || reloaded.Address != agent.Address {
		t.Fatalf("agent did not survive a restart: %+v", reloaded)
	}
	if second.Hub().PublicKey != hub.PublicKey {
		t.Fatal("the hub key must be stable across restarts")
	}
	if key, err := second.PairKey(agent.ID, agent.ID+1); err != nil || key == "" {
		t.Fatalf("pair key creation failed: %v", err)
	}
}
