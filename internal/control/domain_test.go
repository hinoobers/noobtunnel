package control_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/control"
)

// testDomain is the hostname used by the domain mode tests.
const testDomain = "noobtunnel.example.com"

// domainHarness starts a control node published on its own domain.
func domainHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessOpts(t, true, "", func(opts *control.Options) {
		opts.Domain = testDomain
		// Port 443 is what a real deployment shares with published resources;
		// tests use a free port so they never need a privileged one.
		opts.ControlRoutePort = freePort(t)
	})
}

// TestDomainCheckReportsThePublicRoute covers the preflight line operators look
// at when the UI is not reachable on its hostname.
func TestDomainCheckReportsThePublicRoute(t *testing.T) {
	h := domainHarness(t)
	checks := h.server.RunChecks(context.Background())
	var found bool
	for _, check := range checks {
		if check.ID != "domain" {
			continue
		}
		found = true
		if check.Status != "ok" || !strings.Contains(check.Detail, "https://"+testDomain) {
			t.Fatalf("domain check = %+v", check)
		}
	}
	if !found {
		t.Fatal("no domain check was reported")
	}
}

// TestDomainCheckExplainsAnUnpublishedRoute covers the failure operators hit
// when a web server already holds port 443.
func TestDomainCheckExplainsAnUnpublishedRoute(t *testing.T) {
	h := newHarness(t, true)
	checks := h.server.RunChecks(context.Background())
	for _, check := range checks {
		if check.ID == "domain" {
			if check.Status != "info" || !strings.Contains(check.Detail, "TLS listener only") {
				t.Fatalf("domain check without a domain = %+v", check)
			}
			return
		}
	}
	t.Fatal("no domain check was reported")
}

// TestDomainModeAdvertisesTheControlNode checks the UI sees the public address
// the operator should hand out.
func TestDomainModeAdvertisesTheControlNode(t *testing.T) {
	h := domainHarness(t)
	status, body, _ := h.api("GET", "/api/state", nil, h.login(t))
	if status != http.StatusOK {
		t.Fatalf("/api/state returned %d", status)
	}
	page := string(body)
	if !strings.Contains(page, `"domain":"`+testDomain+`"`) {
		t.Fatalf("state does not report the domain: %s", page)
	}
	if !strings.Contains(page, `"publicURL":"https://`+testDomain+`"`) {
		t.Fatalf("state does not report the public URL: %s", page)
	}
}

// TestAgentCommandsKeepPinningAcrossCertificateRenewals is the reason agents are
// pointed at the control listener rather than at the public 443 route: the
// managed certificate is renewed, the pinned one never is.
func TestAgentCommandsKeepPinningAcrossCertificateRenewals(t *testing.T) {
	h := domainHarness(t)
	status, body, _ := h.api("POST", "/api/agents", map[string]any{"name": "domain-box"}, h.login(t))
	if status != http.StatusOK {
		t.Fatalf("add agent returned %d: %s", status, body)
	}
	var result struct {
		InstallCommand string `json:"installCommand"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	command := result.InstallCommand
	for _, want := range []string{
		"--server " + testDomain + ":",
		"--fingerprint " + h.server.Cert().Fingerprint,
		"sha256//" + h.server.Cert().Pin,
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("install command is missing %q:\n%s", want, command)
		}
	}
	// The browser's own address must not leak into the agent command.
	for _, unwanted := range []string{"127.0.0.1", "localhost"} {
		if strings.Contains(command, unwanted) {
			t.Fatalf("install command should not contain %q:\n%s", unwanted, command)
		}
	}
}

// TestControlDomainCannotBePublishedAsAResource keeps a resource from claiming
// the name the control node answers on, where it would never be reached.
func TestControlDomainCannotBePublishedAsAResource(t *testing.T) {
	h := domainHarness(t)
	status, body, _ := h.api("POST", "/api/resources", map[string]any{
		"name":     "clash",
		"protocol": "https",
		"domain":   testDomain,
		"targets":  []any{},
	}, h.login(t))
	if status != http.StatusBadRequest {
		t.Fatalf("publishing on the control domain returned %d: %s", status, body)
	}
	if !strings.Contains(string(body), "control node") {
		t.Fatalf("error should explain the clash: %s", body)
	}
}
// TestDockerInstallMethodMarksTheCommand covers the "Install with: Docker"
// choice in the UI: the same command, plus --docker so the installer on the
// target machine writes compose files instead of a systemd unit.
func TestDockerInstallMethodMarksTheCommand(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)

	commandFor := func(path, name string) string {
		t.Helper()
		status, body, _ := h.api("POST", path, map[string]any{"name": name}, cookies)
		if status != http.StatusOK {
			t.Fatalf("adding %s returned %d: %s", name, status, body)
		}
		var result struct {
			InstallCommand string `json:"installCommand"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return result.InstallCommand
	}

	docker := commandFor("/api/agents?method=docker", "docker-box")
	if !strings.Contains(docker, " --docker") {
		t.Fatalf("the Docker install command should carry --docker:\n%s", docker)
	}
	if !strings.Contains(docker, "/install.sh") {
		t.Fatalf("the Docker install command should still use the control node's installer:\n%s", docker)
	}
	service := commandFor("/api/agents", "service-box")
	if strings.Contains(service, "--docker") {
		t.Fatalf("the default command should not ask for Docker:\n%s", service)
	}
}
