package control_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// domainViewResult is the part of a domain row the tests look at.
type domainViewResult struct {
	Hostname  string `json:"hostname"`
	Pattern   string `json:"pattern"`
	Synced    bool   `json:"synced"`
	LastError string `json:"lastError"`
	Address   string `json:"address"`
}

// addDNSProvider registers a Cloudflare provider and returns its id.
func (h *harness) addDNSProvider(t *testing.T, name string, cookies []*http.Cookie) string {
	t.Helper()
	status, body, _ := h.api("POST", "/api/dns/providers", map[string]any{
		"name": name, "kind": "cloudflare", "token": "test-token",
	}, cookies)
	if status != http.StatusOK {
		t.Fatalf("adding a provider returned %d: %s", status, body)
	}
	var created struct {
		Provider struct {
			ID string `json:"id"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	return created.Provider.ID
}

// domainView reads one row of the Domains view.
func (h *harness) domainView(t *testing.T, hostname string, cookies []*http.Cookie) domainViewResult {
	t.Helper()
	status, body, _ := h.api("GET", "/api/state", nil, cookies)
	if status != http.StatusOK {
		t.Fatalf("/api/state returned %d", status)
	}
	var view struct {
		Domains []domainViewResult `json:"domains"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	for _, domain := range view.Domains {
		if domain.Hostname == hostname {
			return domain
		}
	}
	t.Fatalf("%s is not in the Domains view: %s", hostname, body)
	return domainViewResult{}
}

// TestFailedDNSDoesNotBecomeInSync covers the report "first it said error, then
// it says in sync, but no record was created": a failed sync used to store the
// target address and time anyway, so once the error was cleared (re-selecting the
// provider does that) the loop skipped the domain and the UI claimed it was fine.
func TestFailedDNSDoesNotBecomeInSync(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]string{}, comments: map[string]string{}, fail: true}
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	h := newHarnessWithDNS(t, server.URL)
	admin := h.login(t)
	providerID := h.addDNSProvider(t, "cloudflare", admin)
	if status, body, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "app.example.com"}, admin); status != http.StatusOK {
		t.Fatalf("adding a domain returned %d: %s", status, body)
	}
	// Attaching the provider syncs, and the provider is broken.
	if status, body, _ := h.api("PATCH", "/api/domains/app.example.com", map[string]any{"providerId": providerID}, admin); status != http.StatusOK {
		t.Fatalf("attaching a provider returned %d: %s", status, body)
	}
	domain := h.domainView(t, "app.example.com", admin)
	if domain.LastError == "" {
		t.Fatalf("the failure should be reported: %+v", domain)
	}
	if domain.Synced {
		t.Fatalf("a domain whose record could not be written is not in sync: %+v", domain)
	}

	// Re-attaching clears the error. The domain must not become "in sync" by
	// itself: it has to try again, and the provider still refuses.
	if status, _, _ := h.api("PATCH", "/api/domains/app.example.com", map[string]any{"providerId": providerID}, admin); status != http.StatusOK {
		t.Fatal("re-attaching the provider failed")
	}
	domain = h.domainView(t, "app.example.com", admin)
	if domain.Synced {
		t.Fatalf("clearing the error must not make a missing record look synced: %+v", domain)
	}
	if domain.LastError == "" {
		t.Fatalf("the retry should report the failure again: %+v", domain)
	}

	// The provider works again: the record is created, and only now is it synced.
	fake.mu.Lock()
	fake.fail = false
	fake.mu.Unlock()
	if status, _, _ := h.api("POST", "/api/dns/providers/"+providerID+"/sync", map[string]any{}, admin); status != http.StatusOK {
		t.Fatal("forcing a sync failed")
	}
	if got := fake.address("app.example.com"); got == "" {
		t.Fatal("the record was not created once the provider worked")
	}
	domain = h.domainView(t, "app.example.com", admin)
	if !domain.Synced || domain.LastError != "" {
		t.Fatalf("the domain should be in sync now: %+v", domain)
	}
}

// TestDNSErrorsAreListedForTheLogsTab checks the new Errors view has something to
// show when automation fails, with the reason and what to check.
func TestDNSErrorsAreListedForTheLogsTab(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]string{}, comments: map[string]string{}, fail: true}
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	h := newHarnessWithDNS(t, server.URL)
	admin := h.login(t)
	providerID := h.addDNSProvider(t, "cloudflare", admin)
	if status, _, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "app.example.com"}, admin); status != http.StatusOK {
		t.Fatal("adding a domain failed")
	}
	if status, _, _ := h.api("PATCH", "/api/domains/app.example.com", map[string]any{"providerId": providerID}, admin); status != http.StatusOK {
		t.Fatal("attaching a provider failed")
	}

	status, body, _ := h.api("GET", "/api/state", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("/api/state returned %d", status)
	}
	if strings.Contains(string(body), `"errors":null`) {
		t.Fatalf("the error list must be an array: %s", body)
	}
	var view struct {
		Errors []struct {
			Source  string `json:"source"`
			Message string `json:"message"`
			Detail  string `json:"detail"`
			Hint    string `json:"hint"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Errors) == 0 {
		t.Fatalf("the failed DNS update should be listed: %s", body)
	}
	first := view.Errors[0]
	if first.Source != "dns" || !strings.Contains(first.Message, "app.example.com") {
		t.Fatalf("unexpected error entry: %+v", first)
	}
	if !strings.Contains(first.Detail, "token is broken") {
		t.Fatalf("the provider's answer should be in the detail: %+v", first)
	}
	if first.Hint == "" {
		t.Fatalf("the entry should say what to check: %+v", first)
	}

	// Clearing works, so the operator can start from a clean list.
	if status, _, _ := h.api("DELETE", "/api/errors", nil, admin); status != http.StatusOK {
		t.Fatal("clearing the error log failed")
	}
	status, body, _ = h.api("GET", "/api/errors", nil, admin)
	if status != http.StatusOK || strings.Contains(string(body), "token is broken") {
		t.Fatalf("the error log was not cleared: %s", body)
	}
}
