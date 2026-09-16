package control_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCloudflare is a small stand-in for the Cloudflare API.
type fakeCloudflare struct {
	mu       sync.Mutex
	records  map[string]string // name -> content
	comments map[string]string
	created  int
	updated  int
	fail     bool
}

func (f *fakeCloudflare) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if f.fail {
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"token is broken"}]}`))
			return
		}
		switch {
		case r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-1","name":"example.com"}]}`))
		case strings.HasSuffix(r.URL.Path, "/dns_records") && r.Method == http.MethodGet:
			name := r.URL.Query().Get("name")
			content, ok := f.records[name]
			result := "[]"
			if ok {
				result = fmt.Sprintf(`[{"id":"rec-1","content":%q}]`, content)
			}
			_, _ = fmt.Fprintf(w, `{"success":true,"result":%s}`, result)
		case strings.HasSuffix(r.URL.Path, "/dns_records") && r.Method == http.MethodPost:
			var body struct {
				Name    string `json:"name"`
				Content string `json:"content"`
				Comment string `json:"comment"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.records[body.Name] = body.Content
			f.comments[body.Name] = body.Comment
			f.created++
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-new","content":"ok"}}`))
		case strings.Contains(r.URL.Path, "/dns_records/") && r.Method == http.MethodPut:
			var body struct {
				Name    string `json:"name"`
				Content string `json:"content"`
				Comment string `json:"comment"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.records[body.Name] = body.Content
			f.comments[body.Name] = body.Comment
			f.updated++
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-1","content":"ok"}}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *fakeCloudflare) address(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[name]
}

func TestDNSAutomationUpdatesTheRecord(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]string{}, comments: map[string]string{}}
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	h := newHarnessWithDNS(t, server.URL)
	admin := h.login(t)

	// Configure a provider.
	status, body, _ := h.api("POST", "/api/dns/providers", map[string]any{
		"name": "cloudflare", "kind": "cloudflare", "token": "test-token",
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("adding a provider returned %d: %s", status, body)
	}
	var created struct {
		Provider struct {
			ID       string `json:"id"`
			HasToken bool   `json:"hasToken"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if !created.Provider.HasToken {
		t.Fatal("the token should be recorded")
	}

	// Add a domain and attach the provider.
	if status, body, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "app.example.com"}, admin); status != http.StatusOK {
		t.Fatalf("adding a domain returned %d: %s", status, body)
	}
	status, body, _ = h.api("PATCH", "/api/domains/app.example.com",
		map[string]any{"providerId": created.Provider.ID}, admin)
	if status != http.StatusOK {
		t.Fatalf("attaching a provider returned %d: %s", status, body)
	}

	// The record is created automatically.
	deadline := 20
	for i := 0; i < deadline; i++ {
		if fake.address("app.example.com") != "" {
			break
		}
		sleepBriefly()
	}
	if fake.address("app.example.com") == "" {
		t.Fatal("no A record was created")
	}
	// The record is labelled so it is recognisable in the provider's dashboard.
	if comment := fake.comments["app.example.com"]; !strings.Contains(comment, "noobtunnel") {
		t.Fatalf("the record should carry a noobtunnel comment, got %q", comment)
	}
	createdRecord := fake.address("app.example.com")

	// Publishing the domain on an extra exit node must move the record.
	agent := h.enrolledAgent(t, "homelab")
	node := h.addExitNode(t, "second ip", "203.0.113.55")
	status, body, _ = h.api("POST", "/api/resources", resourceBody(
		"site", "http", agent.id, h.agentAddress(t, agent.id), 8080, freePort(t),
		map[string]any{"domain": "app.example.com", "exitNodeId": node}), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}

	deadline = 20
	for i := 0; i < deadline; i++ {
		if fake.address("app.example.com") == "203.0.113.55" {
			break
		}
		sleepBriefly()
	}
	if got := fake.address("app.example.com"); got != "203.0.113.55" {
		t.Fatalf("the record should follow the exit node, got %q (was %q)", got, createdRecord)
	}

	// The domain view reports the automation state.
	status, body, _ = h.api("GET", "/api/state", nil, admin)
	var view struct {
		Domains []struct {
			Hostname     string `json:"hostname"`
			ProviderName string `json:"providerName"`
			Address      string `json:"address"`
			Synced       bool   `json:"synced"`
			ExitNodeName string `json:"exitNodeName"`
		} `json:"domains"`
		DNSProviders []struct {
			Name string `json:"name"`
		} `json:"dnsProviders"`
	}
	if status != http.StatusOK {
		t.Fatalf("/api/state returned %d", status)
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.DNSProviders) != 1 || view.DNSProviders[0].Name != "cloudflare" {
		t.Fatalf("providers in state: %+v", view.DNSProviders)
	}
	if len(view.Domains) != 1 {
		t.Fatalf("domains in state: %+v", view.Domains)
	}
	domain := view.Domains[0]
	if domain.ProviderName != "cloudflare" || domain.Address != "203.0.113.55" || !domain.Synced {
		t.Fatalf("domain automation state: %+v", domain)
	}
	if domain.ExitNodeName != "second ip" {
		t.Fatalf("the domain should name the exit node it points at: %+v", domain)
	}

	// The token itself must never be exposed.
	if strings.Contains(string(body), "test-token") {
		t.Fatal("the API leaked the provider token")
	}
}

func TestDNSAutomationReportsFailures(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]string{}, comments: map[string]string{}, fail: true}
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	h := newHarnessWithDNS(t, server.URL)
	admin := h.login(t)
	status, body, _ := h.api("POST", "/api/dns/providers", map[string]any{
		"name": "broken", "kind": "cloudflare", "token": "bad-token",
	}, admin)
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
	if status, _, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "broken.example.com"}, admin); status != http.StatusOK {
		t.Fatal("could not add the domain")
	}
	if status, body, _ := h.api("PATCH", "/api/domains/broken.example.com",
		map[string]any{"providerId": created.Provider.ID}, admin); status != http.StatusOK {
		t.Fatalf("attaching returned %d: %s", status, body)
	}

	// The failure is reported on the domain instead of being swallowed.
	deadline := 20
	var lastError string
	for i := 0; i < deadline; i++ {
		status, body, _ = h.api("GET", "/api/state", nil, admin)
		var view struct {
			Domains []struct {
				LastError string `json:"lastError"`
			} `json:"domains"`
		}
		if json.Unmarshal(body, &view) == nil && len(view.Domains) == 1 {
			lastError = view.Domains[0].LastError
			if lastError != "" {
				break
			}
		}
		sleepBriefly()
	}
	if !strings.Contains(lastError, "token is broken") {
		t.Fatalf("the provider error should surface on the domain, got %q", lastError)
	}
}

func TestDNSProviderValidation(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	if status, body, _ := h.api("POST", "/api/dns/providers", map[string]any{"name": "x", "kind": "cloudflare"}, admin); status != http.StatusBadRequest {
		t.Fatalf("a provider without a token returned %d: %s", status, body)
	}
	if status, body, _ := h.api("POST", "/api/dns/providers", map[string]any{"name": "", "kind": "cloudflare", "token": "t"}, admin); status != http.StatusBadRequest {
		t.Fatalf("a provider without a name returned %d: %s", status, body)
	}
	h.createViewer(t, admin, "reader")
	viewer := h.loginAs(t, "reader", "viewer-password-1")
	if status, _, _ := h.api("GET", "/api/dns/providers", nil, viewer); status != http.StatusOK {
		t.Fatalf("a viewer should be able to read providers: %d", status)
	}
	if status, _, _ := h.api("POST", "/api/dns/providers", map[string]any{
		"name": "sneaky", "kind": "cloudflare", "token": "t",
	}, viewer); status != http.StatusForbidden {
		t.Fatalf("a viewer created a provider: %d", status)
	}
}

// TestDNSProviderCannotBeDeletedWhileInUse guards the domain's configuration.
func TestDNSProviderCannotBeDeletedWhileInUse(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	status, body, _ := h.api("POST", "/api/dns/providers", map[string]any{
		"name": "cloudflare", "kind": "cloudflare", "token": "t",
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("adding returned %d: %s", status, body)
	}
	var created struct {
		Provider struct {
			ID string `json:"id"`
		} `json:"provider"`
	}
	_ = json.Unmarshal(body, &created)
	if status, _, _ := h.api("POST", "/api/domains", map[string]any{"hostname": "keep.example.com"}, admin); status != http.StatusOK {
		t.Fatal("could not add the domain")
	}
	if status, _, _ := h.api("PATCH", "/api/domains/keep.example.com", map[string]any{"providerId": created.Provider.ID}, admin); status != http.StatusOK {
		t.Fatal("could not attach the provider")
	}
	if status, body, _ := h.api("DELETE", "/api/dns/providers/"+created.Provider.ID, nil, admin); status != http.StatusBadRequest {
		t.Fatalf("deleting a provider in use returned %d: %s", status, body)
	}
}
