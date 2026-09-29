package control_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/control"
)

// TestIPAPIFailuresReachTheErrorsView covers an API that stops answering, or sends
// something unexpected: that is a failure like any other, so it has to appear
// where every failure does - once per distinct message, because lookups happen on
// the request path.
func TestIPAPIFailuresReachTheErrorsView(t *testing.T) {
	h := newHarness(t, true)
	failure := errors.New(`geoip: https://iplog.example.com: Get "https://iplog.example.com/checkip?ip=1.1.1.1": context deadline exceeded`)
	h.server.ReportGeoIPErrorForTest(failure)
	h.server.ReportGeoIPErrorForTest(failure)

	entries := geoIPEntries(h.server.ErrorsForTest())
	if len(entries) != 1 {
		t.Fatalf("the failure should be reported once, got %d: %+v", len(entries), entries)
	}
	if entries[0].Source != "geoip" || !strings.Contains(entries[0].Detail, "context deadline exceeded") {
		t.Fatalf("the entry should carry the API's own error: %+v", entries[0])
	}
	if !strings.Contains(entries[0].Hint, "Settings") {
		t.Fatalf("the entry should say where to fix it: %+v", entries[0])
	}

	// A different failure is a new entry; the same one again is not.
	h.server.ReportGeoIPErrorForTest(errors.New("geoip: the API sent something that is not the documented JSON"))
	if got := len(geoIPEntries(h.server.ErrorsForTest())); got != 2 {
		t.Fatalf("a different failure should be reported, got %d entries", got)
	}
}

// geoIPEntries keeps the entries this test is about: the harness records its own
// simulated-backend note as well.
func geoIPEntries(entries []control.ErrorEntry) []control.ErrorEntry {
	var out []control.ErrorEntry
	for _, entry := range entries {
		if entry.Source == "geoip" {
			out = append(out, entry)
		}
	}
	return out
}

// TestIPAPISettingsAreStoredAndUsed covers the settings panel end to end: the host
// and token are saved, the lookup uses them straight away, and the country a rule
// matches on comes from the API.
func TestIPAPISettingsAreStoredAndUsed(t *testing.T) {
	fake := newFakeIPAPI(t, "EE")
	h := newHarnessOpts(t, true, "", func(opts *control.Options) {
		opts.IPAPIHost = ""
		opts.IPAPIToken = ""
	})
	admin := h.login(t)

	// Nothing configured yet: the panel reports no country lookup service.
	status, body, _ := h.api("GET", "/api/geoip", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("GET /api/geoip returned %d", status)
	}
	if strings.Contains(string(body), "token\":\"") {
		t.Fatalf("the API leaked the token: %s", body)
	}

	// Saving with a check looks one address up with the settings just entered.
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{
		"host": fake.server.URL, "token": fake.token, "check": true,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("saving the settings returned %d: %s", status, body)
	}
	var result struct {
		GeoIP struct {
			Configured bool   `json:"configured"`
			HasToken   bool   `json:"hasToken"`
			Ready      bool   `json:"ready"`
			Lookups    int    `json:"lookups"`
			Host       string `json:"host"`
		} `json:"geoip"`
		Check struct {
			Country     string `json:"country"`
			CountryFrom string `json:"countryFrom"`
		} `json:"check"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Error != "" {
		t.Fatalf("the check should have succeeded, got: %s", result.Error)
	}
	if !result.GeoIP.Configured || !result.GeoIP.HasToken {
		t.Fatalf("the settings were not stored: %+v", result.GeoIP)
	}
	if !result.GeoIP.Ready || result.GeoIP.Lookups == 0 {
		t.Fatalf("the API was not used: %+v", result.GeoIP)
	}
	if result.Check.Country != "EE" {
		t.Fatalf("the check answered %+v", result.Check)
	}

	// A country lookup works straight away, which is what rules rely on.
	if got := h.server.GeoIPLookupForTest("203.0.113.9"); got != "EE" {
		t.Fatalf("country lookup = %q, want EE", got)
	}

	// A token that the API rejects is reported rather than swallowed.
	fake.token = "something-else"
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{
		"host": fake.server.URL, "token": "wrong", "check": true,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("a failed check should still answer, got %d", status)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Error, "401") {
		t.Fatalf("the API's own error should be reported: %q", result.Error)
	}

	// Clearing removes the settings again.
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{"clear": true}, admin)
	if status != http.StatusOK {
		t.Fatalf("clearing returned %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.GeoIP.Configured {
		t.Fatalf("the settings should be gone: %+v", result.GeoIP)
	}
	if got := h.server.GeoIPLookupForTest("203.0.113.9"); got != "" {
		t.Fatalf("no API means no country, got %q", got)
	}
}

func TestPublicIPAPISelectionMakesIpLogFallbackOptional(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	status, body, _ := h.api("POST", "/api/geoip", map[string]any{
		"host": "http://127.0.0.1:4702", "token": "iplog-key",
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("saving iplog: %d %s", status, body)
	}
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{"provider": "ipapi"}, admin)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "API key") {
		t.Fatalf("keyless public provider: %d %s", status, body)
	}
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{
		"provider": "ipapi", "publicToken": "test-key",
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("saving public provider: %d %s", status, body)
	}
	cfg := h.server.Store().GeoIP()
	if cfg.Provider != "ipapi" || cfg.Host != "http://127.0.0.1:4702" || cfg.Token != "iplog-key" || cfg.PublicToken != "test-key" || cfg.FallbackEnabled {
		t.Fatalf("public settings = %+v", cfg)
	}
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{"provider": "ipapi", "fallbackEnabled": true}, admin)
	if status != http.StatusOK || !h.server.Store().GeoIP().FallbackEnabled {
		t.Fatalf("enabling configured iplog fallback: %d %s", status, body)
	}
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{"provider": "ipapi", "fallbackEnabled": false}, admin)
	if status != http.StatusOK || h.server.Store().GeoIP().PublicToken != "test-key" || h.server.Store().GeoIP().FallbackEnabled {
		t.Fatalf("saving public provider again: %d %s", status, body)
	}
}

func TestPublicIPAPIFallbackNeedsConfiguredIpLog(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	status, body, _ := h.api("POST", "/api/geoip", map[string]any{
		"provider": "ipapi", "publicToken": "test-key", "fallbackEnabled": true,
	}, admin)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "configure iplog") {
		t.Fatalf("fallback without iplog: %d %s", status, body)
	}
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{
		"provider": "ipapi", "publicToken": "test-key", "fallbackEnabled": false,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("public API without fallback: %d %s", status, body)
	}
}

// TestTheIPAPIFlagsWorkWithoutThePanel keeps a control node started with
// --ipapi-host working before anyone opens the settings tab.
func TestTheIPAPIFlagsWorkWithoutThePanel(t *testing.T) {
	fake := newFakeIPAPI(t, "SE")
	h := newHarnessOpts(t, true, "", func(opts *control.Options) {
		opts.IPAPIHost = fake.server.URL
		opts.IPAPIToken = fake.token
	})
	admin := h.login(t)
	status, body, _ := h.api("GET", "/api/geoip", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("GET /api/geoip returned %d", status)
	}
	if !strings.Contains(string(body), `"configured":true`) {
		t.Fatalf("the flags should configure the API: %s", body)
	}
	if got := h.server.GeoIPLookupForTest("203.0.113.9"); got != "SE" {
		t.Fatalf("country lookup = %q, want SE", got)
	}
}

func TestIPAPIForwardFollowsTheSelectedAgent(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	first := h.enrolledAgent(t, "first")
	second := h.enrolledAgent(t, "second")
	status, body, _ := h.api("POST", "/api/geoip", map[string]any{
		"host": "http://172.18.0.1:4702", "agentId": second.id,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("saving IP API agent returned %d: %s", status, body)
	}
	if len(h.server.Forwards(first.id)) != 0 {
		t.Fatal("the other agent received the IP API forward")
	}
	forwards := h.server.Forwards(second.id)
	if len(forwards) != 1 || forwards[0].Target != "172.18.0.1:4702" || forwards[0].Protocol != "tcp" {
		t.Fatalf("selected agent forwards = %+v", forwards)
	}
	if got := h.server.Store().GeoIP().AgentID; got != second.id {
		t.Fatalf("stored agent ID = %d, want %d", got, second.id)
	}
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{
		"provider": "ipapi", "publicToken": "test-key", "agentId": second.id,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("saving public API returned %d: %s", status, body)
	}
	if forwards := h.server.Forwards(second.id); len(forwards) != 0 {
		t.Fatalf("iplog was forwarded with fallback disabled: %+v", forwards)
	}
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{
		"provider": "ipapi", "fallbackEnabled": true, "agentId": second.id,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("enabling public API fallback returned %d: %s", status, body)
	}
	forwards = h.server.Forwards(second.id)
	if len(forwards) != 1 || forwards[0].Target != "172.18.0.1:4702" {
		t.Fatalf("iplog fallback forward = %+v", forwards)
	}
	status, _, _ = h.api("POST", "/api/geoip", map[string]any{
		"host": "http://172.18.0.1:4702", "agentId": 999999,
	}, admin)
	if status != http.StatusBadRequest {
		t.Fatalf("unknown agent returned %d, want 400", status)
	}
}
