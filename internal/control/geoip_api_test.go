package control_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/control"
)

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

	// Nothing configured yet: country rules are inert.
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
