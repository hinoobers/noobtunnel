package control_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/control"
)

// TestGeoIPCredentialsAreStored catches the reported bug: the key was entered in
// the UI but the download still complained that no licence key was set.
func TestGeoIPCredentialsAreStored(t *testing.T) {
	// Point the download at a local server so nothing touches the internet.
	fake := newFakeMaxMind(t)
	h := newHarnessOpts(t, true, "", func(opts *control.Options) {
		opts.GeoIPLicenceKey = ""
		opts.GeoIPDir = t.TempDir()
		fake.attach(opts)
	})
	admin := h.login(t)

	// The stored credentials start empty.
	status, body, _ := h.api("GET", "/api/geoip", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("GET /api/geoip returned %d", status)
	}
	if strings.Contains(string(body), "licenseKey\":\"") {
		t.Fatalf("the API leaked the licence key: %s", body)
	}

	// Saving with fetch must use the key that was just entered.
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{
		"licenseKey": "test-licence-key", "accountId": "12345", "fetch": true,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("saving credentials returned %d: %s", status, body)
	}
	if strings.Contains(string(body), "licence key is required") {
		t.Fatalf("the saved key was not used: %s", body)
	}
	var result struct {
		GeoIP struct {
			Configured bool `json:"configured"`
			HasKey     bool `json:"hasKey"`
			Ready      bool `json:"ready"`
			Networks   int  `json:"networks"`
		} `json:"geoip"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if !result.GeoIP.Configured || !result.GeoIP.HasKey {
		t.Fatalf("the credentials were not stored: %+v", result.GeoIP)
	}
	if result.Error != "" {
		t.Fatalf("the local download should have succeeded, got: %s", result.Error)
	}
	if !result.GeoIP.Ready || result.GeoIP.Networks == 0 {
		t.Fatalf("the database was not loaded: %+v", result.GeoIP)
	}

	// A country lookup works straight away, which is what rules rely on.
	checked := h.server.GeoIPLookupForTest("203.0.113.9")
	if checked != "EE" {
		t.Fatalf("country lookup = %q, want EE", checked)
	}

	// Clearing removes them again.
	status, body, _ = h.api("POST", "/api/geoip", map[string]any{"clear": true}, admin)
	if status != http.StatusOK {
		t.Fatalf("clearing returned %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.GeoIP.Configured {
		t.Fatalf("credentials should be gone: %+v", result.GeoIP)
	}
	// The cache stays on disk, so a cleared key does not lose the data.
	if !result.GeoIP.Ready {
		t.Fatalf("the cached database should still be loaded: %+v", result.GeoIP)
	}
}
