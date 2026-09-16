package control_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// raw sends a body verbatim, which is how the stylesheet editor uploads CSS.
func (h *harness) raw(method, path, contentType string, body []byte, cookies []*http.Cookie) (int, []byte) {
	h.t.Helper()
	request, err := http.NewRequest(method, "https://"+h.address+path, strings.NewReader(string(body)))
	if err != nil {
		h.t.Fatal(err)
	}
	request.Header.Set("X-Noobtunnel", "1")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := h.client().Do(request)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, raw
}

// TestBrandingRenamesTheServiceAndKeepsCustomCSS covers the branding tab end to
// end: the name reaches the UI and the published-service messages, the custom
// stylesheet starts from the default theme, and both survive a restart.
func TestBrandingRenamesTheServiceAndKeepsCustomCSS(t *testing.T) {
	dir := t.TempDir()
	first := newHarnessOnDir(t, true, "", dir, nil)
	admin := first.login(t)

	// The editor is pre-filled with the stylesheet the control node serves, and a
	// fresh node reports that it is not customised.
	status, body, _ := first.api("GET", "/api/css", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("GET /api/css returned %d: %s", status, body)
	}
	var editor struct {
		CSS    string `json:"css"`
		Custom bool   `json:"custom"`
	}
	if err := json.Unmarshal(body, &editor); err != nil {
		t.Fatalf("the stylesheet is not JSON: %v", err)
	}
	if editor.Custom {
		t.Fatal("a fresh control node reported a custom stylesheet")
	}
	if !strings.Contains(editor.CSS, ":root") {
		t.Fatalf("the editor was not pre-filled with the default theme: %.60s", editor.CSS)
	}

	// With nothing stored the public stylesheet is empty and the browser keeps the
	// bundled one.
	if status, _, _ := first.api("GET", "/custom.css", nil, nil); status != http.StatusNoContent {
		t.Fatalf("/custom.css returned %d with no custom sheet, want 204", status)
	}

	// Rename the service. The settings endpoint replaces what it is given, so the
	// test posts the current settings back with one field changed.
	status, body, _ = first.api("GET", "/api/state", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("GET /api/state returned %d", status)
	}
	var view struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	view.Settings["brandName"] = "acme tunnel"
	if status, body, _ = first.api("POST", "/api/settings", view.Settings, admin); status != http.StatusOK {
		t.Fatalf("renaming the service returned %d: %s", status, body)
	}

	// The name reaches the signed out page too, so the login screen is branded.
	status, body, _ = first.api("GET", "/api/session", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/session returned %d", status)
	}
	var session struct {
		BrandName string `json:"brandName"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		t.Fatal(err)
	}
	if session.BrandName != "acme tunnel" {
		t.Fatalf("/api/session reported the brand as %q", session.BrandName)
	}

	// Upload a stylesheet and check it is served, and reported, straight away.
	custom := []byte(":root { --accent: #ff0000; }\n")
	if status, body = first.raw("POST", "/api/css", "text/css", custom, admin); status != http.StatusOK {
		t.Fatalf("uploading a stylesheet returned %d: %s", status, body)
	}
	status, body, _ = first.api("GET", "/custom.css", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("/custom.css returned %d after an upload", status)
	}
	if !strings.Contains(string(body), "#ff0000") {
		t.Fatalf("/custom.css served %q", body)
	}
	status, body, _ = first.api("GET", "/api/state", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("GET /api/state returned %d", status)
	}
	var after struct {
		Server struct {
			BrandName string `json:"brandName"`
			CustomCSS bool   `json:"customCss"`
		} `json:"server"`
	}
	if err := json.Unmarshal(body, &after); err != nil {
		t.Fatal(err)
	}
	if !after.Server.CustomCSS {
		t.Fatal("the state did not report the custom stylesheet")
	}
	if after.Server.BrandName != "acme tunnel" {
		t.Fatalf("the state reported the brand as %q", after.Server.BrandName)
	}
	first.stop()

	// A restart keeps both: the brand lives in the state file and the stylesheet
	// next to it.
	second := newHarnessOnDir(t, true, "", dir, nil)
	defer second.stop()
	admin2 := second.login(t)
	status, body, _ = second.api("GET", "/custom.css", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "#ff0000") {
		t.Fatalf("the stylesheet did not survive a restart (%d): %s", status, body)
	}
	status, body, _ = second.api("GET", "/api/state", nil, admin2)
	if status != http.StatusOK {
		t.Fatalf("GET /api/state returned %d", status)
	}
	var restarted struct {
		Server struct {
			BrandName string `json:"brandName"`
		} `json:"server"`
		Settings struct {
			BrandName string `json:"brandName"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(body, &restarted); err != nil {
		t.Fatal(err)
	}
	if restarted.Server.BrandName != "acme tunnel" || restarted.Settings.BrandName != "acme tunnel" {
		t.Fatalf("the brand name did not survive a restart: %+v", restarted)
	}

	// Resetting puts the default theme back and empties the public stylesheet.
	if status, body, _ = second.api("DELETE", "/api/css", nil, admin2); status != http.StatusOK {
		t.Fatalf("resetting the stylesheet returned %d: %s", status, body)
	}
	if status, _, _ := second.api("GET", "/custom.css", nil, nil); status != http.StatusNoContent {
		t.Fatalf("/custom.css returned %d after a reset, want 204", status)
	}
	status, body, _ = second.api("GET", "/api/css", nil, admin2)
	if status != http.StatusOK {
		t.Fatalf("GET /api/css returned %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &editor); err != nil {
		t.Fatal(err)
	}
	if editor.Custom || !strings.Contains(editor.CSS, ":root") {
		t.Fatalf("resetting should restore the default theme, got custom=%v", editor.Custom)
	}
}

// TestBrandNameIsValidated keeps a pasted name from breaking the header or an
// HTTP header value on a published service.
func TestBrandNameIsValidated(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)

	status, body, _ := h.api("GET", "/api/state", nil, admin)
	if status != http.StatusOK {
		t.Fatalf("GET /api/state returned %d", status)
	}
	var view struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	// A name with control characters and an over-long tail is trimmed rather than
	// rejected, and an empty name falls back to the bundled one.
	view.Settings["brandName"] = "  " + strings.Repeat("x", 60) + "\n"
	if status, body, _ = h.api("POST", "/api/settings", view.Settings, admin); status != http.StatusOK {
		t.Fatalf("saving an over-long name returned %d: %s", status, body)
	}
	var saved struct {
		Settings struct {
			BrandName string `json:"brandName"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	if len([]rune(saved.Settings.BrandName)) != 40 || strings.ContainsAny(saved.Settings.BrandName, "\n") {
		t.Fatalf("the brand name was not normalised: %q", saved.Settings.BrandName)
	}
	// An empty name is not an error: the control node falls back to the bundled
	// name rather than rendering an empty header.
	view.Settings["brandName"] = "   "
	if status, body, _ = h.api("POST", "/api/settings", view.Settings, admin); status != http.StatusOK {
		t.Fatalf("saving an empty name returned %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Settings.BrandName != "noobtunnel" {
		t.Fatalf("an empty name should fall back to noobtunnel, got %q", saved.Settings.BrandName)
	}
}
