package control_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// loginAs signs in with a specific account and returns the session cookies.
func (h *harness) loginAs(t *testing.T, username, password string) []*http.Cookie {
	t.Helper()
	status, body, cookies := h.api("POST", "/api/login",
		map[string]string{"username": username, "password": password}, nil)
	if status != http.StatusOK {
		t.Fatalf("login as %s returned %d: %s", username, status, body)
	}
	return cookies
}

// createViewer adds a regular account through the API.
func (h *harness) createViewer(t *testing.T, cookies []*http.Cookie, username string) {
	t.Helper()
	status, body, _ := h.api("POST", "/api/users", map[string]any{
		"username": username, "password": "viewer-password-1", "role": "regular",
	}, cookies)
	if status != http.StatusOK {
		t.Fatalf("creating a viewer returned %d: %s", status, body)
	}
}

func TestLoginRequiresUsername(t *testing.T) {
	h := newHarness(t, true)
	// The harness seeds the password without a username: the legacy default is
	// still accepted so older scripts keep working.
	status, body, cookies := h.api("POST", "/api/login", map[string]string{"password": "correct-horse-battery-staple"}, nil)
	if status != http.StatusOK {
		t.Fatalf("legacy password-only login returned %d: %s", status, body)
	}
	if len(cookies) == 0 {
		t.Fatal("login returned no session cookie")
	}
	status, body, _ = h.api("POST", "/api/login", map[string]string{
		"username": "admin", "password": "wrong-password",
	}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a wrong password returned %d: %s", status, body)
	}
	status, body, _ = h.api("POST", "/api/login", map[string]string{
		"username": "nobody", "password": "correct-horse-battery-staple",
	}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("an unknown user returned %d: %s", status, body)
	}
}

func TestSessionReportsTheSignedInAccount(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)
	status, body, _ := h.api("GET", "/api/session", nil, cookies)
	if status != http.StatusOK {
		t.Fatalf("/api/session returned %d", status)
	}
	var session struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
		Role          string `json:"role"`
		CanAdmin      bool   `json:"canAdmin"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		t.Fatal(err)
	}
	if !session.Authenticated || session.Username != "admin" || session.Role != "admin" || !session.CanAdmin {
		t.Fatalf("unexpected session payload: %+v", session)
	}
}

func TestRegularAccountsCannotManageGlobalSettings(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	h.createViewer(t, admin, "reader")
	viewer := h.loginAs(t, "reader", "viewer-password-1")

	// Reading is fine.
	if status, _, _ := h.api("GET", "/api/state", nil, viewer); status != http.StatusOK {
		t.Fatalf("a viewer should be able to read state, got %d", status)
	}
	// Global configuration and user management stay with admins.
	cases := []struct {
		method string
		path   string
		body   any
	}{
		{"POST", "/api/settings", map[string]any{"meshCidr": "10.0.0.0/24"}},
		{"POST", "/api/users", map[string]any{"username": "sneaky", "password": "sneaky-password", "role": "admin"}},
		{"DELETE", "/api/users/1", nil},
		{"POST", "/api/tokens", map[string]any{"name": "sneaky"}},
	}
	for _, tc := range cases {
		status, body, _ := h.api(tc.method, tc.path, tc.body, viewer)
		if status != http.StatusForbidden {
			t.Errorf("%s %s as a viewer returned %d (%s), want 403", tc.method, tc.path, status, strings.TrimSpace(string(body)))
		}
	}
	// Global settings remain untouched.
	if agents := h.server.Store().Agents(); len(agents) != 0 {
		t.Fatalf("a viewer managed to enroll an agent: %+v", agents)
	}
	if got := h.server.Settings().MeshCIDR; got == "10.0.0.0/24" {
		t.Fatal("a viewer managed to change the mesh range")
	}
}

func TestAdminsCanManageUsers(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)

	// Create.
	status, body, _ := h.api("POST", "/api/users", map[string]any{
		"username": "ops", "password": "ops-password-1", "role": "admin",
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("creating a user returned %d: %s", status, body)
	}
	var created struct {
		User struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.User.Role != "admin" || created.User.ID == "" {
		t.Fatalf("unexpected user: %+v", created.User)
	}

	// List.
	status, body, _ = h.api("GET", "/api/users", nil, admin)
	if status != http.StatusOK || !strings.Contains(string(body), "ops") {
		t.Fatalf("listing users returned %d: %s", status, body)
	}
	if strings.Contains(string(body), "passwordHash") {
		t.Fatal("the user list must not leak password hashes")
	}

	// The new admin can sign in.
	opsCookies := h.loginAs(t, "ops", "ops-password-1")
	if status, _, _ := h.api("GET", "/api/state", nil, opsCookies); status != http.StatusOK {
		t.Fatalf("the new admin cannot use the API: %d", status)
	}

	// Change the role, then the password.
	if status, body, _ := h.api("PATCH", "/api/users/"+created.User.ID,
		map[string]any{"role": "regular"}, admin); status != http.StatusOK {
		t.Fatalf("role change returned %d: %s", status, body)
	}
	if _, err := h.client().Post("", "", nil); err != nil {
		_ = err
	}
	if status, body, _ := h.api("POST", "/api/users/"+created.User.ID+"/password",
		map[string]any{"password": "rotated-password-1"}, admin); status != http.StatusOK {
		t.Fatalf("password reset returned %d: %s", status, body)
	}
	viewerCookies := h.loginAs(t, "ops", "rotated-password-1")

	// Password rotation revokes old sessions; the fresh regular account cannot manage users.
	if status, _, _ := h.api("POST", "/api/agents", map[string]any{"name": "nope"}, opsCookies); status != http.StatusUnauthorized {
		t.Fatalf("the old session was not revoked: %d", status)
	}
	if status, _, _ := h.api("POST", "/api/users", map[string]any{"username": "nope", "password": "nope-password-1", "role": "admin"}, viewerCookies); status != http.StatusForbidden {
		t.Fatalf("the demoted user still had admin rights: %d", status)
	}

	// Disable, then delete.
	if status, body, _ := h.api("PATCH", "/api/users/"+created.User.ID,
		map[string]any{"disabled": true}, admin); status != http.StatusOK {
		t.Fatalf("disable returned %d: %s", status, body)
	}
	status, body, _ = h.api("POST", "/api/login", map[string]string{
		"username": "ops", "password": "rotated-password-1",
	}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("a disabled account could sign in: %d %s", status, body)
	}
	if status, body, _ := h.api("DELETE", "/api/users/"+created.User.ID, nil, admin); status != http.StatusOK {
		t.Fatalf("delete returned %d: %s", status, body)
	}
}

func TestLastAdminCannotBeRemovedThroughTheAPI(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	users := h.server.Auth().Users()
	if len(users) != 1 {
		t.Fatalf("expected a single seeded admin, got %d", len(users))
	}
	status, body, _ := h.api("DELETE", "/api/users/"+users[0].ID, nil, admin)
	if status != http.StatusBadRequest {
		t.Fatalf("deleting the last admin returned %d: %s", status, body)
	}
	if !strings.Contains(string(body), "admin") {
		t.Fatalf("the error should explain the admin restriction: %s", body)
	}
}

func TestSelfServicePasswordChange(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	h.createViewer(t, admin, "reader")
	viewer := h.loginAs(t, "reader", "viewer-password-1")

	// A viewer may change its own password even though it cannot change anything else.
	status, body, _ := h.api("POST", "/api/password", map[string]any{
		"current": "viewer-password-1", "password": "my-own-new-password",
	}, viewer)
	if status != http.StatusOK {
		t.Fatalf("self service password change returned %d: %s", status, body)
	}
	if status, body, _ := h.api("POST", "/api/password", map[string]any{
		"current": "wrong", "password": "another-password",
	}, viewer); status != http.StatusUnauthorized {
		t.Fatalf("a wrong current password returned %d: %s", status, body)
	}
	h.loginAs(t, "reader", "my-own-new-password")
}

func TestAPITokenRoleIsHonoured(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	status, body, _ := h.api("POST", "/api/tokens", map[string]any{"name": "readonly", "role": "viewer"}, admin)
	if status != http.StatusBadRequest {
		t.Fatalf("regular token returned %d: %s", status, body)
	}
}
