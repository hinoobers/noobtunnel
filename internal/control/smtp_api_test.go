package control_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestSMTPSettingsKeepPasswordPrivate(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	secret := "test-smtp-password-123"
	config := map[string]any{"host": "mail.example.com", "port": 465, "security": "tls", "username": "noreply@example.com", "password": secret, "from": "noreply@example.com"}
	if status, body, _ := h.api("POST", "/api/smtp", config, admin); status != http.StatusOK || strings.Contains(string(body), secret) {
		t.Fatalf("SMTP save returned %d or exposed the password: %s", status, body)
	}
	if status, body, _ := h.api("GET", "/api/smtp", nil, admin); status != http.StatusOK || strings.Contains(string(body), secret) || !strings.Contains(string(body), "hasPassword") {
		t.Fatalf("SMTP read returned %d or exposed the password: %s", status, body)
	}
	config["password"] = ""
	if status, body, _ := h.api("POST", "/api/smtp", config, admin); status != http.StatusOK || strings.Contains(string(body), secret) {
		t.Fatalf("SMTP save with unchanged password returned %d: %s", status, body)
	}
	if status, _, _ := h.api("GET", "/api/smtp", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated SMTP read returned %d", status)
	}
}

func TestUserEmailIsLinkedAndUnique(t *testing.T) {
	h := newHarness(t, true)
	user, err := h.server.Auth().AddUserWithEmail("sam", "Sam@example.com", "sam-password-123", "regular")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.server.Auth().AddUserWithEmail("lee", "SAM@example.com", "lee-password-123", "regular"); err == nil {
		t.Fatal("duplicate email was accepted")
	}
	if status, _, _ := h.api("POST", "/api/login", map[string]string{"username": "sam@example.com", "password": "sam-password-123"}, nil); status != http.StatusUnauthorized {
		t.Fatalf("unverified email login returned %d", status)
	}
	token, err := h.server.Auth().IssueEmailToken(user.ID, user.Email, "verify")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.Auth().ConfirmEmail(token); err != nil {
		t.Fatal(err)
	}
	if err := h.server.Auth().ConfirmEmail(token); err == nil {
		t.Fatal("confirmation token worked twice")
	}
	if status, _, _ := h.api("POST", "/api/login", map[string]string{"username": "sam@example.com", "password": "sam-password-123"}, nil); status != http.StatusOK {
		t.Fatalf("login using linked email returned %d", status)
	}
}
