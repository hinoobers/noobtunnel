package proxy

import "testing"

func TestResourceOwnerKeepsIdentityAccessWithEmailAllowlist(t *testing.T) {
	manager := &Manager{IdentityAccount: func(username string) (string, string, uint16, bool) {
		switch username {
		case "owner":
			return "owner-id", "owner@example.com", 2, true
		case "guest":
			return "guest-id", "guest@example.com", 3, true
		case "stranger":
			return "stranger-id", "stranger@example.com", 4, true
		default:
			return "", "", 0, false
		}
	}}
	h := &httpResource{group: &group{manager: manager}}
	r := &resource{spec: Spec{OwnerID: "owner-id", IdentityEmails: []string{"guest@example.com"}}}
	if !h.allowedIdentity(r, "owner") || !h.allowedIdentity(r, "guest") {
		t.Fatal("owner or allowed guest lost access")
	}
	if h.allowedIdentity(r, "stranger") {
		t.Fatal("unlisted account gained access")
	}
}
