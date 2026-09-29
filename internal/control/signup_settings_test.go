package control_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func TestExpiredSignupIsRemovedOnStartupAndLimitSettingsPersist(t *testing.T) {
	dir := t.TempDir()
	auth, err := store.OpenAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.AddUser("admin", "correct-horse-battery-staple", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	pending, err := auth.AddUserWithEmail("pending", "pending@example.com", "password-123", store.RoleRegular)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.UpdateUser(pending.ID, func(u *store.User) error {
		u.CreatedAt = time.Now().UTC().Add(-25 * time.Hour)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	h := newHarnessOnDir(t, true, "", dir, nil)
	if _, err := h.server.Auth().UserByID(pending.ID); err != store.ErrNotFound {
		t.Fatalf("expired account survived restart: %v", err)
	}
	admin := h.login(t)
	status, body, _ := h.api("POST", "/api/signup/settings", map[string]any{"enabled": false, "maxUsers": 1}, admin)
	if status != http.StatusOK {
		t.Fatalf("save signup limit: %d %s", status, body)
	}
	status, body, _ = h.api("GET", "/api/signup/settings", nil, admin)
	var settings struct {
		MaxUsers        int `json:"maxUsers"`
		RegisteredUsers int `json:"registeredUsers"`
	}
	if err := json.Unmarshal(body, &settings); err != nil || status != http.StatusOK || settings.MaxUsers != 1 || settings.RegisteredUsers != 0 {
		t.Fatalf("signup settings: %d %s %v", status, body, err)
	}
	status, _, _ = h.api("POST", "/api/signup/settings", map[string]any{"enabled": false, "maxUsers": 0}, admin)
	if status != http.StatusBadRequest {
		t.Fatalf("zero user limit accepted: %d", status)
	}
	replacement, err := h.server.Auth().AddUserWithEmail("replacement", "replacement@example.com", "password-123", store.RoleRegular)
	if err != nil || replacement.MeshSlot != pending.MeshSlot {
		t.Fatalf("expired mesh slot was not reused: %+v %v", replacement, err)
	}
}
