package store

import (
	"errors"
	"testing"
	"time"
)

func TestSignupLimitExpiryAndMeshSlotReuse(t *testing.T) {
	auth, err := OpenAuth(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	admin, err := auth.AddUser("admin", "admin-password-123", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SetSignupSettings(true, 1); err != nil {
		t.Fatal(err)
	}
	first, err := auth.AddUserWithEmail("pending", "pending@example.com", "password-123", RoleRegular)
	if err != nil {
		t.Fatal(err)
	}
	link, err := auth.IssueEmailToken(first.ID, first.Email, "verify")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.AddUserWithEmail("extra", "extra@example.com", "password-123", RoleRegular); !errors.Is(err, ErrUserLimit) {
		t.Fatalf("over limit: %v", err)
	}
	now := time.Now().UTC()
	if _, err := auth.UpdateUser(first.ID, func(u *User) error { u.CreatedAt = now.Add(-23 * time.Hour); return nil }); err != nil {
		t.Fatal(err)
	}
	if removed, err := auth.ExpireUnverified(now); err != nil || len(removed) != 0 {
		t.Fatalf("account expired too early: %v %v", removed, err)
	}
	if _, err := auth.UpdateUser(first.ID, func(u *User) error { u.CreatedAt = now.Add(-25 * time.Hour); return nil }); err != nil {
		t.Fatal(err)
	}
	removed, err := auth.ExpireUnverified(now)
	if err != nil || len(removed) != 1 || removed[0].ID != first.ID {
		t.Fatalf("expiry: %v %v", removed, err)
	}
	if _, err := auth.UserByID(first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired user remains: %v", err)
	}
	if err := auth.ConfirmEmail(link); !errors.Is(err, ErrInvalidEmailToken) {
		t.Fatalf("expired confirmation link still works: %v", err)
	}
	if _, err := auth.UserByID(admin.ID); err != nil {
		t.Fatalf("admin was removed: %v", err)
	}
	second, err := auth.AddUserWithEmail("replacement", "replacement@example.com", "password-123", RoleRegular)
	if err != nil || second.MeshSlot != first.MeshSlot {
		t.Fatalf("freed slot was not reused: %+v %v", second, err)
	}
}
