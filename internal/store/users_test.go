package store

import (
	"errors"
	"testing"
)

func TestEnsureAdminCreatesTheFirstAccount(t *testing.T) {
	dir := t.TempDir()
	auth, err := OpenAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	if auth.HasUsers() {
		t.Fatal("a fresh control node should have no accounts")
	}
	if err := auth.EnsureAdmin("first-password"); err != nil {
		t.Fatal(err)
	}
	if !auth.HasUsers() {
		t.Fatal("EnsureAdmin should create an account")
	}
	user, err := auth.Authenticate("admin", "first-password")
	if err != nil {
		t.Fatalf("the created admin cannot sign in: %v", err)
	}
	if user.Role != RoleAdmin || !user.CanAdmin() {
		t.Fatalf("expected an admin, got %+v", user)
	}
	// A second call must not overwrite anything.
	if err := auth.EnsureAdmin("something-else"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Authenticate("admin", "first-password"); err != nil {
		t.Fatal("the original password should still work")
	}
}

func TestLegacyPasswordMigratesToAdminUser(t *testing.T) {
	dir := t.TempDir()
	auth, err := OpenAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a control node from before roles existed: only a password hash.
	hash, err := hashSecret("legacy-password")
	if err != nil {
		t.Fatal(err)
	}
	auth.mu.Lock()
	auth.st.PasswordHash = hash
	auth.st.Users = nil
	if err := auth.saveLocked(); err != nil {
		t.Fatal(err)
	}
	auth.mu.Unlock()

	reopened, err := OpenAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	users := reopened.Users()
	if len(users) != 1 || users[0].Username != "admin" || users[0].Role != RoleAdmin {
		t.Fatalf("legacy password should become an admin account, got %+v", users)
	}
	if _, err := reopened.Authenticate("admin", "legacy-password"); err != nil {
		t.Fatalf("the migrated account cannot sign in: %v", err)
	}
	if _, err := reopened.Authenticate("admin", "wrong-password"); err == nil {
		t.Fatal("a wrong password must not authenticate")
	}
}

func TestUserLifecycleAndValidation(t *testing.T) {
	auth, err := OpenAuth(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.EnsureAdmin("admin-password"); err != nil {
		t.Fatal(err)
	}
	viewer, err := auth.AddUser("sam", "sam-password", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if viewer.CanAdmin() {
		t.Fatal("a viewer must not be an admin")
	}
	if _, err := auth.AddUser("SAM", "another-password", RoleAdmin); !errors.Is(err, ErrUserExists) {
		t.Fatalf("usernames must be unique regardless of case, got %v", err)
	}
	if _, err := auth.AddUser("ab", "long-enough-password", RoleViewer); !errors.Is(err, ErrBadUsername) {
		t.Fatalf("short usernames must be rejected, got %v", err)
	}
	if _, err := auth.AddUser("bad name", "long-enough-password", RoleViewer); !errors.Is(err, ErrBadUsername) {
		t.Fatalf("usernames with spaces must be rejected, got %v", err)
	}
	if _, err := auth.AddUser("shortpw", "tiny", RoleViewer); err == nil {
		t.Fatal("short passwords must be rejected")
	}
	if _, err := auth.Authenticate("sam", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password should be rejected, got %v", err)
	}
	if _, err := auth.Authenticate("nobody", "whatever"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user should be rejected, got %v", err)
	}

	// Disabling blocks sign in.
	if _, err := auth.UpdateUser(viewer.ID, func(u *User) error { u.Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Authenticate("sam", "sam-password"); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("a disabled account should not sign in, got %v", err)
	}

	// Password resets work and are hashed.
	if err := auth.SetUserPassword(viewer.ID, "brand-new-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.UpdateUser(viewer.ID, func(u *User) error { u.Disabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Authenticate("sam", "brand-new-password"); err != nil {
		t.Fatalf("the new password should work: %v", err)
	}
	if _, err := auth.Authenticate("sam", "sam-password"); err == nil {
		t.Fatal("the old password must stop working")
	}
	users := auth.Users()
	for _, u := range users {
		if u.PasswordHash != "" {
			t.Fatal("listing users must not expose password hashes")
		}
	}
}

func TestLastAdminIsProtected(t *testing.T) {
	auth, err := OpenAuth(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.EnsureAdmin("admin-password"); err != nil {
		t.Fatal(err)
	}
	admin := auth.Users()[0]
	if _, err := auth.UpdateUser(admin.ID, func(u *User) error { u.Role = RoleViewer; return nil }); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting the last admin must fail, got %v", err)
	}
	if _, err := auth.UpdateUser(admin.ID, func(u *User) error { u.Disabled = true; return nil }); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disabling the last admin must fail, got %v", err)
	}
	if err := auth.RemoveUser(admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting the last admin must fail, got %v", err)
	}
	// With a second admin the first can be demoted.
	second, err := auth.AddUser("second", "second-password", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.UpdateUser(admin.ID, func(u *User) error { u.Role = RoleViewer; return nil }); err != nil {
		t.Fatalf("demoting with another admin present should work: %v", err)
	}
	if err := auth.RemoveUser(second.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("removing the only remaining admin must fail, got %v", err)
	}
}

func TestAPITokenRoles(t *testing.T) {
	auth, err := OpenAuth(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.EnsureAdmin("admin-password"); err != nil {
		t.Fatal(err)
	}
	adminToken, _, err := auth.AddAPITokenWithRole("ci", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	viewerToken, _, err := auth.AddAPITokenWithRole("readonly", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if role, ok := auth.VerifyAPIToken(adminToken); !ok || role != RoleAdmin {
		t.Fatalf("admin token resolved to %v %v", role, ok)
	}
	if role, ok := auth.VerifyAPIToken(viewerToken); !ok || role != RoleViewer {
		t.Fatalf("viewer token resolved to %v %v", role, ok)
	}
	if _, ok := auth.VerifyAPIToken("ntapi_nope"); ok {
		t.Fatal("a bogus token must not verify")
	}
	// Tokens created before roles existed default to admin.
	legacy, _, err := auth.AddAPIToken("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if role, _ := auth.VerifyAPIToken(legacy); role != RoleAdmin {
		t.Fatalf("legacy tokens should default to admin, got %v", role)
	}
}

// TestUpsertUser covers the CLI's bootstrap and recovery path.
func TestUpsertUser(t *testing.T) {
	auth, err := OpenAuth(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	created, isNew, err := auth.UpsertUser("admin", "first-password", RoleAdmin)
	if err != nil || !isNew {
		t.Fatalf("creating through upsert failed: %v (new=%v)", err, isNew)
	}
	if _, err := auth.Authenticate("admin", "first-password"); err != nil {
		t.Fatalf("the upserted account cannot sign in: %v", err)
	}
	// Running it again replaces the password instead of failing.
	updated, isNew, err := auth.UpsertUser("admin", "second-password", RoleAdmin)
	if err != nil || isNew {
		t.Fatalf("updating through upsert failed: %v (new=%v)", err, isNew)
	}
	if updated.ID != created.ID {
		t.Fatal("upsert must reuse the existing account")
	}
	if _, err := auth.Authenticate("admin", "second-password"); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
	if _, err := auth.Authenticate("admin", "first-password"); err == nil {
		t.Fatal("the previous password must stop working")
	}
	// A disabled account is re-enabled by upsert. Reaching that state needs a
	// second admin, because the last enabled admin is protected.
	if _, err := auth.AddUser("second", "second-password", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.UpdateUser(created.ID, func(u *User) error { u.Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.UpsertUser("admin", "third-password", RoleAdmin); err != nil {
		t.Fatalf("upsert should re-enable a disabled account: %v", err)
	}
	if _, err := auth.Authenticate("admin", "third-password"); err != nil {
		t.Fatalf("the recovered account cannot sign in: %v", err)
	}
}
