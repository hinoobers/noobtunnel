package store

import "testing"

func TestEmailConfirmationAndPasswordRecovery(t *testing.T) {
	auth, err := OpenAuth(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	user, err := auth.AddUserWithEmail("alice", "alice@example.com", "initial-password", RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Authenticate(user.Username, "initial-password"); err != ErrEmailUnverified {
		t.Fatalf("unconfirmed login: %v", err)
	}
	verification, err := auth.IssueEmailToken(user.ID, user.Email, "verify")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ConfirmEmail(verification); err != nil {
		t.Fatal(err)
	}
	if err := auth.ConfirmEmail(verification); err == nil {
		t.Fatal("confirmation link worked twice")
	}
	if _, err := auth.Authenticate(user.Email, "initial-password"); err != nil {
		t.Fatal(err)
	}
	recovery, err := auth.IssueEmailToken(user.ID, user.Email, "reset")
	if err != nil {
		t.Fatal(err)
	}
	address, err := auth.ResetPassword(recovery, "replacement-password")
	if err != nil || address != user.Email {
		t.Fatalf("reset: %s %v", address, err)
	}
	if _, err := auth.ResetPassword(recovery, "another-password"); err == nil {
		t.Fatal("reset link worked twice")
	}
	if _, err := auth.Authenticate(user.Email, "initial-password"); err == nil {
		t.Fatal("old password still works")
	}
	if updated, err := auth.Authenticate(user.Email, "replacement-password"); err != nil || updated.SessionVersion == 0 {
		t.Fatalf("new password or session version: %v", err)
	}
	change, err := auth.IssueEmailToken(user.ID, "new@example.com", "change")
	if err != nil {
		t.Fatal(err)
	}
	if current, _ := auth.UserByID(user.ID); current.Email != user.Email {
		t.Fatal("email changed before confirmation")
	}
	if err := auth.ConfirmEmail(change); err != nil {
		t.Fatal(err)
	}
	if current, _ := auth.UserByID(user.ID); current.Email != "new@example.com" || !current.EmailVerified {
		t.Fatal("confirmed email change was not applied")
	}
}
