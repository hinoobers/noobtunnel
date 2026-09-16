package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Role decides what an account may do on the control node.
type Role string

const (
	// RoleAdmin can change the mesh, enroll and revoke agents, and manage users.
	RoleAdmin Role = "admin"
	// RoleViewer can see everything but change nothing.
	RoleViewer Role = "viewer"
)

// ValidRole reports whether r is a known role.
func ValidRole(r Role) bool { return r == RoleAdmin || r == RoleViewer }

// User is a control node account.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"passwordHash,omitempty"`
	Role         Role       `json:"role"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastLogin    *time.Time `json:"lastLogin,omitempty"`
	Disabled     bool       `json:"disabled,omitempty"`
}

// CanAdmin reports whether the account may perform changes.
func (u User) CanAdmin() bool { return u.Role == RoleAdmin && !u.Disabled }

var (
	// ErrUserExists means the username is taken.
	ErrUserExists = errors.New("store: that username is already taken")
	// ErrLastAdmin protects against locking everyone out.
	ErrLastAdmin = errors.New("store: the last enabled admin cannot be removed, disabled or demoted")
	// ErrUserDisabled means the account exists but is switched off.
	ErrUserDisabled = errors.New("store: that account is disabled")
	// ErrBadUsername means the username is not acceptable.
	ErrBadUsername = errors.New("store: usernames must be 3-32 characters of letters, digits, dot, dash or underscore")
)

// HasUsers reports whether any account exists yet.
func (a *Auth) HasUsers() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.st.Users) > 0
}

// Users lists accounts without their password hashes, sorted by username.
func (a *Auth) Users() []User {
	a.mu.RLock()
	out := append([]User(nil), a.st.Users...)
	a.mu.RUnlock()
	for i := range out {
		out[i].PasswordHash = ""
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Username) < strings.ToLower(out[j].Username) })
	return out
}

// AdminCount returns how many enabled admins exist.
func (a *Auth) AdminCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.adminCountLocked()
}

func (a *Auth) adminCountLocked() int {
	count := 0
	for _, u := range a.st.Users {
		if u.CanAdmin() {
			count++
		}
	}
	return count
}

// UserByID returns one account.
func (a *Auth) UserByID(id string) (User, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	u, ok := a.findLocked(id)
	if !ok {
		return User{}, ErrNotFound
	}
	u.PasswordHash = ""
	return u, nil
}

func (a *Auth) findLocked(id string) (User, bool) {
	for _, u := range a.st.Users {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

func (a *Auth) findByUsernameLocked(username string) (User, bool) {
	for _, u := range a.st.Users {
		if strings.EqualFold(u.Username, username) {
			return u, true
		}
	}
	return User{}, false
}

// Authenticate verifies a username and password.
func (a *Auth) Authenticate(username, password string) (User, error) {
	a.mu.RLock()
	user, ok := a.findByUsernameLocked(strings.TrimSpace(username))
	a.mu.RUnlock()
	if !ok {
		// Spend roughly the same time as a real check to avoid leaking which
		// usernames exist.
		_ = verifySecret(dummyHash, password)
		return User{}, ErrBadCredentials
	}
	if err := verifySecret(user.PasswordHash, password); err != nil {
		return User{}, ErrBadCredentials
	}
	if user.Disabled {
		return User{}, ErrUserDisabled
	}
	user.PasswordHash = ""
	return user, nil
}

// dummyHash is a valid scrypt hash used to equalise failed login timing.
var dummyHash = func() string {
	hash, err := hashSecret("noobtunnel-invalid-password")
	if err != nil {
		return ""
	}
	return hash
}()

// AddUser creates an account.
func (a *Auth) AddUser(username, password string, role Role) (User, error) {
	username = strings.TrimSpace(username)
	if err := validateUsername(username); err != nil {
		return User{}, err
	}
	if !ValidRole(role) {
		return User{}, fmt.Errorf("store: unknown role %q", role)
	}
	if len(password) < 8 {
		return User{}, errors.New("store: passwords must be at least 8 characters")
	}
	hash, err := hashSecret(password)
	if err != nil {
		return User{}, err
	}
	id, err := randomToken(8)
	if err != nil {
		return User{}, err
	}
	user := User{
		ID:           id,
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.findByUsernameLocked(username); exists {
		return User{}, ErrUserExists
	}
	a.st.Users = append(a.st.Users, user)
	if err := a.saveLocked(); err != nil {
		return User{}, err
	}
	user.PasswordHash = ""
	return user, nil
}

// UpdateUser applies a change, protecting the last enabled admin.
func (a *Auth) UpdateUser(id string, mutate func(*User) error) (User, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	index := -1
	for i := range a.st.Users {
		if a.st.Users[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return User{}, ErrNotFound
	}
	original := a.st.Users[index]
	candidate := original
	if err := mutate(&candidate); err != nil {
		return User{}, err
	}
	if candidate.Username != original.Username {
		if err := validateUsername(candidate.Username); err != nil {
			return User{}, err
		}
		if other, exists := a.findByUsernameLocked(candidate.Username); exists && other.ID != id {
			return User{}, ErrUserExists
		}
	}
	if !ValidRole(candidate.Role) {
		return User{}, fmt.Errorf("store: unknown role %q", candidate.Role)
	}
	losingAdmin := original.CanAdmin() && !(candidate.Role == RoleAdmin && !candidate.Disabled)
	if losingAdmin && a.adminCountLocked() <= 1 {
		return User{}, ErrLastAdmin
	}
	a.st.Users[index] = candidate
	if err := a.saveLocked(); err != nil {
		return User{}, err
	}
	candidate.PasswordHash = ""
	return candidate, nil
}

// RemoveUser deletes an account.
func (a *Auth) RemoveUser(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.st.Users {
		if a.st.Users[i].ID != id {
			continue
		}
		if a.st.Users[i].CanAdmin() && a.adminCountLocked() <= 1 {
			return ErrLastAdmin
		}
		a.st.Users = append(a.st.Users[:i], a.st.Users[i+1:]...)
		return a.saveLocked()
	}
	return ErrNotFound
}

// SetUserPassword replaces an account's password.
func (a *Auth) SetUserPassword(id, password string) error {
	if len(password) < 8 {
		return errors.New("store: passwords must be at least 8 characters")
	}
	hash, err := hashSecret(password)
	if err != nil {
		return err
	}
	_, err = a.UpdateUser(id, func(u *User) error {
		u.PasswordHash = hash
		return nil
	})
	return err
}

// MarkLogin records a successful sign in.
func (a *Auth) MarkLogin(id string) {
	now := time.Now().UTC()
	_, _ = a.UpdateUser(id, func(u *User) error {
		u.LastLogin = &now
		return nil
	})
}

// EnsureAdmin creates the first admin account if none exists.
func (a *Auth) EnsureAdmin(password string) error {
	if a.HasUsers() || password == "" {
		return nil
	}
	_, err := a.AddUser("admin", password, RoleAdmin)
	return err
}

// FindByUsername looks an account up by name.
func (a *Auth) FindByUsername(username string) (User, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	user, ok := a.findByUsernameLocked(strings.TrimSpace(username))
	if !ok {
		return User{}, ErrNotFound
	}
	user.PasswordHash = ""
	return user, nil
}

// UpsertUser creates an account or, when it already exists, replaces its
// password and role. It is what the CLI uses to bootstrap and to recover an
// account without the web UI.
func (a *Auth) UpsertUser(username, password string, role Role) (User, bool, error) {
	if !ValidRole(role) {
		return User{}, false, fmt.Errorf("store: unknown role %q", role)
	}
	existing, err := a.FindByUsername(username)
	if err == nil {
		updated, err := a.UpdateUser(existing.ID, func(u *User) error {
			u.Role = role
			u.Disabled = false
			return nil
		})
		if err != nil {
			return User{}, false, err
		}
		if err := a.SetUserPassword(existing.ID, password); err != nil {
			return User{}, false, err
		}
		return updated, false, nil
	}
	created, err := a.AddUser(username, password, role)
	if err != nil {
		return User{}, false, err
	}
	return created, true, nil
}

// migrateLegacyPassword turns a pre-users password hash into an admin account.
func (a *Auth) migrateLegacyPassword() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.st.Users) > 0 || a.st.PasswordHash == "" {
		return nil
	}
	id, err := randomToken(8)
	if err != nil {
		return err
	}
	a.st.Users = append(a.st.Users, User{
		ID:           id,
		Username:     "admin",
		PasswordHash: a.st.PasswordHash,
		Role:         RoleAdmin,
		CreatedAt:    time.Now().UTC(),
	})
	a.st.PasswordHash = ""
	return a.saveLocked()
}

func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return ErrBadUsername
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return ErrBadUsername
		}
	}
	return nil
}

func randomToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
