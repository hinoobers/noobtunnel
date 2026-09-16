package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// scrypt parameters. These are deliberately expensive enough to make offline
// guessing of the admin password painful without slowing down logins.
const (
	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
)

// ErrBadCredentials is returned when a password or token does not match.
var ErrBadCredentials = errors.New("store: invalid credentials")

// APIToken is a long lived token for scripting against the control node API.
type APIToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"createdAt"`
	// Role defaults to admin for tokens created before roles existed.
	Role Role `json:"role,omitempty"`
}

// EffectiveRole returns the token's role, defaulting to admin.
func (t APIToken) EffectiveRole() Role {
	if ValidRole(t.Role) {
		return t.Role
	}
	return RoleAdmin
}

// AuthState is persisted separately from mesh state so it can be rotated on its own.
type AuthState struct {
	// PasswordHash is the pre-users admin password. It is migrated into an
	// "admin" account on load and left empty afterwards.
	PasswordHash string     `json:"passwordHash,omitempty"`
	SessionKey   string     `json:"sessionKey"`
	APITokens    []APIToken `json:"apiTokens,omitempty"`
	Users        []User     `json:"users,omitempty"`
}

// Auth holds the control node's administrative credentials.
type Auth struct {
	path string
	mu   sync.RWMutex
	st   AuthState
}

// OpenAuth loads or creates the auth file in dir.
func OpenAuth(dir string) (*Auth, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	a := &Auth{path: filepath.Join(dir, "auth.json")}
	raw, err := os.ReadFile(a.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &a.st); err != nil {
			return nil, fmt.Errorf("store: parse %s: %w", a.path, err)
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	if a.st.SessionKey == "" {
		if err := a.rotateLocked(); err != nil {
			return nil, err
		}
		if err := a.saveLocked(); err != nil {
			return nil, err
		}
	}
	if err := a.migrateLegacyPassword(); err != nil {
		return nil, err
	}
	return a, nil
}

// Path returns the auth file path.
func (a *Auth) Path() string { return a.path }

func (a *Auth) saveLocked() error {
	raw, err := json.MarshalIndent(a.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

func (a *Auth) rotateLocked() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	a.st.SessionKey = base64.StdEncoding.EncodeToString(key)
	return nil
}

// HasPassword reports whether any account exists, so the UI can tell a fresh
// control node from a configured one.
func (a *Auth) HasPassword() bool {
	return a.HasUsers()
}

// SetPassword sets the password of the first admin account, creating one when
// the control node has no accounts yet. It backs the --admin-password flag.
func (a *Auth) SetPassword(password string) error {
	if len(password) < 8 {
		return errors.New("store: admin password must be at least 8 characters")
	}
	if err := a.EnsureAdmin(password); err != nil {
		return err
	}
	a.mu.Lock()
	var adminID string
	for _, u := range a.st.Users {
		if u.Role == RoleAdmin {
			adminID = u.ID
			break
		}
	}
	a.mu.Unlock()
	if adminID == "" {
		return errors.New("store: no admin account available")
	}
	return a.SetUserPassword(adminID, password)
}

// CheckPassword verifies the password of the first admin account. It is kept for
// CLI compatibility; the API authenticates users by name.
func (a *Auth) CheckPassword(password string) error {
	a.mu.RLock()
	var hash string
	for _, u := range a.st.Users {
		if u.Role == RoleAdmin {
			hash = u.PasswordHash
			break
		}
	}
	a.mu.RUnlock()
	if hash == "" {
		return ErrBadCredentials
	}
	return verifySecret(hash, password)
}

// SessionKey returns the HMAC key used to sign session cookies.
func (a *Auth) SessionKey() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	key, _ := base64.StdEncoding.DecodeString(a.st.SessionKey)
	return key
}

// RotateSessionKey invalidates every existing browser session.
func (a *Auth) RotateSessionKey() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.rotateLocked(); err != nil {
		return err
	}
	return a.saveLocked()
}

// AddAPIToken mints a new API token and returns the plaintext exactly once.
func (a *Auth) AddAPIToken(name string) (string, APIToken, error) {
	return a.AddAPITokenWithRole(name, RoleAdmin)
}

// AddAPITokenWithRole mints an API token with an explicit role.
func (a *Auth) AddAPITokenWithRole(name string, role Role) (string, APIToken, error) {
	if !ValidRole(role) {
		role = RoleAdmin
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", APIToken{}, err
	}
	plaintext := "ntapi_" + base64.RawURLEncoding.EncodeToString(raw)
	hash, err := hashSecret(plaintext)
	if err != nil {
		return "", APIToken{}, err
	}
	idRaw := make([]byte, 4)
	if _, err := rand.Read(idRaw); err != nil {
		return "", APIToken{}, err
	}
	tok := APIToken{
		ID:        base64.RawURLEncoding.EncodeToString(idRaw),
		Name:      strings.TrimSpace(name),
		Hash:      hash,
		CreatedAt: time.Now().UTC(),
		Role:      role,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.APITokens = append(a.st.APITokens, tok)
	if err := a.saveLocked(); err != nil {
		return "", APIToken{}, err
	}
	return plaintext, tok, nil
}

// VerifyAPIToken checks a bearer token and returns its role.
func (a *Auth) VerifyAPIToken(plaintext string) (Role, bool) {
	a.mu.RLock()
	tokens := append([]APIToken(nil), a.st.APITokens...)
	a.mu.RUnlock()
	for _, t := range tokens {
		if verifySecret(t.Hash, plaintext) == nil {
			return t.EffectiveRole(), true
		}
	}
	return "", false
}

// APITokens lists the configured tokens without their secrets.
func (a *Auth) APITokens() []APIToken {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := append([]APIToken(nil), a.st.APITokens...)
	for i := range out {
		out[i].Hash = ""
	}
	return out
}

// RemoveAPIToken deletes a token by id.
func (a *Auth) RemoveAPIToken(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.st.APITokens[:0]
	found := false
	for _, t := range a.st.APITokens {
		if t.ID == id {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		return ErrNotFound
	}
	a.st.APITokens = out
	return a.saveLocked()
}

// hashSecret returns a self describing scrypt hash: scrypt$N$r$p$salt$hash.
func hashSecret(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(secret), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", scryptN, scryptR, scryptP,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

func verifySecret(encoded, secret string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return ErrBadCredentials
	}
	n, err1 := strconv.Atoi(parts[1])
	r, err2 := strconv.Atoi(parts[2])
	p, err3 := strconv.Atoi(parts[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return ErrBadCredentials
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrBadCredentials
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrBadCredentials
	}
	got, err := scrypt.Key([]byte(secret), salt, n, r, p, len(want))
	if err != nil {
		return ErrBadCredentials
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrBadCredentials
	}
	return nil
}
