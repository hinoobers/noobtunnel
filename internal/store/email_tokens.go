package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var ErrInvalidEmailToken = errors.New("store: this link is invalid or expired")
var ErrEmailTokenCooldown = errors.New("store: wait before requesting another email")

const DefaultSignupMaxUsers = 25

func (a *Auth) signupMaxUsersLocked() int {
	if a.st.SignupMaxUsers == 0 {
		return DefaultSignupMaxUsers
	}
	return a.st.SignupMaxUsers
}

func (a *Auth) regularUserCountLocked() int {
	count := 0
	for _, user := range a.st.Users {
		if user.Role == RoleRegular {
			count++
		}
	}
	return count
}

// SignupCapacity reports the current regular account count and configured cap.
func (a *Auth) SignupCapacity() (int, int) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.regularUserCountLocked(), a.signupMaxUsersLocked()
}

// SetSignupSettings saves both signup controls together.
func (a *Auth) SetSignupSettings(enabled bool, maxUsers int) error {
	if maxUsers < 1 || maxUsers > 255 {
		return errors.New("store: maximum users must be between 1 and 255")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.SignupEnabled = enabled
	a.st.SignupMaxUsers = maxUsers
	return a.saveLocked()
}

// EmailToken stores only a digest of a single-use verification or recovery link.
type EmailToken struct {
	Hash      string    `json:"hash"`
	UserID    string    `json:"userId"`
	Email     string    `json:"email"`
	Purpose   string    `json:"purpose"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func tokenDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (a *Auth) SignupEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.st.SignupEnabled
}

func (a *Auth) SetSignupEnabled(enabled bool) error {
	_, maxUsers := a.SignupCapacity()
	return a.SetSignupSettings(enabled, maxUsers)
}

// ExpireUnverified removes accounts still pending after 24 hours, including
// their email links. The last enabled admin is kept to avoid lockout.
func (a *Auth) ExpireUnverified(now time.Time) ([]User, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	removed := make([]User, 0)
	kept := make([]User, 0, len(a.st.Users))
	admins := a.adminCountLocked()
	for _, user := range a.st.Users {
		if user.Email == "" || user.EmailVerified || user.CreatedAt.IsZero() || user.CreatedAt.Add(24*time.Hour).After(now) || (user.CanAdmin() && admins <= 1) {
			kept = append(kept, user)
			continue
		}
		if user.CanAdmin() {
			admins--
		}
		user.PasswordHash = ""
		removed = append(removed, user)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	a.st.Users = kept
	remaining := a.st.EmailTokens[:0]
	for _, token := range a.st.EmailTokens {
		belongs := false
		for _, user := range removed {
			if token.UserID == user.ID {
				belongs = true
				break
			}
		}
		if !belongs {
			remaining = append(remaining, token)
		}
	}
	a.st.EmailTokens = remaining
	if err := a.saveLocked(); err != nil {
		return nil, err
	}
	return removed, nil
}

// IssueEmailToken creates a link for an existing account. For a change, email
// is the proposed new address and the current address remains active.
func (a *Auth) IssueEmailToken(userID, email, purpose string) (string, error) {
	if purpose != "verify" && purpose != "change" && purpose != "reset" {
		return "", ErrInvalidEmailToken
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if err := validateEmail(email); err != nil || email == "" {
		return "", ErrBadEmail
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	user, ok := a.findLocked(userID)
	if !ok || user.Disabled {
		return "", ErrNotFound
	}
	if purpose == "verify" && (user.Email != email || user.EmailVerified) {
		return "", ErrInvalidEmailToken
	}
	if purpose == "reset" && (user.Email != email || !user.EmailVerified) {
		return "", ErrInvalidEmailToken
	}
	if purpose == "change" {
		if other, exists := a.findByUsernameLocked(email); exists && other.ID != userID {
			return "", ErrEmailExists
		}
	}
	now := time.Now().UTC()
	for _, issued := range a.st.EmailTokens {
		if issued.UserID == userID && issued.Purpose == purpose && now.Sub(issued.CreatedAt) < 5*time.Minute {
			return "", ErrEmailTokenCooldown
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	filtered := a.st.EmailTokens[:0]
	for _, issued := range a.st.EmailTokens {
		if issued.ExpiresAt.After(now) && !(issued.UserID == userID && issued.Purpose == purpose) {
			filtered = append(filtered, issued)
		}
	}
	a.st.EmailTokens = append(filtered, EmailToken{Hash: tokenDigest(plaintext), UserID: userID, Email: email, Purpose: purpose, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err := a.saveLocked(); err != nil {
		return "", err
	}
	return plaintext, nil
}

func (a *Auth) consumeTokenLocked(plaintext, purpose string) (int, EmailToken, error) {
	if len(plaintext) != 43 {
		return -1, EmailToken{}, ErrInvalidEmailToken
	}
	digest := tokenDigest(plaintext)
	for i, issued := range a.st.EmailTokens {
		if issued.Purpose == purpose && subtle.ConstantTimeCompare([]byte(issued.Hash), []byte(digest)) == 1 && issued.ExpiresAt.After(time.Now().UTC()) {
			return i, issued, nil
		}
	}
	return -1, EmailToken{}, ErrInvalidEmailToken
}

// ConfirmEmail activates a new user's address or a verified email change.
func (a *Auth) ConfirmEmail(plaintext string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	index, issued, err := a.consumeTokenLocked(plaintext, "verify")
	if err != nil {
		index, issued, err = a.consumeTokenLocked(plaintext, "change")
	}
	if err != nil {
		return err
	}
	for i := range a.st.Users {
		u := &a.st.Users[i]
		if u.ID != issued.UserID {
			continue
		}
		if issued.Purpose == "verify" && u.Email != issued.Email {
			return ErrInvalidEmailToken
		}
		if issued.Purpose == "change" {
			if other, exists := a.findByUsernameLocked(issued.Email); exists && other.ID != u.ID {
				return ErrEmailExists
			}
			u.Email = issued.Email
		}
		u.EmailVerified = true
		a.st.EmailTokens = append(a.st.EmailTokens[:index], a.st.EmailTokens[index+1:]...)
		return a.saveLocked()
	}
	return ErrInvalidEmailToken
}

// ResetPassword consumes a verified account's recovery link and invalidates
// its existing browser sessions through SessionVersion.
func (a *Auth) ResetPassword(plaintext, password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("store: passwords must be at least 8 characters")
	}
	hash, err := hashSecret(password)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	index, issued, err := a.consumeTokenLocked(plaintext, "reset")
	if err != nil {
		return "", err
	}
	for i := range a.st.Users {
		u := &a.st.Users[i]
		if u.ID != issued.UserID || !u.EmailVerified || u.Email != issued.Email {
			continue
		}
		u.PasswordHash = hash
		u.SessionVersion++
		a.st.EmailTokens = append(a.st.EmailTokens[:index], a.st.EmailTokens[index+1:]...)
		return u.Email, a.saveLocked()
	}
	return "", ErrInvalidEmailToken
}
