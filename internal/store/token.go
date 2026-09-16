package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// TokenPrefix identifies noobtunnel enrollment tokens.
const TokenPrefix = "nt"

// NewToken mints an enrollment token of the form nt_<tokenid>_<secret>.
//
// The token id is public and used for lookup; the secret is only stored on the
// control node and the enrolled machine. Both halves are hex so the token can
// never contain the "_" separator itself.
func NewToken() (string, error) {
	var idRaw [6]byte
	if _, err := rand.Read(idRaw[:]); err != nil {
		return "", err
	}
	var secretRaw [32]byte
	if _, err := rand.Read(secretRaw[:]); err != nil {
		return "", err
	}
	return TokenPrefix + "_" + hex.EncodeToString(idRaw[:]) + "_" + hex.EncodeToString(secretRaw[:]), nil
}

// TokenID extracts the public lookup id from a token.
func TokenID(token string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(token), "_")
	if len(parts) != 3 || parts[0] != TokenPrefix || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return parts[1], true
}

// EqualToken compares two tokens in constant time.
func EqualToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(a)), []byte(strings.TrimSpace(b))) == 1
}
