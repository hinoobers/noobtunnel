// Package wg wraps the parts of WireGuard that noobtunnel needs: key handling,
// configuration rendering, `wg show` parsing and the platform backend that
// actually programs the kernel.
package wg

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyLength is the length of a Curve25519 key in bytes.
const KeyLength = 32

// KeyPair is a WireGuard private/public key pair in the base64 form used by wg(8).
type KeyPair struct {
	Private string
	Public  string
}

// GenerateKeyPair creates a new key pair exactly the way `wg genkey` does:
// 32 random bytes, clamped, with the public key derived by X25519 scalar-base
// multiplication.
func GenerateKeyPair() (KeyPair, error) {
	var priv [KeyLength]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, fmt.Errorf("wg: generate private key: %w", err)
	}
	return KeyPairFromPrivate(priv)
}

// MustGeneratePrivateKey returns a fresh private key, panicking only if the
// system random source fails.
func MustGeneratePrivateKey() string {
	kp, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	return kp.Private
}

// KeyPairFromPrivate derives the public key for a raw private key.
func KeyPairFromPrivate(priv [KeyLength]byte) (KeyPair, error) {
	scalar := clamp(priv)
	pub, err := curve25519.X25519(scalar[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("wg: derive public key: %w", err)
	}
	return KeyPair{
		Private: base64.StdEncoding.EncodeToString(priv[:]),
		Public:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// PublicFromPrivate returns the base64 public key for a base64 private key.
func PublicFromPrivate(privateB64 string) (string, error) {
	raw, err := DecodeKey(privateB64)
	if err != nil {
		return "", err
	}
	kp, err := KeyPairFromPrivate(raw)
	if err != nil {
		return "", err
	}
	return kp.Public, nil
}

// GeneratePresharedKey creates a random 32 byte pre-shared key in base64 form.
// Pre-shared keys are not clamped; they are used as plain symmetric keys.
func GeneratePresharedKey() (string, error) {
	var psk [KeyLength]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return "", fmt.Errorf("wg: generate preshared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(psk[:]), nil
}

// DecodeKey decodes a base64 WireGuard key.
func DecodeKey(s string) ([KeyLength]byte, error) {
	var out [KeyLength]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(s); err != nil {
			return out, fmt.Errorf("wg: key is not valid base64")
		}
	}
	if len(raw) != KeyLength {
		return out, fmt.Errorf("wg: key decodes to %d bytes, want %d", len(raw), KeyLength)
	}
	copy(out[:], raw)
	return out, nil
}

// ValidKey reports whether s is a well formed WireGuard key.
func ValidKey(s string) bool {
	_, err := DecodeKey(s)
	return err == nil
}

// clamp applies the X25519 clamping rules.
func clamp(b [KeyLength]byte) [KeyLength]byte {
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	return b
}
