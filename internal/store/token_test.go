package store

import (
	"strings"
	"testing"
)

// TestTokensAlwaysParse guards against a token alphabet that collides with the
// separator: an early version used URL-safe base64, which contains "_", so
// roughly half of all tokens failed to parse.
func TestTokensAlwaysParse(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		token, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(token, "_") != 2 {
			t.Fatalf("token %q does not have exactly two separators", token)
		}
		id, ok := TokenID(token)
		if !ok {
			t.Fatalf("token %q does not parse", token)
		}
		if seen[id] {
			t.Fatalf("duplicate token id %q", id)
		}
		seen[id] = true
	}
}

func TestTokenIDRejectsJunk(t *testing.T) {
	for _, bad := range []string{"", "nt", "nt_", "nt_a", "nt_a_b_c", "xx_a_b", "nt__b"} {
		if _, ok := TokenID(bad); ok {
			t.Fatalf("%q should not parse", bad)
		}
	}
}

func TestEqualToken(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !EqualToken(token, "  "+token+" ") {
		t.Fatal("tokens should compare equal regardless of surrounding space")
	}
	if EqualToken(token, token+"x") {
		t.Fatal("different tokens must not compare equal")
	}
}
