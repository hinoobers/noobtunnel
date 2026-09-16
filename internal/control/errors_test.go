package control

import (
	"errors"
	"testing"
)

// TestErrorLogCollapsesRepeats covers the retry case: a sync that fails every
// minute must not fill the list with the same line. Interleaved failures used to
// defeat the check, which only looked at the newest entry.
func TestErrorLogCollapsesRepeats(t *testing.T) {
	log := newErrorLog()
	log.record("dns", "could not update app.example.com", "error 9005", "check the token")
	log.record("certificate", "no managed certificate for app.example.com", "acme: timeout", "check port 80")
	log.record("dns", "could not update app.example.com", "error 9005", "check the token")

	entries := log.recent()
	if len(entries) != 2 {
		t.Fatalf("the repeated failure should not be listed twice: %+v", entries)
	}
	if entries[0].Source != "dns" {
		t.Fatalf("the repeated failure should move back to the top: %+v", entries)
	}

	// A different detail is a different problem and stays separate.
	log.record("dns", "could not update app.example.com", "error 81057", "check the token")
	if entries := log.recent(); len(entries) != 3 {
		t.Fatalf("a different failure should be its own entry: %+v", entries)
	}

	log.clear()
	if entries := log.recent(); len(entries) != 0 {
		t.Fatalf("clear should empty the log: %+v", entries)
	}
}

// TestCertificateNoiseIsNotReported keeps scanners out of the Errors view: a
// client that sends no SNI, or a plain probe, is not a certificate failure worth
// showing an operator.
func TestCertificateNoiseIsNotReported(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"", errors.New("acme/autocert: missing server name"), false},
		{"app.example.com", errors.New("acme/autocert: missing server name"), false},
		{"", errors.New("some other failure"), false},
		{"app.example.com", errors.New("acme/autocert: unable to authorize"), true},
	}
	for _, tc := range cases {
		if got := worthReporting(tc.name, tc.err); got != tc.want {
			t.Errorf("worthReporting(%q, %v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}
