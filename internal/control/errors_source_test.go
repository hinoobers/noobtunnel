package control

import (
	"errors"
	"testing"
)

// TestForeignNamesAreNotReportedAsCertificateProblems covers the error that made
// an operator ask whether their server had been taken over: a scanner connecting
// to port 443 with somebody else's name produced "no managed certificate for
// sneakprofile.com". Nothing was issued for it - the host policy refuses names
// that are not published here - and there is nothing to fix, so it must not be
// reported.
func TestForeignNamesAreNotReportedAsCertificateProblems(t *testing.T) {
	for _, err := range []error{
		errors.New("acme/autocert: no https resource is published for sneakprofile.com"),
		errors.New("acme/autocert: missing server name"),
	} {
		if worthReporting("sneakprofile.com", err) {
			t.Fatalf("%v is not the operator's problem", err)
		}
	}
	if worthReporting("", errors.New("no https resource is published for x.example.com")) {
		t.Fatal("a handshake without a server name is not a certificate problem")
	}
	// A name that is published here and could not be issued is worth reporting,
	// because the operator can act on it.
	published := errors.New("acme: could not complete the challenge: connection refused on port 80")
	if !worthReporting("app.example.com", published) {
		t.Fatal("a failing challenge for a published name has to be reported")
	}
}
