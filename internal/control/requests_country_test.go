package control

import (
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proxy"
)

// TestLocalRequestsAreNotCountedAsUnknown covers the table being full of
// "unknown": a request from this machine or from a private address has no country
// to look up, and calling that unknown hides the addresses the IP API really did
// not answer for.
func TestLocalRequestsAreNotCountedAsUnknown(t *testing.T) {
	log := newRequestLog()
	for _, ip := range []string{"127.0.0.1", "10.77.0.1", "192.168.1.20", "172.18.0.1", "::1"} {
		log.record(proxy.RequestEvent{Time: time.Now(), IPText: ip, Allowed: true, Host: "a.example.com"})
	}
	summary, entries := log.snapshot()
	if summary.Unknown != 0 {
		t.Fatalf("a local address is not an unknown country: %+v", summary)
	}
	for _, entry := range entries {
		if entry.Country != "local" {
			t.Fatalf("%s should read as local, got %q", entry.IP, entry.Country)
		}
	}
	// By country, they are grouped as "local" rather than as unknown.
	found := false
	for _, stat := range summary.Countries {
		if stat.Country == "local" {
			found = true
		}
		if stat.Country == "unknown" {
			t.Fatalf("nothing should be unknown here: %+v", summary.Countries)
		}
	}
	if !found {
		t.Fatalf("local requests should be grouped: %+v", summary.Countries)
	}

	// A public address with no answer is the one that is unknown.
	log.record(proxy.RequestEvent{Time: time.Now(), IPText: "203.0.113.9", Allowed: true})
	summary, entries = log.snapshot()
	if summary.Unknown != 1 {
		t.Fatalf("a public address the API did not answer for is unknown: %+v", summary)
	}
	if entries[0].Country != "" {
		t.Fatalf("the entry keeps the empty country so the UI can explain it, got %q", entries[0].Country)
	}
}
