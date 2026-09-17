package control

import (
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proxy"
)

// TestALateAnswerFillsInTheEarlierRequests covers the list disagreeing with
// itself: the IP API answers a moment too late for one request, so that entry has
// no country, and the next request from the same address does. Every earlier entry
// with that address is filled in once the answer arrives.
func TestALateAnswerFillsInTheEarlierRequests(t *testing.T) {
	log := newRequestLog()
	at := time.Now()
	// Two requests while the API was still thinking.
	log.record(proxy.RequestEvent{Time: at, IPText: "203.0.113.9", Allowed: true, Host: "a.example.com"})
	log.record(proxy.RequestEvent{Time: at.Add(time.Second), IPText: "203.0.113.9", Allowed: true, Host: "a.example.com"})
	// And one that finally has an answer.
	log.record(proxy.RequestEvent{Time: at.Add(2 * time.Second), IPText: "203.0.113.9", Country: "EE", Allowed: true, Host: "a.example.com"})

	summary, entries := log.snapshot()
	for _, entry := range entries {
		if entry.Country != "EE" {
			t.Fatalf("every request from that address should read EE: %+v", entry)
		}
	}
	if summary.Unknown != 0 {
		t.Fatalf("nothing is unknown once the answer arrived: %+v", summary)
	}
	found := false
	for _, stat := range summary.Countries {
		if stat.Country == "EE" && stat.Total == 3 {
			found = true
		}
		if stat.Country == "unknown" {
			t.Fatalf("the unknown group should be gone: %+v", summary.Countries)
		}
	}
	if !found {
		t.Fatalf("all three requests belong to EE: %+v", summary.Countries)
	}

	// A different address is untouched, and an address that never gets an answer
	// stays unknown.
	log.record(proxy.RequestEvent{Time: at, IPText: "198.51.100.4", Allowed: true})
	summary, entries = log.snapshot()
	if summary.Unknown != 1 {
		t.Fatalf("the address with no answer is still unknown: %+v", summary)
	}
	if entries[0].Country != "" || entries[1].Country != "EE" {
		t.Fatalf("only the unanswered address is untouched: %+v", entries)
	}
}

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
