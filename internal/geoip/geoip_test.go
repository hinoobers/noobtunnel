package geoip

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI answers /checkip the way the documented IP API does, counting how often
// it was asked.
type fakeAPI struct {
	server *httptest.Server
	calls  atomic.Int64
	// status and body let a test make the API fail.
	status int
	body   string
	// delay makes the API slow, which is what the request path has to tolerate.
	delay time.Duration
	// tokens records the Authorization header it was given.
	tokens []string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	fake := &fakeAPI{status: http.StatusOK}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.calls.Add(1)
		if fake.delay > 0 {
			time.Sleep(fake.delay)
		}
		fake.tokens = append(fake.tokens, r.Header.Get("Authorization"))
		if r.URL.Path != "/checkip" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("ip") == "" {
			http.Error(w, "ip is required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fake.status)
		_, _ = w.Write([]byte(fake.body))
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// answer is the response the user's API returns, trimmed to what matters.
const answer = `{
  "cache": "hit",
  "data": {
    "ip": "1.1.1.1",
    "is_tor": false,
    "asns": [{"asn": 13335, "name": "CLOUDFLARENET - Cloudflare, Inc.", "country_code": "US"}],
    "allocation": {"registry": "apnic", "country_code": "AU", "status": "assigned"},
    "abuse": {"abuse_confidence_score": 7, "country_code": "AU", "is_whitelisted": true},
    "security": {
      "hosting": {"detected": true, "confidence": "likely"},
      "proxy": {"detected": false, "type": null}
    }
  }
}`

// TestFailuresAreHandedToTheOperator covers the wiring that puts a broken API where
// every other failure goes: the client reports what went wrong, and the same
// failure twice is not reported twice.
func TestFailuresAreHandedToTheOperator(t *testing.T) {
	fake := newFakeAPI(t)
	fake.status = http.StatusBadGateway
	fake.body = `{"error": "the upstream is down"}`
	api := New(fake.server.URL, "")
	seen := []string{}
	api.OnError = func(err error) { seen = append(seen, err.Error()) }

	ctx := context.Background()
	addr := netip.MustParseAddr("1.1.1.1")
	_, _ = api.Lookup(ctx, addr)
	// The failed answer is remembered, so a retry within the failure window does
	// not ask again and does not report again.
	_, _ = api.Lookup(ctx, addr)
	if len(seen) != 1 {
		t.Fatalf("the failure should be reported once, got %d: %v", len(seen), seen)
	}
	if !strings.Contains(seen[0], "502") {
		t.Fatalf("the report should carry the API's status: %v", seen)
	}

	// A response that is not the documented JSON is reported too, because that is
	// what "unexpected answer" looks like from here.
	fake.status = http.StatusOK
	fake.body = `not json at all`
	if _, err := api.Lookup(ctx, netip.MustParseAddr("1.1.1.2")); err == nil {
		t.Fatal("an unexpected answer has to be an error")
	}
	if len(seen) != 2 || !strings.Contains(seen[1], "not the documented JSON") {
		t.Fatalf("the unexpected answer should be reported: %v", seen)
	}
}

// TestLookupReadsTheDocumentedAnswer covers the fields country rules need, and the
// order they are taken from: the abuse report first, then the allocation, then the
// network's ASN.
func TestLookupReadsTheDocumentedAnswer(t *testing.T) {
	fake := newFakeAPI(t)
	fake.body = answer
	api := New(fake.server.URL, "secret-token")

	info, err := api.Lookup(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Country != "AU" || info.CountryFrom != "abuse" {
		t.Fatalf("country = %q from %q, want AU from the abuse report", info.Country, info.CountryFrom)
	}
	if !info.Hosting || info.Proxy || info.IsTor {
		t.Fatalf("security signals = %+v", info)
	}
	if info.AbuseScore != 7 || !strings.Contains(info.ASN, "CLOUDFLARENET") {
		t.Fatalf("asn/abuse = %+v", info)
	}
	if got := fake.tokens[0]; got != "Bearer secret-token" {
		t.Fatalf("the token should be sent as a bearer token, got %q", got)
	}
}

// TestLookupFallsBackToTheAllocationAndTheASN keeps a country available when the
// API has no abuse record for the address.
func TestLookupFallsBackToTheAllocationAndTheASN(t *testing.T) {
	fake := newFakeAPI(t)
	fake.body = `{"data": {"allocation": {"country_code": "de"}}}`
	api := New(fake.server.URL, "")
	info, err := api.Lookup(context.Background(), netip.MustParseAddr("9.9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Country != "DE" || info.CountryFrom != "allocation" {
		t.Fatalf("country = %q from %q, want DE from the allocation", info.Country, info.CountryFrom)
	}

	fake.body = `{"data": {"asns": [{"asn": 1, "name": "EXAMPLE", "country_code": "se"}]}}`
	other := New(fake.server.URL, "")
	info, err = other.Lookup(context.Background(), netip.MustParseAddr("9.9.9.10"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Country != "SE" || info.CountryFrom != "asn" {
		t.Fatalf("country = %q from %q, want SE from the ASN", info.Country, info.CountryFrom)
	}
}

// TestAnswersAreCached covers what makes this usable at all: the API is asked once
// per address, not once per request, and a decision that needs the answer gets the
// cached one.
func TestAnswersAreCached(t *testing.T) {
	fake := newFakeAPI(t)
	fake.body = answer
	api := New(fake.server.URL, "")
	addr := netip.MustParseAddr("1.1.1.1")
	for i := 0; i < 5; i++ {
		if got := api.CountryForDecision(context.Background(), addr); got != "AU" {
			t.Fatalf("lookup %d answered %q", i, got)
		}
	}
	if got := fake.calls.Load(); got != 1 {
		t.Fatalf("the API should be asked once, it was asked %d times", got)
	}
	// Configuring a different API drops what came from the old one.
	fake.body = `{"data": {"allocation": {"country_code": "FR"}}}`
	api.Configure(fake.server.URL, "other")
	if got := api.CountryForDecision(context.Background(), addr); got != "FR" {
		t.Fatalf("a new configuration should be asked again, got %q", got)
	}
}

// TestTheRequestPathNeverWaitsForTheAPI is the fix for countries taking minutes to
// appear: the answer is wanted while a request is being logged, and a slow lookup
// must not hold that request up. The lookup happens behind the scenes, and the
// answer is there for the next one - and for every earlier entry from the address.
func TestTheRequestPathNeverWaitsForTheAPI(t *testing.T) {
	fake := newFakeAPI(t)
	fake.body = answer
	fake.delay = 300 * time.Millisecond
	api := New(fake.server.URL, "")
	addr := netip.MustParseAddr("1.1.1.1")

	started := time.Now()
	if got := api.Country(addr); got != "" {
		t.Fatalf("nothing is known yet, got %q", got)
	}
	if waited := time.Since(started); waited > 100*time.Millisecond {
		t.Fatalf("the request path waited %s for a lookup", waited)
	}

	// The lookup finishes on its own, and the answer is cached.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := api.Country(addr); got == "AU" {
			if fake.calls.Load() != 1 {
				t.Fatalf("the address should be looked up once, got %d", fake.calls.Load())
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the background lookup never produced an answer")
}

// TestFailuresAreReportedAndRemembered keeps a broken API from being hammered: the
// reason is recorded, and the next request within the failure window does not try
// again.
func TestFailuresAreReportedAndRemembered(t *testing.T) {
	fake := newFakeAPI(t)
	fake.status = http.StatusUnauthorized
	fake.body = `{"error": "token is broken"}`
	api := New(fake.server.URL, "bad-token")

	if _, err := api.Lookup(context.Background(), netip.MustParseAddr("1.1.1.1")); err == nil {
		t.Fatal("a rejected token has to be reported")
	} else if !strings.Contains(err.Error(), "401") {
		t.Fatalf("the error should name the status: %v", err)
	}
	_, _, _, _, lastError := api.Stats()
	if !strings.Contains(lastError, "401") {
		t.Fatalf("the failure should be remembered for the panel: %q", lastError)
	}
	before := fake.calls.Load()
	if got := api.Country(netip.MustParseAddr("1.1.1.1")); got != "" {
		t.Fatalf("a failed lookup has no country, got %q", got)
	}
	if fake.calls.Load() != before {
		t.Fatal("a failure should not be retried on every request")
	}
}

// TestNothingIsAskedWithoutAnAPI keeps country rules inert rather than chatty when
// no API is configured.
func TestNothingIsAskedWithoutAnAPI(t *testing.T) {
	api := New("", "")
	if api.Configured() || api.Ready() {
		t.Fatal("an unconfigured client is neither configured nor ready")
	}
	if _, err := api.Lookup(context.Background(), netip.MustParseAddr("1.1.1.1")); err != ErrNotConfigured {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if got := api.Country(netip.MustParseAddr("1.1.1.1")); got != "" {
		t.Fatalf("no API means no country, got %q", got)
	}
}

// TestHostNormalisation accepts what an operator types: a bare hostname, a URL
// with a scheme and a trailing slash.
func TestHostNormalisation(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"iplog.example.com", "https://iplog.example.com"},
		{"https://iplog.example.com/", "https://iplog.example.com"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"  iplog.example.com  ", "https://iplog.example.com"},
		{"", ""},
	} {
		api := New(tc.in, "")
		host, _, _, _, _ := api.Stats()
		if host != tc.want {
			t.Fatalf("New(%q) host = %q, want %q", tc.in, host, tc.want)
		}
	}
}

// TestTheRequestIsTheDocumentedOne pins the endpoint: <host>/checkip?ip=<address>.
func TestTheRequestIsTheDocumentedOne(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.String()
		var decoded struct {
			Data json.RawMessage `json:"data"`
		}
		_ = decoded
		_, _ = w.Write([]byte(answer))
	}))
	defer server.Close()
	api := New(server.URL, "")
	if _, err := api.Lookup(context.Background(), netip.MustParseAddr("1.1.1.1")); err != nil {
		t.Fatal(err)
	}
	if got != "/checkip?ip=1.1.1.1" {
		t.Fatalf("the request was %q, want /checkip?ip=1.1.1.1", got)
	}
}
