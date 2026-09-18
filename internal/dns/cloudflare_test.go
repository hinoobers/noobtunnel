package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type testSRV struct {
	Priority int
	Weight   int
	Port     int
	Target   string
}

// fakeAPI is a small stand-in for the Cloudflare API.
type fakeAPI struct {
	mu      sync.Mutex
	records map[string]string
	srv     map[string]testSRV
	// createOK answers a create successfully without storing anything: the case
	// that used to be reported as "in sync" with no record in the zone.
	createOK bool
	requests []string
}

func (f *fakeAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-1","name":"example.com"}]}`))
		case strings.HasSuffix(r.URL.Path, "/dns_records") && r.Method == http.MethodGet:
			name := r.URL.Query().Get("name")
			if r.URL.Query().Get("type") == "SRV" {
				if data, ok := f.srv[name]; ok {
					_, _ = fmt.Fprintf(w, `{"success":true,"result":[{"id":"srv-1","comment":%q,"data":{"priority":%d,"weight":%d,"port":%d,"target":%q}}]}`,
						RecordComment, data.Priority, data.Weight, data.Port, data.Target)
					return
				}
				_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
				return
			}
			if content, ok := f.records[name]; ok {
				_, _ = fmt.Fprintf(w, `{"success":true,"result":[{"id":"rec-1","content":%q,"comment":%q}]}`, content, RecordComment)
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		case strings.HasSuffix(r.URL.Path, "/dns_records") && r.Method == http.MethodPost:
			var body struct {
				Name    string `json:"name"`
				Content string `json:"content"`
				Type    string `json:"type"`
				Data    struct {
					Priority int    `json:"priority"`
					Weight   int    `json:"weight"`
					Port     int    `json:"port"`
					Target   string `json:"target"`
				} `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !f.createOK {
				if body.Type == "SRV" {
					if f.srv == nil {
						f.srv = make(map[string]testSRV)
					}
					f.srv[body.Name] = testSRV{
						Priority: body.Data.Priority, Weight: body.Data.Weight, Port: body.Data.Port, Target: body.Data.Target,
					}
				} else {
					f.records[body.Name] = body.Content
				}
			}
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-new"}}`))
		case strings.Contains(r.URL.Path, "/dns_records/") && r.Method == http.MethodDelete:
			for name := range f.srv {
				delete(f.srv, name)
			}
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case strings.Contains(r.URL.Path, "/dns_records/") && r.Method == http.MethodPut:
			var body struct {
				Name    string `json:"name"`
				Content string `json:"content"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.records[body.Name] = body.Content
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-1"}}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func TestEnsureAndDeleteSRV(t *testing.T) {
	fake := &fakeAPI{records: map[string]string{}, srv: make(map[string]testSRV)}
	c, server := client(fake)
	defer server.Close()
	name := "_minecraft._tcp.play.example.com"
	if err := c.EnsureSRV(context.Background(), name, "play.example.com", 25570, 10, 20); err != nil {
		t.Fatalf("creating SRV failed: %v", err)
	}
	record := fake.srv[name]
	if record.Port != 25570 || record.Priority != 10 || record.Weight != 20 || record.Target != "play.example.com" {
		t.Fatalf("unexpected SRV data: %+v", record)
	}
	if err := c.DeleteSRV(context.Background(), name); err != nil {
		t.Fatalf("deleting SRV failed: %v", err)
	}
	if _, exists := fake.srv[name]; exists {
		t.Fatal("SRV record still exists after deletion")
	}
}

func client(fake *fakeAPI) (*Cloudflare, *httptest.Server) {
	server := httptest.NewServer(fake.handler())
	return &Cloudflare{Token: "test", BaseURL: server.URL, Client: server.Client()}, server
}

// TestEnsureARejectsAnAddressThatIsNotAnIP covers the misconfiguration behind the
// report: the advertised endpoint was the domain itself, so the "address" sent as
// an A record was a hostname. That has to fail with something an operator can act
// on, before any provider call.
func TestEnsureARejectsAnAddressThatIsNotAnIP(t *testing.T) {
	fake := &fakeAPI{records: map[string]string{}}
	c, server := client(fake)
	defer server.Close()
	err := c.EnsureA(context.Background(), "app.example.com", "tunnel.example.com")
	if err == nil || !strings.Contains(err.Error(), "not an IPv4 address") {
		t.Fatalf("expected the address to be refused, got %v", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("nothing should be sent to the provider, sent: %v", fake.requests)
	}
}

// TestEnsureAVerifiesTheRecordExists is the guarantee that "in sync" means the
// record is really there: a provider that answers "created" without keeping the
// record must be reported as a failure.
func TestEnsureAVerifiesTheRecordExists(t *testing.T) {
	fake := &fakeAPI{records: map[string]string{}, createOK: true}
	c, server := client(fake)
	defer server.Close()
	err := c.EnsureA(context.Background(), "app.example.com", "203.0.113.10")
	if err == nil {
		t.Fatal("a record that does not read back must be an error")
	}
	if !strings.Contains(err.Error(), "not there after writing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestEnsureAHandlesWildcardNamesAndUpdates checks the two things that make the
// automation work for the domains operators actually add: the "*." name is sent
// escaped, and an existing record is updated instead of failing.
func TestEnsureAHandlesWildcardNamesAndUpdates(t *testing.T) {
	fake := &fakeAPI{records: map[string]string{"*.example.com": "203.0.113.9"}}
	c, server := client(fake)
	defer server.Close()
	if err := c.EnsureA(context.Background(), "*.example.com", "203.0.113.10"); err != nil {
		t.Fatalf("updating a wildcard record failed: %v", err)
	}
	if got := fake.records["*.example.com"]; got != "203.0.113.10" {
		t.Fatalf("the wildcard record was not updated, it reads %q", got)
	}
	// The lookup has to escape the wildcard, or the provider sees a different
	// query than the record name.
	var escaped bool
	for _, request := range fake.requests {
		if strings.Contains(request, "name=%2A.example.com") {
			escaped = true
		}
	}
	if !escaped {
		t.Fatalf("the wildcard name was not escaped in the lookup: %v", fake.requests)
	}
}

// TestEnsureAIsIdempotent checks a second call with the same address does not
// rewrite the record.
func TestEnsureAIsIdempotent(t *testing.T) {
	fake := &fakeAPI{records: map[string]string{}}
	c, server := client(fake)
	defer server.Close()
	if err := c.EnsureA(context.Background(), "app.example.com", "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	before := len(fake.requests)
	if err := c.EnsureA(context.Background(), "app.example.com", "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	for _, request := range fake.requests[before:] {
		if strings.HasPrefix(request, "POST") || strings.HasPrefix(request, "PUT") {
			t.Fatalf("the record was rewritten although it was already correct: %s", request)
		}
	}
}
