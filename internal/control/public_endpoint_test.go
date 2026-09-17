package control

import (
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// TestPublicEndpointNamesWhatCanBeOpened covers how a published service is
// described: a web resource is a URL, and a tcp or udp service is an address and
// a port with no scheme. A domain on a database used to render as "http://name",
// which is not something anyone can open or connect to.
func TestPublicEndpointNamesWhatCanBeOpened(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resource store.Resource
		want     string
	}{
		{"https with a domain", store.Resource{Protocol: store.ProtocolHTTPS, Domain: "app.example.com"}, "https://app.example.com"},
		{"http with a domain", store.Resource{Protocol: store.ProtocolHTTP, Domain: "app.example.com", ListenPort: 80}, "http://app.example.com"},
		{"http on another port", store.Resource{Protocol: store.ProtocolHTTP, Domain: "app.example.com", ListenPort: 8080}, "http://app.example.com:8080"},
		{"tcp with a domain", store.Resource{Protocol: store.ProtocolTCP, Domain: "db.example.com", ListenPort: 3306}, "db.example.com:3306"},
		{"tcp by address", store.Resource{Protocol: store.ProtocolTCP, ListenPort: 2525}, "203.0.113.9:2525"},
		{"passthrough", store.Resource{Protocol: store.ProtocolHTTPSPassthrough, Domain: "tls.example.com", ListenPort: 443}, "https://tls.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicEndpoint(tc.resource, "", "203.0.113.9"); got != tc.want {
				t.Fatalf("public = %q, want %q", got, tc.want)
			}
		})
	}
	// An exit node address is what a resource with no domain answers on.
	resource := store.Resource{Protocol: store.ProtocolTCP, ListenPort: 2525}
	if got := publicEndpoint(resource, "198.51.100.7", "203.0.113.9"); got != "198.51.100.7:2525" {
		t.Fatalf("the exit node address should be used, got %q", got)
	}
}
