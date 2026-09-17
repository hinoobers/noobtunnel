package control_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// TestHTTPSResourcesAreTerminatedOn443 proves the operator cannot pick a port for
// HTTPS, because the control node answers with its own certificate.
func TestHTTPSResourcesAreTerminatedOn443(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	h.advertise(t, agent.id, "192.168.1.0/24")

	// Without a domain there is nothing to issue a certificate for.
	status, body, _ := h.api("POST", "/api/resources",
		resourceBody("no domain", "https", agent.id, "192.168.1.10", 8123, 0, nil), admin)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "domain") {
		t.Fatalf("an https resource without a domain returned %d: %s", status, body)
	}

	// With a domain the port is forced to 443, whatever the caller asked for.
	status, body, _ = h.api("POST", "/api/resources",
		resourceBody("site", "https", agent.id, "192.168.1.10", 8123, 8443,
			map[string]any{"domain": "site.example.com"}), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing https returned %d: %s", status, body)
	}
	var created struct {
		Resource struct {
			ListenPort int    `json:"listenPort"`
			Public     string `json:"public"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Resource.ListenPort != 443 {
		t.Fatalf("https should always listen on 443, got %d", created.Resource.ListenPort)
	}
	if created.Resource.Public != "https://site.example.com" {
		t.Fatalf("public address = %q", created.Resource.Public)
	}
}

// TestIdentityControlledResourceNeedsAnAccount drives the whole path: a published
// HTTP resource with identity control, reached through the real proxy.
func TestIdentityControlledResourceNeedsAnAccount(t *testing.T) {
	targetHost, targetPort := tcpHTTPEcho(t)
	listenPort := freePort(t)

	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	h.advertise(t, agent.id, targetHost+"/32")
	// This harness has no kernel mesh or running agent forwarder. Place the
	// simulated agent at the local service address so DialAddr is reachable;
	// previously the test passed only because HTTP ignored that override.
	if err := h.server.Store().UpdateAgent(agent.id, func(a *store.Agent) error {
		a.Address = targetHost
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"private", "http", agent.id, targetHost, targetPort, listenPort,
		map[string]any{"identity": true}), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing an identity controlled resource returned %d: %s", status, body)
	}

	call := func(user, password string) (int, string) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", listenPort), nil)
		if err != nil {
			t.Fatal(err)
		}
		if user != "" {
			req.SetBasicAuth(user, password)
		}
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return response.StatusCode, strings.TrimSpace(string(raw))
	}

	if status, _ := call("", ""); status != http.StatusUnauthorized {
		t.Fatalf("anonymous access returned %d, want 401", status)
	}
	if status, _ := call("admin", "wrong-password"); status != http.StatusUnauthorized {
		t.Fatalf("a wrong password returned %d, want 401", status)
	}
	// The seeded admin account works.
	if status, text := call("admin", "correct-horse-battery-staple"); status != http.StatusOK || text != "hello" {
		t.Fatalf("signing in with a real account returned %d %q", status, text)
	}
}

// TestIdentityControlRejectedForTCP keeps the toggle honest.
func TestIdentityControlRejectedForTCP(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	agent := h.enrolledAgent(t, "homelab")
	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"ssh", "tcp", agent.id, h.agentAddress(t, agent.id), 22, freePort(t),
		map[string]any{"identity": true}), admin)
	if status != http.StatusBadRequest {
		t.Fatalf("identity control on a tcp resource returned %d: %s", status, body)
	}
	if !strings.Contains(string(body), "identity") {
		t.Fatalf("the error should explain why: %s", body)
	}
}

// tcpHTTPEcho starts a tiny HTTP service behind the tunnel.
func tcpHTTPEcho(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	})}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
