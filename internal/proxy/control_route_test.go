package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestControlNodeIsPublishedOnTheSharedHTTPSPort covers --domain: the control
// node's own UI answers on its hostname over the shared HTTPS port, in the same
// listener that publishes resources, and without a backend to dial.
func TestControlNodeIsPublishedOnTheSharedHTTPSPort(t *testing.T) {
	listenPort := freePort(t)
	backend := httptestServer(t, "service-behind-tls")
	host, port := hostPort(backend)

	m := New(quiet())
	defer m.Close()
	m.Certificates = NewSelfSignedProvider()
	m.ControlDomain = "control.example.com"
	m.ControlPort = listenPort
	m.ControlBindAddr = "127.0.0.1"
	m.ControlHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "control node:"+r.URL.Path)
	})

	spec := testSpec(1, ProtoHTTPS, host, port, listenPort)
	spec.Domain = "app.example.com"
	m.Reconcile([]Spec{spec})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", listenPort))
			},
		},
	}
	get := func(name, path string) (int, string) {
		t.Helper()
		client.Transport.(*http.Transport).TLSClientConfig.ServerName = name
		request, err := http.NewRequest("GET", "https://"+name+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("request for %s failed: %v", name, err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, strings.TrimSpace(string(body))
	}

	// The control node answers on its own name: no target, no dial.
	if status, body := get("control.example.com", "/settings"); status != http.StatusOK || body != "control node:/settings" {
		t.Fatalf("control node route = %d %q", status, body)
	}
	// A published resource sharing the port still reaches its service.
	if status, body := get("app.example.com", "/"); status != http.StatusOK || body != "service-behind-tls" {
		t.Fatalf("resource route = %d %q", status, body)
	}
	// Anything else still gets the readable "not published" answer.
	if status, body := get("typo.example.com", "/"); status != http.StatusNotFound || !strings.Contains(body, "no resource is published") {
		t.Fatalf("unknown host = %d %q", status, body)
	}
}

// TestWithoutADomainTheControlNodeIsNotPublished checks the route stays off
// unless a domain is configured, so existing setups are untouched.
func TestWithoutADomainTheControlNodeIsNotPublished(t *testing.T) {
	m := New(quiet())
	defer m.Close()
	m.Certificates = NewSelfSignedProvider()
	m.ControlHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "control node")
	})
	m.Reconcile(nil)

	if len(m.groups) != 0 {
		t.Fatalf("no listener should be started without a domain, got %d", len(m.groups))
	}
}
