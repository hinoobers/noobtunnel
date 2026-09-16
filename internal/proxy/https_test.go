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

// TestHTTPSResourceTerminatesTLS proves the control node serves its own
// certificate and proxies to the service over plain HTTP.
func TestHTTPSResourceTerminatesTLS(t *testing.T) {
	backend := httptestServer(t, "service-behind-tls")
	host, port := hostPort(backend)
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.Certificates = NewSelfSignedProvider()
	spec := testSpec(1, ProtoHTTPS, host, port, listenPort)
	spec.Domain = "app.example.com"
	m.Reconcile([]Spec{spec})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.com"},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", listenPort))
			},
		},
	}
	request, err := http.NewRequest("GET", "https://app.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "service-behind-tls" {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
	// The certificate belongs to the published domain and was issued by us.
	state := response.TLS
	if state == nil || len(state.PeerCertificates) == 0 {
		t.Fatal("no server certificate was presented")
	}
	leaf := state.PeerCertificates[0]
	if leaf.Subject.CommonName != "app.example.com" {
		t.Fatalf("certificate common name = %q", leaf.Subject.CommonName)
	}
	if err := leaf.VerifyHostname("app.example.com"); err != nil {
		t.Fatalf("certificate does not cover the domain: %v", err)
	}
}

// TestIdentityControlledResourceRequiresAnAccount covers the per-resource gate.
func TestIdentityControlledResourceRequiresAnAccount(t *testing.T) {
	backend := httptestServer(t, "private-service")
	host, port := hostPort(backend)
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.IdentityCheck = func(username, password string) error {
		if username == "sam" && password == "secret-password" {
			return nil
		}
		return fmt.Errorf("bad credentials")
	}
	spec := testSpec(1, ProtoHTTP, host, port, listenPort)
	spec.Domain = "private.example.com"
	spec.Identity = true
	m.Reconcile([]Spec{spec})

	request := func(user, password string) (int, string) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", listenPort), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "private.example.com"
		if user != "" {
			req.SetBasicAuth(user, password)
		}
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, strings.TrimSpace(string(body))
	}

	if status, body := request("", ""); status != http.StatusUnauthorized {
		t.Fatalf("an anonymous request should be refused, got %d %q", status, body)
	}
	if status, _ := request("sam", "wrong-password"); status != http.StatusUnauthorized {
		t.Fatalf("a wrong password should be refused, got %d", status)
	}
	if status, body := request("sam", "secret-password"); status != http.StatusOK || body != "private-service" {
		t.Fatalf("valid credentials should pass, got %d %q", status, body)
	}
	// The cached success still requires the same credentials.
	if status, _ := request("sam", "secret-password-2"); status != http.StatusUnauthorized {
		t.Fatalf("a different password must not reuse the cache, got %d", status)
	}
}
