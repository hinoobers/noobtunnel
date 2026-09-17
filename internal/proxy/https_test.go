package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
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

func TestIdentityLoginFormRedirectsAndHidesTheSessionFromBackend(t *testing.T) {
	var backendCookie, backendAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCookie = r.Header.Get("Cookie")
		backendAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "private-service")
	}))
	t.Cleanup(backend.Close)
	host, port := hostPort(strings.TrimPrefix(backend.URL, "http://"))
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.IdentitySession = func(r *http.Request) (string, bool) {
		cookie, err := r.Cookie("noobtunnel_session")
		return "sam", err == nil && cookie.Value == "signed"
	}
	m.IdentityLogin = func(w http.ResponseWriter, _ *http.Request, username, password string) (string, error) {
		if username != "sam" || password != "secret-password" {
			return "", fmt.Errorf("incorrect username or password")
		}
		http.SetCookie(w, &http.Cookie{Name: "noobtunnel_session", Value: "signed", Path: "/", HttpOnly: true})
		return username, nil
	}
	spec := testSpec(1, ProtoHTTP, host, port, listenPort)
	spec.Domain = "private.example.com"
	spec.Identity = true
	spec.IdentityMode = "login"
	m.Reconcile([]Spec{spec})

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 5 * time.Second, Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		req.Host = "private.example.com"
		return nil
	}}
	base := fmt.Sprintf("http://127.0.0.1:%d", listenPort)
	request := func(method, path string, body io.Reader) *http.Response {
		req, err := http.NewRequest(method, base+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "private.example.com"
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	response := request(http.MethodGet, "/dashboard", nil)
	page, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(page), "Sign in to continue") {
		t.Fatalf("anonymous request did not get the login form: %d %s", response.StatusCode, page)
	}
	form := url.Values{"username": {"sam"}, "password": {"secret-password"}, "next": {"/dashboard"}}
	response = request(http.MethodPost, identityLoginPath, strings.NewReader(form.Encode()))
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "private-service" {
		t.Fatalf("login did not continue to the resource: %d %s", response.StatusCode, body)
	}
	if backendCookie != "" || backendAuth != "" {
		t.Fatalf("proxy credentials leaked to backend: cookie=%q authorization=%q", backendCookie, backendAuth)
	}
}
