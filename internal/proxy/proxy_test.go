package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// echoServer answers everything it receives, prefixed so tests can tell the two
// directions apart.
func echoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write([]byte("echo:" + string(buf[:n])))
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func hostPort(addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

// testSpec builds a single target resource bound to loopback.
func testSpec(id uint32, protocol, host string, port, listenPort int) Spec {
	return Spec{
		ID: id, Name: protocol, Protocol: protocol, BindAddr: "127.0.0.1",
		ListenPort: listenPort, Enabled: true,
		Targets: []TargetSpec{{ID: 1, Host: host, Port: port}},
	}
}

// readUntil accumulates bytes until want appears or the deadline passes, which
// is what a real service behind a PROXY protocol header does when the header and
// the payload arrive in separate TCP segments.
func readUntil(conn net.Conn, want string, timeout time.Duration) []byte {
	var data []byte
	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	for !strings.Contains(string(data), want) {
		n, err := conn.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			return data
		}
	}
	return data
}

func TestTCPForwardingAndStats(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, port := hostPort(upstream)

	listenPort := freePort(t)
	m := New(quiet())
	defer m.Close()
	m.Reconcile([]Spec{testSpec(1, ProtoTCP, host, port, listenPort)})

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
	if err != nil {
		t.Fatalf("could not reach the published port: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "echo:hello" {
		t.Fatalf("forwarded %q, want %q", got, "echo:hello")
	}

	// Counters must reflect the traffic.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stats := m.Stats()[1]
		if stats.TxBytes >= 5 && stats.RxBytes >= 10 && stats.Total >= 1 && stats.Listening {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("stats did not move: %+v", m.Stats()[1])
}

// TestTCPForwardingSendsProxyProtocolHeaders proves the service behind the
// tunnel sees the real client address.
func TestTCPForwardingSendsProxyProtocolHeaders(t *testing.T) {
	for _, version := range []string{ProxyProtocolV1, ProxyProtocolV2} {
		t.Run(version, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			received := make(chan []byte, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				received <- readUntil(conn, "payload", 5*time.Second)
			}()
			host, port := hostPort(ln.Addr().String())

			listenPort := freePort(t)
			m := New(quiet())
			defer m.Close()
			spec := testSpec(1, ProtoTCP, host, port, listenPort)
			spec.ProxyProtocol = version
			m.Reconcile([]Spec{spec})

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("payload")); err != nil {
				t.Fatal(err)
			}
			select {
			case data := <-received:
				switch version {
				case ProxyProtocolV1:
					if !strings.HasPrefix(string(data), "PROXY TCP4 127.0.0.1 127.0.0.1 ") {
						t.Fatalf("v1 header missing: %q", data)
					}
					if !strings.HasSuffix(string(data), "payload") {
						t.Fatalf("payload should follow the header: %q", data)
					}
				case ProxyProtocolV2:
					if !bytes.HasPrefix(data, signatureV2) {
						t.Fatalf("v2 header missing: %q", data)
					}
					if !bytes.HasSuffix(data, []byte("payload")) {
						t.Fatalf("payload should follow the header: %q", data)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the service never received the connection")
			}
		})
	}
}

// TestHTTPProxyProtocolHeaderIsSent checks the HTTP path too.
func TestHTTPProxyProtocolHeaderIsSent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		received <- string(readUntil(conn, "GET / HTTP/1.1", 5*time.Second))
	}()
	host, port := hostPort(ln.Addr().String())

	listenPort := freePort(t)
	m := New(quiet())
	defer m.Close()
	spec := testSpec(1, ProtoHTTP, host, port, listenPort)
	spec.Domain = "app.example.com"
	spec.ProxyProtocol = ProxyProtocolV1
	m.Reconcile([]Spec{spec})

	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", listenPort), nil)
	req.Host = "app.example.com"
	go func() { _, _ = client.Do(req) }()

	select {
	case data := <-received:
		if !strings.HasPrefix(data, "PROXY TCP4 ") {
			t.Fatalf("the backend should receive a PROXY header first, got %q", data)
		}
		if !strings.Contains(data, "GET / HTTP/1.1") {
			t.Fatalf("the request should follow the header, got %q", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend never received the request")
	}
}

func TestTCPForwardingFailsWhenTheServiceIsDown(t *testing.T) {
	listenPort := freePort(t)
	port := freePort(t) // nothing is listening here
	m := New(quiet())
	defer m.Close()
	m.Reconcile([]Spec{testSpec(7, ProtoTCP, "127.0.0.1", port, listenPort)})

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
	if err != nil {
		t.Fatalf("the listener should still accept: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("anyone home?"))
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the connection to be dropped when the service is down")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Stats()[7].LastError != "" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the failure should be reported in the resource stats")
}

func TestHTTPRoutingByHostHeader(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()

	// A minimal HTTP service behind the tunnel.
	backend := httptestServer(t, "service-a")
	host, port := hostPort(backend)
	_ = upstream

	listenPort := freePort(t)
	m := New(quiet())
	defer m.Close()
	siteA := testSpec(1, ProtoHTTP, host, port, listenPort)
	siteA.Domain = "a.example.com"
	siteB := testSpec(2, ProtoHTTP, host, port, listenPort)
	siteB.Domain = "b.example.com"
	m.Reconcile([]Spec{siteA, siteB})

	client := &http.Client{Timeout: 5 * time.Second}
	request := func(host string) (int, string) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", listenPort), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request for %s failed: %v", host, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(body))
	}

	status, body := request("a.example.com")
	if status != 200 || body != "service-a" {
		t.Fatalf("routing to the service failed: %d %q", status, body)
	}
	// An unknown host must be refused, not silently sent somewhere else.
	status, body = request("typo.example.com")
	if status != http.StatusNotFound || !strings.Contains(body, "no resource is published") {
		t.Fatalf("unknown host should 404, got %d %q", status, body)
	}
	if !strings.Contains(body, "a.example.com") {
		t.Fatalf("the error should list configured domains, got %q", body)
	}
}

// httptestServer runs a tiny HTTP service and returns its address.
func httptestServer(t *testing.T, name string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(name))
	})}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return ln.Addr().String()
}

func TestHTTPSPassthroughRoutesBySNI(t *testing.T) {
	// A TLS service with a certificate for its own name, exactly like the
	// services users run at home.
	cert, err := selfSignedCert("secure.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tlsConn, ok := c.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					_, _ = tlsConn.Write([]byte("hello from behind the tunnel"))
				}
			}(conn)
		}
	}()
	defer ln.Close()
	host, port := hostPort(ln.Addr().String())

	listenPort := freePort(t)
	m := New(quiet())
	defer m.Close()
	secure := testSpec(1, ProtoHTTPSPassthrough, host, port, listenPort)
	secure.Domain = "secure.example.com"
	m.Reconcile([]Spec{secure})

	// The client sees the service's own certificate: TLS was not terminated.
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), &tls.Config{
		ServerName:         "secure.example.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("TLS handshake through the tunnel failed: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; got != "secure.example.com" {
		t.Fatalf("the service certificate should pass through, got %q", got)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "hello from behind the tunnel" {
		t.Fatalf("payload = %q", got)
	}
	// An unknown SNI must be dropped rather than routed somewhere else.
	bad, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), &tls.Config{
		ServerName: "unknown.example.com", InsecureSkipVerify: true,
	})
	if err == nil {
		defer bad.Close()
		_ = bad.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		if _, readErr := bad.Read(buf); readErr == nil {
			t.Fatal("an unknown server name should not be routed")
		}
	}
}

func TestUDPForwarding(t *testing.T) {
	// A UDP echo service.
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = server.WriteTo([]byte("udp:"+string(buf[:n])), addr)
		}
	}()
	host, port := hostPort(server.LocalAddr().String())

	// UDP needs its own free port; freePort only hands out TCP ones.
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenPort := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	m := New(quiet())
	defer m.Close()
	m.Reconcile([]Spec{testSpec(1, ProtoUDP, host, port, listenPort)})

	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no reply through the UDP tunnel: %v", err)
	}
	if got := string(buf[:n]); got != "udp:ping" {
		t.Fatalf("reply = %q", got)
	}
}

func TestReconcileStopsRemovedResourcesAndReportsBindFailures(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, port := hostPort(upstream)
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	spec := testSpec(1, ProtoTCP, host, port, listenPort)
	m.Reconcile([]Spec{spec})
	if !m.Stats()[1].Listening {
		t.Fatal("the resource should be listening")
	}

	// Disabling frees the port.
	spec.Enabled = false
	m.Reconcile([]Spec{spec})
	if m.Stats()[1].Listening {
		t.Fatal("a disabled resource should not listen")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		t.Fatalf("the port should be free after disabling: %v", err)
	}
	_ = ln.Close()

	// A port already taken by something else is reported, not ignored.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	_, blockedPort := hostPort(blocker.Addr().String())
	m.Reconcile([]Spec{testSpec(2, ProtoTCP, host, port, blockedPort)})
	stats := m.Stats()[2]
	if stats.Listening || stats.LastError == "" {
		t.Fatalf("a bind failure should be reported: %+v", stats)
	}
}

func TestConcurrentConnectionsAreCounted(t *testing.T) {
	upstream, stop := echoServer(t)
	defer stop()
	host, port := hostPort(upstream)
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.Reconcile([]Spec{testSpec(1, ProtoTCP, host, port, listenPort)})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = conn.Write([]byte("x"))
			buf := make([]byte, 16)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Read(buf)
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Stats()[1].Total >= 8 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected at least 8 connections, got %+v", m.Stats()[1])
}
