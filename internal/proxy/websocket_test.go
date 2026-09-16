package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// upgradeServer speaks just enough of the upgrade dance: it answers 101 and then
// echoes everything it receives, which is what a WebSocket endpoint does until
// somebody speaks the protocol on top.
func upgradeServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpgrade(r) {
			http.Error(w, "not an upgrade", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacking", http.StatusInternalServerError)
			return
		}
		conn, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = buffered.Flush()
		_, _ = io.Copy(conn, conn)
	})}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return ln.Addr().String(), func() { _ = server.Close() }
}

// TestWebSocketUpgradePassesThrough covers the report "websockets are not
// supported": an HTTP or HTTPS resource has to turn a 101 into a real tunnel
// between the client and the service, in both directions.
func TestWebSocketUpgradePassesThrough(t *testing.T) {
	backend, stop := upgradeServer(t)
	defer stop()
	host, port := hostPort(backend)
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	spec := testSpec(1, ProtoHTTP, host, port, listenPort)
	spec.Domain = "chat.example.com"
	spec.WebSockets = true
	m.Reconcile([]Spec{spec})

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	request := "GET /socket HTTP/1.1\r\nHost: chat.example.com\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("expected a 101 handshake, got %q", status)
	}
	// Read the rest of the handshake headers.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	// Now the socket has to be a two way stream.
	if _, err := conn.Write([]byte("ping-over-websocket")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("ping-over-websocket"))
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatalf("no answer through the upgraded connection: %v", err)
	}
	if string(reply) != "ping-over-websocket" {
		t.Fatalf("the tunnel echoed %q", reply)
	}
	// And in the other direction: the service can push without being asked.
	if _, err := conn.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	again := make([]byte, 4)
	if _, err := io.ReadFull(reader, again); err != nil {
		t.Fatalf("the second frame did not come back: %v", err)
	}
	if string(again) != "more" {
		t.Fatalf("the tunnel echoed %q on the second frame", again)
	}
}

// TestWebSocketsCanBeTurnedOff keeps the toggle honest: a resource that disables
// them answers the upgrade with a readable refusal instead of a broken socket.
func TestWebSocketsCanBeTurnedOff(t *testing.T) {
	backend, stop := upgradeServer(t)
	defer stop()
	host, port := hostPort(backend)
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	spec := testSpec(2, ProtoHTTP, host, port, listenPort)
	spec.Domain = "chat.example.com"
	spec.WebSockets = false
	m.Reconcile([]Spec{spec})

	request, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/socket", listenPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The resource is routed by domain, so the request has to carry it.
	request.Host = "chat.example.com"
	// And it has to be an actual upgrade request.
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusNotImplemented {
		t.Fatalf("a disabled upgrade should be refused, got %d %q", response.StatusCode, body)
	}
	if !strings.Contains(string(body), "websockets are disabled") {
		t.Fatalf("the refusal should say why: %q", body)
	}
}
