package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

func TestForwardPreservesReplyAfterClientHalfClose(t *testing.T) {
	service, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	payload := bytes.Repeat([]byte("reply"), 100000)
	go func() {
		conn, err := service.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
		conn.Write(payload)
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f := &forwarder{target: service.Addr().String(), done: make(chan struct{}), agent: &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	go f.serve(context.Background(), ln)
	defer f.stop()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("request"))
	conn.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("reply truncated: %d bytes, %v", len(got), err)
	}
}

// TestAForwardIsRetriedOnceTheAddressExists covers the failure the operator sees
// as "could not carry a loopback service ... bind: cannot assign requested
// address": the listener is opened before the device has its mesh address. The
// attempt has to be repeated rather than dropped, or the service stays published
// and unreachable.
func TestAForwardIsRetriedOnceTheAddressExists(t *testing.T) {
	service, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	a := &Agent{
		opts:       Options{Interface: "noobtun"},
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		hostRunner: &fakeHost{},
	}
	// An address this machine does not have yet, which is what an agent sees
	// before its device is configured.
	a.session = &sessionState{
		welcome: proto.Welcome{Address: "10.77.0.99"},
		peers:   map[uint32]proto.Peer{},
	}
	port := freeTCPPort(t)
	a.setForwards([]proto.Forward{{Port: port, Target: service.Addr().String()}})
	a.syncForwards(context.Background())
	a.mu.Lock()
	_, carried := a.forwards[port]
	a.mu.Unlock()
	if carried {
		t.Fatal("binding an address this machine does not have should fail")
	}

	// The device comes up, and the next pass carries it.
	a.mu.Lock()
	a.session.welcome.Address = "127.0.0.1"
	a.mu.Unlock()
	a.syncForwards(context.Background())
	a.mu.Lock()
	f, carried := a.forwards[port]
	a.mu.Unlock()
	if !carried {
		t.Fatal("the forward should be retried once the address exists")
	}
	f.stop()
}

// TestLoopbackServiceIsCarriedOnTheMeshAddress covers the case a mesh cannot reach
// by itself: a service that only listens on its machine's loopback. `127.0.0.1`
// means the machine that dials it, so the agent listens on its own mesh address
// and passes the connection through.
func TestLoopbackServiceIsCarriedOnTheMeshAddress(t *testing.T) {
	// The service, exactly as a database bound to localhost would be.
	service, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	go func() {
		for {
			conn, err := service.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32)
				n, _ := c.Read(buf)
				_, _ = c.Write([]byte("db:" + string(buf[:n])))
			}(conn)
		}
	}()

	// The harness has no real mesh interface, so the agent is told its address is
	// loopback: the forward binds there, which is the same code path used with a
	// real mesh address in production.
	host := &fakeHost{}
	a := &Agent{
		opts:       Options{Interface: "noobtun"},
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		hostRunner: host,
	}
	a.session = &sessionState{
		welcome: proto.Welcome{Address: "127.0.0.1"},
		peers:   map[uint32]proto.Peer{},
	}

	port := freeTCPPort(t)
	a.setForwards([]proto.Forward{{Port: port, Target: service.Addr().String()}})
	a.syncForwards(context.Background())
	t.Cleanup(func() {
		a.setForwards(nil)
		a.syncForwards(context.Background())
	})
	a.mu.Lock()
	carried := len(a.forwards)
	a.mu.Unlock()
	if carried != 1 {
		t.Fatalf("the forward should be running, got %d", carried)
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("the forwarded port never accepted a connection: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no answer through the forward: %v", err)
	}
	if got := string(buf[:n]); got != "db:ping" {
		t.Fatalf("forwarded %q, want %q", got, "db:ping")
	}

	// The same forward is kept, not restarted, when the control node repeats it.
	previous := a.forwards[port]
	a.setForwards([]proto.Forward{{Port: port, Target: service.Addr().String()}})
	a.syncForwards(context.Background())
	if a.forwards[port] != previous {
		t.Fatal("an unchanged forward should keep its listener")
	}

	// And stopped when the control node drops it.
	a.setForwards(nil)
	a.syncForwards(context.Background())
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
		t.Fatal("a forward that is no longer wanted should stop listening")
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
