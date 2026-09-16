package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

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
	a.syncForwards(context.Background(), []proto.Forward{
		{Port: port, Target: service.Addr().String()},
	})
	t.Cleanup(func() { a.syncForwards(context.Background(), nil) })
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
	a.syncForwards(context.Background(), []proto.Forward{
		{Port: port, Target: service.Addr().String()},
	})
	if a.forwards[port] != previous {
		t.Fatal("an unchanged forward should keep its listener")
	}

	// And stopped when the control node drops it.
	a.syncForwards(context.Background(), nil)
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
