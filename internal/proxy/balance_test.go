package proxy

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// namedTCPService answers with its own name so tests can tell which backend
// served a connection.
func namedTCPService(t *testing.T, name string) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte(name))
			}(conn)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

// connectOnce talks to a published port and returns the backend's answer.
func connectOnce(t *testing.T, port int) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatalf("could not reach the published port: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	return string(buf[:n])
}

func TestRoundRobinSpreadsConnections(t *testing.T) {
	hostA, portA := namedTCPService(t, "a")
	hostB, portB := namedTCPService(t, "b")
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.Reconcile([]Spec{{
		ID: 1, Name: "cluster", Protocol: ProtoTCP, BindAddr: "127.0.0.1",
		ListenPort: listenPort, Enabled: true, Strategy: StrategyRoundRobin,
		Targets: []TargetSpec{
			{ID: 1, Host: hostA, Port: portA},
			{ID: 2, Host: hostB, Port: portB},
		},
	}})

	counts := map[string]int{}
	for i := 0; i < 6; i++ {
		counts[connectOnce(t, listenPort)]++
	}
	if counts["a"] != 3 || counts["b"] != 3 {
		t.Fatalf("round-robin should alternate, got %+v", counts)
	}

	// Both targets are counted separately as well.
	stats := m.Stats()[1]
	if stats.Total != 6 {
		t.Fatalf("resource total = %d, want 6", stats.Total)
	}
	if stats.Targets[1].Total != 3 || stats.Targets[2].Total != 3 {
		t.Fatalf("per-target totals = %+v", stats.Targets)
	}
	if stats.Targets[1].TxBytes == 0 || stats.Targets[2].TxBytes == 0 {
		t.Fatalf("per-target byte counters = %+v", stats.Targets)
	}
}

func TestFailoverUsesTheFirstHealthyTarget(t *testing.T) {
	hostA, portA := namedTCPService(t, "primary")
	hostB, portB := namedTCPService(t, "secondary")
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.Reconcile([]Spec{{
		ID: 1, Name: "failover", Protocol: ProtoTCP, BindAddr: "127.0.0.1",
		ListenPort: listenPort, Enabled: true, Strategy: StrategyFailover,
		Targets: []TargetSpec{
			{ID: 1, Host: hostA, Port: portA},
			{ID: 2, Host: hostB, Port: portB},
		},
	}})

	for i := 0; i < 4; i++ {
		if got := connectOnce(t, listenPort); got != "primary" {
			t.Fatalf("failover should stay on the first target, got %q", got)
		}
	}
	stats := m.Stats()[1]
	if stats.Targets[1].Total != 4 || stats.Targets[2].Total != 0 {
		t.Fatalf("failover totals = %+v", stats.Targets)
	}
}

func TestDeadTargetIsSkippedAndReported(t *testing.T) {
	hostB, portB := namedTCPService(t, "alive")
	deadPort := freePort(t) // nothing listens here
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.Reconcile([]Spec{{
		ID: 1, Name: "mixed", Protocol: ProtoTCP, BindAddr: "127.0.0.1",
		ListenPort: listenPort, Enabled: true, Strategy: StrategyFailover,
		Targets: []TargetSpec{
			{ID: 1, Host: "127.0.0.1", Port: deadPort},
			{ID: 2, Host: hostB, Port: portB},
		},
	}})

	// Traffic still flows through the second target.
	if got := connectOnce(t, listenPort); got != "alive" {
		t.Fatalf("the working target should take over, got %q", got)
	}
	stats := m.Stats()[1]
	if stats.Targets[1].Total != 0 {
		t.Fatalf("the dead target should not be counted as serving: %+v", stats.Targets)
	}
	if !strings.Contains(stats.Targets[1].LastError, "connection") &&
		stats.Targets[1].LastError == "" {
		t.Fatalf("the dead target should report why it failed: %+v", stats.Targets[1])
	}
	if stats.Targets[2].Total != 1 {
		t.Fatalf("the healthy target should have served the connection: %+v", stats.Targets)
	}
}

func TestDisabledTargetIsNotUsed(t *testing.T) {
	hostA, portA := namedTCPService(t, "a")
	listenPort := freePort(t)

	m := New(quiet())
	defer m.Close()
	m.Reconcile([]Spec{{
		ID: 1, Name: "single", Protocol: ProtoTCP, BindAddr: "127.0.0.1",
		ListenPort: listenPort, Enabled: true,
		Targets: []TargetSpec{{ID: 1, Host: hostA, Port: portA}},
	}})
	if got := connectOnce(t, listenPort); got != "a" {
		t.Fatalf("got %q", got)
	}

	// Removing the target must shut the listener's routing down, not fake success.
	spec := Spec{ID: 1, Name: "single", Protocol: ProtoTCP, BindAddr: "127.0.0.1", ListenPort: listenPort, Enabled: true}
	m.Reconcile([]Spec{spec})
	stats := m.Stats()[1]
	if stats.Listening {
		t.Fatalf("a resource without targets must not listen: %+v", stats)
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 500*time.Millisecond); err == nil {
		t.Fatal("the port should be closed once no target remains")
	}
}

func TestDifferentExitNodesUseTheSamePort(t *testing.T) {
	hostA, portA := namedTCPService(t, "a")
	_, portB := namedTCPService(t, "b")

	first := freePort(t)
	second := freePort(t)
	m := New(quiet())
	defer m.Close()
	// Both bind 127.0.0.1 (there is only one address in tests) but different
	// ports, which is what two exit nodes give you in production.
	m.Reconcile([]Spec{
		{ID: 1, Name: "one", Protocol: ProtoTCP, BindAddr: "127.0.0.1", ListenPort: first, Enabled: true,
			Targets: []TargetSpec{{ID: 1, Host: hostA, Port: portA}}},
		{ID: 2, Name: "two", Protocol: ProtoTCP, BindAddr: "127.0.0.1", ListenPort: second, Enabled: true,
			Targets: []TargetSpec{{ID: 1, Host: hostA, Port: portA}}},
	})
	if got := connectOnce(t, first); got != "a" {
		t.Fatalf("first exit node returned %q", got)
	}
	if got := connectOnce(t, second); got != "a" {
		t.Fatalf("second exit node returned %q", got)
	}
	_ = portB
}
