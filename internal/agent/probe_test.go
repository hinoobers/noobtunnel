package agent

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

// probeAgent is an agent that has enrolled, so it has a mesh address to use as
// the source of the second attempt.
func probeAgent(address string) *Agent {
	a := &Agent{
		opts:       Options{Interface: "noobtun"},
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		hostRunner: &fakeHost{},
	}
	a.session = &sessionState{welcome: proto.Welcome{Address: address}}
	return a
}

// TestProbeReportsWhatTheAgentSees covers both halves of the question: a service
// that answers, and one that does not.
func TestProbeReportsWhatTheAgentSees(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	address := ln.Addr().String()

	a := probeAgent("10.77.0.2")
	entry := a.probeOne(address, netip.Addr{})
	if !entry.OK {
		t.Fatalf("the agent should reach its own listener: %+v", entry)
	}
	if entry.LocalAddr == "" {
		t.Fatalf("the source address the agent used should be reported: %+v", entry)
	}
	if entry.Meshed {
		t.Fatalf("a plain attempt is not a meshed one: %+v", entry)
	}

	// The same connection, sourced from the agent's mesh address: this is what a
	// connection arriving through the tunnel looks like to the service.
	meshed := a.probeOne(address, netip.MustParseAddr("127.0.0.1"))
	if !meshed.OK || !meshed.Meshed {
		t.Fatalf("a meshed attempt should be marked and should succeed here: %+v", meshed)
	}
	if meshed.LocalAddr == "" || meshed.LocalAddr[:9] != "127.0.0.1" {
		t.Fatalf("the meshed attempt should use the address it was given: %+v", meshed)
	}
}

// TestProbeReportsAFailedConnection keeps the failure text, which is what makes
// the answer useful: "refused" and "timeout" mean different things.
func TestProbeReportsAFailedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	_ = ln.Close()

	entry := probeAgent("10.77.0.2").probeOne(address, netip.Addr{})
	if entry.OK {
		t.Fatalf("nothing is listening there: %+v", entry)
	}
	if entry.Error == "" {
		t.Fatalf("a failed attempt has to say what went wrong: %+v", entry)
	}
}

// TestProbeTargetIsOnlyHostAndPort keeps the probe from becoming a way to ask an
// agent to resolve names or run anything else.
func TestProbeTargetIsOnlyHostAndPort(t *testing.T) {
	for _, bad := range []string{"", "10.0.0.5", "somewhere.example:80", "10.0.0.5:http", "10.0.0.5:70000"} {
		if validProbeTarget(bad) {
			t.Fatalf("%q should not be probed", bad)
		}
	}
	for _, good := range []string{"10.0.0.5:4700", "192.168.1.9:1", "[::1]:80"} {
		if !validProbeTarget(good) {
			t.Fatalf("%q should be probed", good)
		}
	}
}

// TestProbeAnswersOverTheControlChannel checks the reply actually goes back: the
// control node waits for it, so a probe that never answers looks like an old
// agent instead of a result.
func TestProbeAnswersOverTheControlChannel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	control, agentSide := net.Pipe()
	defer control.Close()
	defer agentSide.Close()

	a := probeAgent("10.77.0.2")
	writer := &connWriter{conn: agentSide}
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.probeTargets(proto.Command{
			T: proto.TCommand, Seq: 7, Action: proto.ActionProbe,
			Targets: []string{ln.Addr().String()},
		}, writer)
	}()

	var result proto.ProbeResult
	if err := proto.ReadJSON(control, &result); err != nil {
		t.Fatal(err)
	}
	<-done
	if result.T != proto.TProbe || result.Seq != 7 {
		t.Fatalf("the answer should carry the request's sequence: %+v", result)
	}
	if len(result.Results) == 0 || !result.Results[0].OK {
		t.Fatalf("the answer should carry the attempt: %+v", result)
	}
}
