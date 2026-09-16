package control

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// timeoutError is what net.Dialer returns when nothing answers.
type timeoutError struct{}

func (timeoutError) Error() string   { return "dial tcp 172.18.0.3:4700: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

// TestDialHintNamesTheSilentTimeout covers the failure that sends operators
// hunting for a healthy service: the packet goes out, the answer never comes
// back, and the reason is on the agent's side.
func TestDialHintNamesTheSilentTimeout(t *testing.T) {
	hint := dialHint(timeoutError{}, "172.18.0.3:4700", "172.18.0.3")
	for _, want := range []string{"tcpdump -ni any port 4700", "NAT"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("the hint should mention %q: %s", want, hint)
		}
	}
}

// TestSilentTimeoutDetailIsAnOrderedProcedure checks the thing the operator is
// actually stuck on: the capture has to be started first, and the answer they
// are looking for has to be spelled out before they are asked to go and look.
func TestSilentTimeoutDetailIsAnOrderedProcedure(t *testing.T) {
	detail := silentTimeoutDetail("cassandra", "4700", "noobtun", "10.77.0.0/16")

	capture := strings.Index(detail, "sudo tcpdump -ni any port 4700")
	press := strings.Index(detail, "press Diagnose on this target")
	if capture < 0 || press < 0 {
		t.Fatalf("the procedure needs both the capture and the retry: %s", detail)
	}
	if press < 0 || press > capture {
		t.Fatalf("pressing Diagnose comes first now that it asks the agent: %s", detail)
	}
	// The capture is the manual fallback, and it has to be started before the
	// retry it is supposed to observe.
	if !strings.Contains(detail, "start this on cassandra first") {
		t.Fatalf("the capture is meant to be started before the retry: %s", detail)
	}
	for _, want := range []string{
		"cassandra",
		"sudo tcpdump -ni any port 4700",
		"nothing arrives on noobtun at all",
		"sudo wg show noobtun allowed-ips",
		"sudo iptables -I FORWARD -i noobtun -j ACCEPT",
		"sudo iptables -I FORWARD -o noobtun -j ACCEPT",
		"sudo iptables -t nat -I POSTROUTING -d 10.77.0.0/16 -j RETURN",
		"install.sh --update",
	} {
		if !strings.Contains(detail, want) {
			t.Fatalf("the procedure should mention %q:\n%s", want, detail)
		}
	}

	// Without a mesh range there is no address to insert into POSTROUTING, so
	// that branch says so instead of printing a command that cannot run.
	noMesh := silentTimeoutDetail("cassandra", "4700", "noobtun", "")
	if strings.Contains(noMesh, "-d  -j RETURN") || !strings.Contains(noMesh, "without a mesh range") {
		t.Fatalf("no mesh range should be named, not left blank:\n%s", noMesh)
	}
}

// TestDialHintSeparatesTheOtherFailures keeps the three shapes apart: nothing
// listening is not the same fault as nothing routing.
func TestDialHintSeparatesTheOtherFailures(t *testing.T) {
	refused := dialHint(errors.New("dial tcp 10.77.0.2:4700: connect: connection refused"), "10.77.0.2:4700", "10.77.0.2")
	if !strings.Contains(refused, "nothing is listening") {
		t.Fatalf("a refused connection is the service, not the tunnel: %s", refused)
	}
	noRoute := dialHint(errors.New("dial tcp 10.77.0.2:4700: connect: no route to host"), "10.77.0.2:4700", "10.77.0.2")
	if !strings.Contains(noRoute, "tunnel did not deliver") {
		t.Fatalf("no route to host is the tunnel: %s", noRoute)
	}
	other := dialHint(errors.New("dial tcp 10.77.0.2:4700: something else"), "10.77.0.2:4700", "10.77.0.2")
	if !strings.Contains(other, "check that the service listens") {
		t.Fatalf("an unknown error should fall back to the plain advice: %s", other)
	}
}
