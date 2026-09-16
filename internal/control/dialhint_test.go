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
	for _, want := range []string{"tcpdump -ni noobtun port 4700", "NAT"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("the hint should mention %q: %s", want, hint)
		}
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
