package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestACancelledRequestIsNotATargetFailure covers a resource that alternated
// between "live" and "error" while nothing was wrong with it: the transport dials
// with the request's context, so a browser closing a tab, a health check giving up,
// or the country lookup that runs while a request is served all cancel a dial - and
// every cancellation was written down as "the target is not reachable", with
// "context canceled" as the reason.
func TestACancelledRequestIsNotATargetFailure(t *testing.T) {
	// A service that accepts and then says nothing, so the request ends only when
	// the caller gives up.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			// Held open, never answered.
			_ = conn
		}
	}()
	host, port := hostPort(silent.Addr().String())

	listenPort := freePort(t)
	m := New(quiet())
	defer m.Close()
	spec := testSpec(9, ProtoHTTP, host, port, listenPort)
	spec.Domain = "slow.example.com"
	m.Reconcile([]Spec{spec})

	// The caller gives up after a moment, which is what a cancelled request looks
	// like from the proxy's point of view.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d/", listenPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "slow.example.com"
	resp, err := (&http.Client{}).Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("the request should have been cancelled, got %d", resp.StatusCode)
	}

	// Give the proxy a moment to record whatever it thinks happened.
	time.Sleep(200 * time.Millisecond)
	stats := m.Stats()[9]
	if stats.LastError != "" {
		t.Fatalf("a cancelled request is not a target failure: %q", stats.LastError)
	}
	if target := stats.Targets[1]; target.LastError != "" {
		t.Fatalf("the target should not be marked broken: %q", target.LastError)
	}
}

// TestATargetThatRefusesIsStillReported is the other side of the same rule: a
// service that is genuinely not there has to keep being reported.
func TestATargetThatRefusesIsStillReported(t *testing.T) {
	port := freePort(t) // nothing is listening here
	listenPort := freePort(t)
	m := New(quiet())
	defer m.Close()
	spec := testSpec(10, ProtoHTTP, "127.0.0.1", port, listenPort)
	spec.Domain = "gone.example.com"
	m.Reconcile([]Spec{spec})

	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", listenPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "gone.example.com"
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req); err == nil {
		_ = resp.Body.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Stats()[10].LastError != "" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("a target that is not answering has to be reported")
}
