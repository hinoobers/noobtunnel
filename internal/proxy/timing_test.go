package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestTheRequestLogSeparatesConnectingFromWaiting covers the number that cannot be
// read from "Took" alone: a slow request spent its time getting to the service or
// waiting for it, and only the two numbers together say which.
func TestTheRequestLogSeparatesConnectingFromWaiting(t *testing.T) {
	// A service that takes a measurable moment to answer, so the two numbers can
	// be told apart.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write([]byte("service"))
	})}
	go func() { _ = server.Serve(backend) }()
	defer func() { _ = server.Close() }()
	host, port := hostPort(backend.Addr().String())
	listenPort := freePort(t)

	events := make(chan RequestEvent, 4)
	m := New(quiet())
	defer m.Close()
	m.OnRequest = func(event RequestEvent) { events <- event }
	spec := testSpec(3, ProtoHTTP, host, port, listenPort)
	spec.Domain = "app.example.com"
	m.Reconcile([]Spec{spec})

	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", listenPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.example.com"
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case event := <-events:
		if !event.Allowed || event.Status != http.StatusOK {
			t.Fatalf("the request should have been served: %+v", event)
		}
		if event.Target == "" {
			t.Fatalf("the event should name the backend: %+v", event)
		}
		if event.DurationMs < 30 {
			t.Fatalf("the service took 30ms, the total should show it: %+v", event)
		}
		if event.DialMs < 0 || event.DialMs > event.DurationMs {
			t.Fatalf("connecting cannot take longer than the whole request: %+v", event)
		}
		if event.HeaderMs < 30 || event.HeaderMs > event.DurationMs {
			t.Fatalf("backend header timing is wrong: %+v", event)
		}
		if event.TransferMs < 20 || event.HeaderMs+event.TransferMs > event.DurationMs+1 {
			t.Fatalf("response transfer timing is wrong: %+v", event)
		}
		// The wait is the service's: the connection itself was to loopback.
		if event.DurationMs-event.DialMs < 30 {
			t.Fatalf("the service's own time should be the difference: %+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no request was observed")
	}

}
