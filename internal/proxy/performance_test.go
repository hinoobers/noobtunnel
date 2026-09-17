package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/access"
)

func auditProxy(tb testing.TB, handler http.HandlerFunc, targets int) (*httpResource, *resource) {
	tb.Helper()
	backend := httptest.NewServer(handler)
	tb.Cleanup(backend.Close)
	host, port := hostPort(strings.TrimPrefix(backend.URL, "http://"))
	r := &resource{spec: testSpec(1, ProtoHTTP, host, port, 0), stat: &resourceStats{}}
	for i := 1; i < targets; i++ {
		r.spec.Targets = append(r.spec.Targets, TargetSpec{ID: uint32(i + 1), Host: host, Port: port})
	}
	g := &group{manager: New(quiet())}
	g.setTargets([]*resource{r})
	h := newHTTPResource(g, time.Second)
	tb.Cleanup(h.close)
	return h, r
}

func TestHTTPDialOverridePreservesHost(t *testing.T) {
	h, r := auditProxy(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Host != "public.example" {
			t.Errorf("Host = %q", req.Host)
		}
		w.WriteHeader(http.StatusNoContent)
	}, 1)
	r.spec.Targets[0].DialAddr = r.spec.Targets[0].Address()
	r.spec.Targets[0].Host = "service.invalid"
	resp, _, _, err := h.roundTrip(r, httptest.NewRequest("GET", "http://public.example/", nil))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestHTTPHopHeadersAndNonCountryRules(t *testing.T) {
	h, r := auditProxy(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("X-Hop") != "" || req.Header.Get("Connection") != "" {
			t.Error("request hop headers leaked")
		}
		w.Header().Set("Connection", "X-Backend-Hop")
		w.Header().Set("X-Backend-Hop", "secret")
		w.WriteHeader(http.StatusNoContent)
	}, 1)
	r.spec.Rules = []access.Rule{{Field: access.FieldPath, Operator: access.OpIs, Values: []string{"/"}, Action: access.ActionAllow}}
	h.group.manager.CountryOf = func(netip.Addr) string { t.Error("non-country rule waited for GeoIP"); return "" }
	h.group.manager.CountryOfFast = func(netip.Addr) string { return "" }
	req := httptest.NewRequest("GET", "http://test/", nil)
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	if w.Header().Get("X-Backend-Hop") != "" || w.Header().Get("Connection") != "" {
		t.Error("response hop headers leaked")
	}
}

func TestEventStreamFlushesBeforeBackendFinishes(t *testing.T) {
	release := make(chan struct{})
	h, _ := auditProxy(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: ready\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-req.Context().Done():
		}
	}, 1)
	server := httptest.NewServer(h)
	defer server.Close()
	defer close(release)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: ready\n" {
		t.Fatalf("first event = %q, %v", line, err)
	}
}

func TestDomainRoutingUsesMostSpecificSuffix(t *testing.T) {
	outer := &resource{spec: Spec{Domain: "example.com"}}
	inner := &resource{spec: Spec{Domain: "app.example.com"}}
	g := &group{}
	g.setTargets([]*resource{outer, inner})
	for i := 0; i < 100; i++ {
		if got, ok := g.route("child.app.example.com:443"); !ok || got != inner {
			t.Fatal("wrong parent domain")
		}
	}
}

func TestUDPShutdownClosesSessions(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port := hostPort(backend.LocalAddr().String())
	r := &resource{spec: testSpec(1, ProtoUDP, host, port, 0), stat: &resourceStats{}}
	g := &group{proto: ProtoUDP, log: quiet(), packet: pc}
	g.setTargets([]*resource{r})
	done := make(chan struct{})
	go func() { g.serveUDP(pc, time.Second); close(done) }()
	defer g.close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.Write([]byte("test"))
	backend.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := backend.ReadFrom(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	g.close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown hung")
	}
	if got := r.stat.set.active.Load(); got != 0 {
		t.Fatalf("%d sessions leaked", got)
	}
}

func BenchmarkHTTPUpload(b *testing.B) {
	for _, size := range []int{1024, 512 << 10} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			h, r := auditProxy(b, func(w http.ResponseWriter, req *http.Request) {
				_, _ = io.Copy(io.Discard, req.Body)
				w.WriteHeader(http.StatusNoContent)
			}, 1)
			payload := bytes.Repeat([]byte("x"), size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				req := httptest.NewRequest("POST", "http://test/upload", bytes.NewReader(payload))
				resp, _, _, err := h.roundTrip(r, req)
				if err != nil {
					b.Fatal(err)
				}
				_ = resp.Body.Close()
			}
		})
	}
}

func TestLargeUploadsArriveIntact(t *testing.T) {
	for _, targets := range []int{1, 2} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("targets=%d/chunked=%v", targets, chunked), func(t *testing.T) {
				payload := bytes.Repeat([]byte("upload"), maxRetryBody/3)
				h, r := auditProxy(t, func(w http.ResponseWriter, req *http.Request) {
					body, err := io.ReadAll(req.Body)
					if err != nil || !bytes.Equal(body, payload) {
						t.Errorf("upload corrupted: bytes=%d err=%v", len(body), err)
					}
					w.WriteHeader(http.StatusNoContent)
				}, targets)
				req := httptest.NewRequest("POST", "http://test/upload", bytes.NewReader(payload))
				if chunked {
					req.ContentLength = -1
				}
				resp, _, _, err := h.roundTrip(r, req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
			})
		}
	}
}

func TestSingleTargetUploadStartsBeforeClientFinishes(t *testing.T) {
	seen := make(chan struct{})
	h, r := auditProxy(t, func(w http.ResponseWriter, req *http.Request) {
		first := make([]byte, 1)
		if _, err := io.ReadFull(req.Body, first); err != nil {
			return
		}
		close(seen)
		io.Copy(io.Discard, req.Body)
		w.WriteHeader(http.StatusNoContent)
	}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	go func() {
		writer.Write([]byte("a"))
		select {
		case <-seen:
			writer.Write([]byte("b"))
		case <-ctx.Done():
		}
		writer.Close()
	}()
	req := httptest.NewRequest("POST", "http://test/", reader).WithContext(ctx)
	req.ContentLength = 2
	resp, _, _, err := h.roundTrip(r, req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestSmallUploadCanFailOverIntact(t *testing.T) {
	payload := bytes.Repeat([]byte("body"), 1024)
	h, r := auditProxy(t, func(w http.ResponseWriter, req *http.Request) {
		got, err := io.ReadAll(req.Body)
		if err != nil || !bytes.Equal(got, payload) {
			t.Errorf("retry body: %d bytes, %v", len(got), err)
		}
		w.WriteHeader(http.StatusNoContent)
	}, 1)
	r.spec.Strategy = StrategyFailover
	r.spec.Targets = append([]TargetSpec{{ID: 2, Host: "127.0.0.1", Port: freePort(t)}}, r.spec.Targets...)
	resp, chosen, _, err := h.roundTrip(r, httptest.NewRequest("POST", "http://test/", bytes.NewReader(payload)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if chosen.ID != 1 {
		t.Fatalf("wrong backend: %d", chosen.ID)
	}
}
