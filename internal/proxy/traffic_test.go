package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUncappedTrafficStillRecordsUsage(t *testing.T) {
	m := New(nil)
	defer m.Close()
	spec := Spec{ID: 91, Protocol: ProtoHTTP, Uncapped: true}
	m.Reconcile([]Spec{spec})
	meter := m.meters[spec.ID]
	if meter == nil {
		t.Fatal("uncapped resource lost its usage meter")
	}
	for i := 0; i < 100; i++ {
		if !meter.allowRequest() || !meter.take(4096, false) {
			t.Fatal("uncapped resource was throttled")
		}
	}
	if m.TrafficRequests(spec.ID) != 100 || m.TrafficUsage(spec.ID) != 409600 {
		t.Fatalf("usage was not counted: requests=%d bytes=%d", m.TrafficRequests(spec.ID), m.TrafficUsage(spec.ID))
	}
}

func TestHTTPRequestsAndBodiesShareMonthlyLimits(t *testing.T) {
	var hits atomic.Int64
	h, resource := auditProxy(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Write([]byte("reply"))
	}, 1)
	resource.spec.MonthlyRequestQuota = 2
	resource.spec.MonthlyQuotaBytes = 1000
	resource.spec.SustainedBps = 15_000_000
	resource.spec.BurstBps = 30_000_000
	resource.spec.PeakBps = 100_000_000
	resource.spec.OverQuotaBps = 512_000
	resource.traffic = h.group.manager.meterForLocked(resource.spec)
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://test/", strings.NewReader("body")))
		want := http.StatusOK
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("request %d status = %d, want %d", i+1, w.Code, want)
		}
	}
	if hits.Load() != 2 || h.group.manager.TrafficRequests(resource.spec.ID) != 2 {
		t.Fatalf("hits = %d, requests = %d", hits.Load(), h.group.manager.TrafficRequests(resource.spec.ID))
	}
	if got := h.group.manager.TrafficUsage(resource.spec.ID); got != 18 {
		t.Fatalf("combined request and response bytes = %d, want 18", got)
	}
}

func TestHTTPRequestQuotaPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	spec := Spec{ID: 10, Protocol: ProtoHTTP, MonthlyRequestQuota: 1, MonthlyQuotaBytes: 100, SustainedBps: 15_000_000, BurstBps: 30_000_000, PeakBps: 100_000_000, OverQuotaBps: 512_000}
	m := New(nil)
	m.SetTrafficStateFile(path)
	m.Reconcile([]Spec{spec})
	if !m.meters[10].allowRequest() {
		t.Fatal("first request was refused")
	}
	m.Close()
	reloaded := New(nil)
	reloaded.SetTrafficStateFile(path)
	reloaded.Reconcile([]Spec{spec})
	defer reloaded.Close()
	if reloaded.TrafficRequests(10) != 1 || reloaded.meters[10].allowRequest() {
		t.Fatal("request quota did not survive restart")
	}
}

func TestTrafficQuotaPersistsAndSlowsAfterMonthlyLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	spec := Spec{ID: 7, Protocol: ProtoTCP, MonthlyQuotaBytes: 1024, SustainedBps: 30_000_000, BurstBps: 30_000_000, OverQuotaBps: 512_000}
	m := New(nil)
	m.SetTrafficStateFile(path)
	m.Reconcile([]Spec{spec})
	meter := m.meters[7]
	if meter == nil || !meter.take(1024, false) {
		t.Fatal("first packet was refused")
	}
	if got := m.TrafficUsage(7); got != 1024 {
		t.Fatalf("usage = %d", got)
	}
	m.Close()

	reloaded := New(nil)
	reloaded.SetTrafficStateFile(path)
	reloaded.Reconcile([]Spec{spec})
	defer reloaded.Close()
	if got := reloaded.TrafficUsage(7); got != 1024 {
		t.Fatalf("usage after restart = %d", got)
	}
	// A full-size datagram cannot pass at once at the over-quota rate.
	if reloaded.meters[7].take(65536, false) {
		t.Fatal("over-quota burst was accepted")
	}
	// A new UTC calendar month resets usage when traffic arrives.
	meter = reloaded.meters[7]
	meter.mu.Lock()
	meter.month = time.Now().UTC().AddDate(0, -1, 0).Format("2006-01")
	meter.mu.Unlock()
	if !meter.take(1024, false) {
		t.Fatal("new month did not reset quota")
	}
	if got := reloaded.TrafficUsage(7); got != 1024 {
		t.Fatalf("reset usage = %d", got)
	}
}
