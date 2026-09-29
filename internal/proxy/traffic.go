package proxy

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// trafficMeter shares monthly quotas and rate limits across one resource's
// connections and HTTP requests.
type trafficMeter struct {
	mu            sync.Mutex
	month         string
	used          uint64
	requests      uint64
	quota         uint64
	requestQuota  uint64
	sustained     uint64
	burst         uint64
	peak          uint64
	overage       uint64
	tokens        float64
	peakTokens    float64
	instantTokens float64
	last          time.Time
}

type trafficRecord struct {
	Month    string `json:"month"`
	Used     uint64 `json:"used"`
	Requests uint64 `json:"requests,omitempty"`
}

func trafficMonth(now time.Time) string { return now.UTC().Format("2006-01") }

func (m *Manager) SetTrafficStateFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		m.log.Warn("could not load traffic quotas", "error", err)
	}
	records := map[string]trafficRecord{}
	if len(data) > 0 && json.Unmarshal(data, &records) != nil {
		m.log.Warn("could not parse traffic quotas")
	}
	m.mu.Lock()
	m.trafficFile = path
	for rawID, record := range records {
		id, err := strconv.ParseUint(rawID, 10, 32)
		if err != nil {
			continue
		}
		m.meters[uint32(id)] = &trafficMeter{month: record.Month, used: record.Used, requests: record.Requests}
	}
	m.mu.Unlock()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.saveTraffic()
			}
		}
	}()
}

func (m *Manager) meterForLocked(spec Spec) *trafficMeter {
	if !spec.Uncapped && (spec.SustainedBps == 0 || spec.BurstBps == 0) {
		return nil
	}
	meter := m.meters[spec.ID]
	if meter == nil {
		meter = &trafficMeter{}
		m.meters[spec.ID] = meter
	}
	meter.mu.Lock()
	meter.quota, meter.requestQuota, meter.sustained, meter.burst, meter.peak, meter.overage = spec.MonthlyQuotaBytes, spec.MonthlyRequestQuota, spec.SustainedBps, spec.BurstBps, spec.PeakBps, spec.OverQuotaBps
	if meter.overage == 0 {
		meter.overage = meter.sustained
	}
	meter.mu.Unlock()
	return meter
}

// TrafficUsage returns this month's combined inbound and outbound bytes.
func (m *Manager) TrafficUsage(id uint32) uint64 {
	m.mu.Lock()
	meter := m.meters[id]
	m.mu.Unlock()
	if meter == nil {
		return 0
	}
	meter.mu.Lock()
	defer meter.mu.Unlock()
	if meter.month != trafficMonth(time.Now()) {
		return 0
	}
	return meter.used
}

// TrafficRequests returns this month's accepted HTTP requests.
func (m *Manager) TrafficRequests(id uint32) uint64 {
	m.mu.Lock()
	meter := m.meters[id]
	m.mu.Unlock()
	if meter == nil {
		return 0
	}
	meter.mu.Lock()
	defer meter.mu.Unlock()
	if meter.month != trafficMonth(time.Now()) {
		return 0
	}
	return meter.requests
}

func (t *trafficMeter) resetMonthLocked(now time.Time) {
	month := trafficMonth(now)
	if t.month != month {
		t.month, t.used, t.requests = month, 0, 0
		t.tokens, t.peakTokens, t.instantTokens, t.last = 0, 0, 0, time.Time{}
	}
}

// allowRequest reserves one request before it is forwarded to a backend.
func (t *trafficMeter) allowRequest() bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resetMonthLocked(time.Now())
	if t.requestQuota > 0 && t.requests >= t.requestQuota {
		return false
	}
	t.requests++
	return true
}

// take waits for stream traffic; UDP returns false and drops the datagram if
// its aggregate rate has been reached. Tokens are spent on the whole packet.
func (t *trafficMeter) take(n int, wait bool) bool {
	if t == nil || n <= 0 {
		return true
	}
	for {
		t.mu.Lock()
		now := time.Now()
		t.resetMonthLocked(now)
		limited := t.quota > 0 && t.used >= t.quota
		low := float64(t.sustained) / 8
		high := float64(t.burst) / 8
		if limited {
			low = float64(t.overage) / 8
			high = low
		}
		peakRate := float64(t.peak) / 8
		if limited {
			peakRate = low
		}
		if low <= 0 || high <= 0 {
			t.used += uint64(n)
			t.mu.Unlock()
			return true
		}
		// The long bucket refills at the sustained rate. A one-second
		// burst bucket and optional 100 ms peak bucket cap shorter spikes.
		capacity := math.Max(65536, high*10)
		peakCapacity := math.Max(65536, high)
		if limited {
			capacity, peakCapacity = math.Max(16*1024, low*0.05), math.Max(16*1024, low*0.05)
		}
		if t.last.IsZero() {
			t.tokens, t.peakTokens = capacity, peakCapacity
			if t.peak > 0 {
				t.instantTokens = math.Max(65536, peakRate*0.1)
			}
		} else {
			seconds := now.Sub(t.last).Seconds()
			if seconds < 0 {
				seconds = 0
			}
			t.tokens = math.Min(capacity, t.tokens+seconds*low)
			t.peakTokens = math.Min(peakCapacity, t.peakTokens+seconds*high)
			if t.peak > 0 {
				t.instantTokens = math.Min(math.Max(65536, peakRate*0.1), t.instantTokens+seconds*peakRate)
			}
		}
		t.last = now
		need := float64(n)
		if t.tokens >= need && t.peakTokens >= need && (t.peak == 0 || t.instantTokens >= need) {
			t.tokens -= need
			t.peakTokens -= need
			if t.peak > 0 {
				t.instantTokens -= need
			}
			t.used += uint64(n)
			t.mu.Unlock()
			return true
		}
		if !wait {
			t.mu.Unlock()
			return false
		}
		seconds := math.Max((need-t.tokens)/low, (need-t.peakTokens)/high)
		if t.peak > 0 {
			seconds = math.Max(seconds, (need-t.instantTokens)/peakRate)
		}
		t.mu.Unlock()
		if seconds < 0.001 {
			seconds = 0.001
		}
		if seconds > 0.25 {
			seconds = 0.25
		}
		time.Sleep(time.Duration(seconds * float64(time.Second)))
	}
}

type meteredWriter struct {
	io.Writer
	meter *trafficMeter
}

func (w meteredWriter) Write(p []byte) (int, error) {
	if w.meter == nil {
		return w.Writer.Write(p)
	}
	written := 0
	for len(p) > 0 {
		chunk := len(p)
		if chunk > 16*1024 {
			chunk = 16 * 1024
		}
		w.meter.take(chunk, true)
		n, err := w.Writer.Write(p[:chunk])
		written += n
		if err != nil || n != chunk {
			if err == nil {
				err = io.ErrShortWrite
			}
			return written, err
		}
		p = p[chunk:]
	}
	return written, nil
}

func (m *Manager) saveTraffic() {
	m.trafficSaveMu.Lock()
	defer m.trafficSaveMu.Unlock()
	m.mu.Lock()
	path := m.trafficFile
	meters := make(map[uint32]*trafficMeter, len(m.meters))
	for id, meter := range m.meters {
		meters[id] = meter
	}
	m.mu.Unlock()
	if path == "" {
		return
	}
	records := make(map[string]trafficRecord, len(meters))
	for id, meter := range meters {
		meter.mu.Lock()
		records[strconv.FormatUint(uint64(id), 10)] = trafficRecord{Month: meter.month, Used: meter.used, Requests: meter.requests}
		meter.mu.Unlock()
	}
	data, err := json.Marshal(records)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err = os.MkdirAll(filepath.Dir(path), 0700); err == nil {
		err = os.WriteFile(tmp, data, 0600)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		m.log.Warn("could not save traffic quotas", "error", err)
	}
}
