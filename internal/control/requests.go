package control

import (
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proxy"
)

// requestLogSize bounds how many individual requests are kept.
const requestLogSize = 400

// RequestEntry is one logged request for the Logs tab.
type RequestEntry struct {
	Time     string `json:"time"`
	Resource string `json:"resource"`
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Country  string `json:"country,omitempty"`
	Account  string `json:"account,omitempty"`
	Protocol string `json:"protocol"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`
	Status   int    `json:"status,omitempty"`
	Path     string `json:"path,omitempty"`
	// DurationMs is how long the control node spent on the request, tunnel and
	// service included.
	DurationMs int64 `json:"durationMs,omitempty"`
}

// CountryStat aggregates requests by country or hostname.
type CountryStat struct {
	Country string `json:"country"`
	Total   int    `json:"total"`
	Blocked int    `json:"blocked"`
}

// RequestSummary is the aggregate view of recent traffic.
type RequestSummary struct {
	Total   int `json:"total"`
	Blocked int `json:"blocked"`
	Allowed int `json:"allowed"`
	Unknown int `json:"unknown"`
	// AvgMs is the average time the control node spent per request, which is the
	// number that shows a slow tunnel or a slow service.
	AvgMs     int           `json:"avgMs,omitempty"`
	Countries []CountryStat `json:"countries"`
	Hosts     []CountryStat `json:"hosts"`
}

// requestLog keeps recent requests and running counters. The counters are capped
// so a long running node cannot grow without bound.
type requestLog struct {
	mu        sync.Mutex
	entries   []RequestEntry
	byCountry map[string]*CountryStat
	byHost    map[string]*CountryStat
	summary   RequestSummary
	// durationSumMs and timed count the requests that carried a duration, so the
	// average stays meaningful.
	durationSumMs int64
	timed         int64
}

func newRequestLog() *requestLog {
	return &requestLog{
		byCountry: map[string]*CountryStat{},
		byHost:    map[string]*CountryStat{},
	}
}

// record adds one request.
func (l *requestLog) record(event proxy.RequestEvent) {
	entry := RequestEntry{
		Time:       event.Time.UTC().Format(time.RFC3339),
		Resource:   event.Resource,
		Host:       event.Host,
		IP:         event.IPText,
		Country:    event.Country,
		Account:    event.Account,
		Protocol:   event.Protocol,
		Allowed:    event.Allowed,
		Reason:     event.Reason,
		Status:     event.Status,
		Path:       event.Path,
		DurationMs: event.DurationMs,
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	// A request from this machine or from a private address has no country to look
	// up, and calling that "unknown" hides the addresses the IP API really did not
	// answer for. A public address the API did not answer for keeps an empty
	// country, so the UI can say why instead of guessing.
	if entry.Country == "" && isPrivateClient(entry.IP) {
		entry.Country = "local"
	}
	l.entries = append([]RequestEntry{entry}, l.entries...)
	if len(l.entries) > requestLogSize {
		l.entries = l.entries[:requestLogSize]
	}
	l.summary.Total++
	if entry.DurationMs > 0 || event.Status > 0 {
		l.durationSumMs += entry.DurationMs
		l.timed++
	}
	if entry.Allowed {
		l.summary.Allowed++
	} else {
		l.summary.Blocked++
	}
	country := entry.Country
	if country == "" {
		country = "unknown"
		l.summary.Unknown++
	}
	bump(l.byCountry, country, entry.Allowed)
	host := entry.Host
	if host == "" {
		host = "(no host)"
	}
	bump(l.byHost, host, entry.Allowed)
}

// isPrivateClient reports whether an address belongs to a network that has no
// country: loopback, link-local, or one of the private ranges.
func isPrivateClient(raw string) bool {
	host := raw
	if parsed, err := netip.ParseAddr(raw); err == nil {
		host = parsed.Unmap().String()
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || !addr.IsGlobalUnicast()
}

func bump(counters map[string]*CountryStat, key string, allowed bool) {
	stat, ok := counters[key]
	if !ok {
		stat = &CountryStat{Country: key}
		counters[key] = stat
	}
	stat.Total++
	if !allowed {
		stat.Blocked++
	}
}

// snapshot returns the aggregates and the most recent requests.
func (l *requestLog) snapshot() (RequestSummary, []RequestEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	summary := l.summary
	if l.timed > 0 {
		summary.AvgMs = int(l.durationSumMs / l.timed)
	}
	summary.Countries = topCounters(l.byCountry, 12)
	summary.Hosts = topCounters(l.byHost, 8)
	entries := append([]RequestEntry(nil), l.entries...)
	if len(entries) > 200 {
		entries = entries[:200]
	}
	return summary, entries
}

// topCounters sorts aggregates and keeps the busiest entries.
func topCounters(counters map[string]*CountryStat, limit int) []CountryStat {
	out := make([]CountryStat, 0, len(counters))
	for _, stat := range counters {
		out = append(out, *stat)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Country < out[j].Country
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// handleRequests serves the request log on its own, for scripts and the UI.
func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) {
	summary, entries := s.requests.snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "requests": entries})
}

// requestSummaryView is what the dashboard shows: aggregates plus recent rows.
func (s *Server) requestSummaryView() map[string]any {
	summary, entries := s.requests.snapshot()
	return map[string]any{"summary": summary, "recent": entries}
}
