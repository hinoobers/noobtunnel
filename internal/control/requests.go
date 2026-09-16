package control

import (
	"net/http"
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
}

// CountryStat aggregates requests by country or hostname.
type CountryStat struct {
	Country string `json:"country"`
	Total   int    `json:"total"`
	Blocked int    `json:"blocked"`
}

// RequestSummary is the aggregate view of recent traffic.
type RequestSummary struct {
	Total     int           `json:"total"`
	Blocked   int           `json:"blocked"`
	Allowed   int           `json:"allowed"`
	Unknown   int           `json:"unknown"`
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
		Time:     event.Time.UTC().Format(time.RFC3339),
		Resource: event.Resource,
		Host:     event.Host,
		IP:       event.IPText,
		Country:  event.Country,
		Account:  event.Account,
		Protocol: event.Protocol,
		Allowed:  event.Allowed,
		Reason:   event.Reason,
		Status:   event.Status,
		Path:     event.Path,
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append([]RequestEntry{entry}, l.entries...)
	if len(l.entries) > requestLogSize {
		l.entries = l.entries[:requestLogSize]
	}
	l.summary.Total++
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
