package control

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proxy"
	bolt "go.etcd.io/bbolt"
)

// requestLogSize bounds how many individual requests are kept.
const requestLogSize = 10_000

var requestBucket = []byte("requests")

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
	// Target is the backend this request reached.
	Target string `json:"target,omitempty"`
	// DurationMs is how long the control node spent on the request, tunnel and
	// service included.
	DurationMs int64 `json:"durationMs,omitempty"`
	// DialMs is how long connecting to that backend took. It is what tells a slow
	// tunnel apart from a slow service: seconds to connect is the path, milliseconds
	// to connect followed by a slow answer is the service.
	DialMs     int64 `json:"dialMs,omitempty"`
	PolicyMs   int64 `json:"policyMs,omitempty"`
	QueueMs    int64 `json:"queueMs,omitempty"`
	BackendMs  int64 `json:"backendMs,omitempty"`
	ReusedConn bool  `json:"reusedConn,omitempty"`
	HeaderMs   int64 `json:"headerMs,omitempty"`
	TransferMs int64 `json:"transferMs,omitempty"`
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
	// countries makes the country consistent for every row from an address,
	// even if one proxy path did not have a lookup result on that request.
	countries map[string]string
	summary   RequestSummary
	// durationSumMs and timed count the requests that carried a duration, so the
	// average stays meaningful.
	durationSumMs int64
	timed         int64
	db            *bolt.DB
	dbCount       int
	pending       []RequestEntry
	dirty         chan struct{}
	stop          chan struct{}
	done          chan struct{}
	closeOnce     sync.Once
	lastSaveError error
}

type requestLogDisk struct {
	Entries       []RequestEntry          `json:"entries"`
	ByCountry     map[string]*CountryStat `json:"byCountry"`
	ByHost        map[string]*CountryStat `json:"byHost"`
	Countries     map[string]string       `json:"countries"`
	Summary       RequestSummary          `json:"summary"`
	DurationSumMs int64                   `json:"durationSumMs"`
	Timed         int64                   `json:"timed"`
}

func newRequestLog(paths ...string) *requestLog {
	l := &requestLog{
		byCountry: map[string]*CountryStat{},
		byHost:    map[string]*CountryStat{},
		countries: map[string]string{},
	}
	if len(paths) == 0 || paths[0] == "" {
		return l
	}
	if err := l.open(paths[0]); err != nil {
		l.lastSaveError = err
		return l
	}
	l.dirty = make(chan struct{}, 1)
	l.stop = make(chan struct{})
	l.done = make(chan struct{})
	go l.persistLoop()
	return l
}

func (l *requestLog) open(path string) error {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("open request database: %w", err)
	}
	l.db = db
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(requestBucket)
		return err
	}); err != nil {
		_ = db.Close()
		l.db = nil
		return fmt.Errorf("prepare request database: %w", err)
	}
	legacy := strings.TrimSuffix(path, filepath.Ext(path)) + ".json"
	if err := l.migrateJSON(legacy); err != nil {
		_ = db.Close()
		l.db = nil
		return err
	}
	if err := l.loadDatabase(); err != nil {
		_ = db.Close()
		l.db = nil
		return err
	}
	return nil
}

// migrateJSON imports the one-file store used by the first persistent request
// log release. A successful migration keeps a recoverable .migrated copy.
func (l *requestLog) migrateJSON(path string) error {
	empty := false
	if err := l.db.View(func(tx *bolt.Tx) error {
		empty = tx.Bucket(requestBucket).Stats().KeyN == 0
		return nil
	}); err != nil || !empty {
		return err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read legacy request log: %w", err)
	}
	var disk requestLogDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return fmt.Errorf("parse legacy request log: %w", err)
	}
	entries := disk.Entries
	if len(entries) > requestLogSize {
		entries = entries[:requestLogSize]
	}
	if err := l.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(requestBucket)
		// The old file is newest-first; insert oldest-first so Bolt's sequence
		// order remains chronological.
		for index := len(entries) - 1; index >= 0; index-- {
			value, err := json.Marshal(entries[index])
			if err != nil {
				return err
			}
			sequence, err := bucket.NextSequence()
			if err != nil {
				return err
			}
			var key [8]byte
			binary.BigEndian.PutUint64(key[:], sequence)
			if err := bucket.Put(key[:], value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("migrate request log: %w", err)
	}
	_ = os.Rename(path, path+".migrated")
	return nil
}

func (l *requestLog) loadDatabase() error {
	var entries []RequestEntry
	err := l.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(requestBucket)
		l.dbCount = bucket.Stats().KeyN
		cursor := bucket.Cursor()
		for _, value := cursor.Last(); value != nil && len(entries) < requestLogSize; _, value = cursor.Prev() {
			var entry RequestEntry
			if err := json.Unmarshal(value, &entry); err != nil {
				return fmt.Errorf("decode request: %w", err)
			}
			entries = append(entries, entry)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("load request database: %w", err)
	}
	// Learn every available answer first, then fill blank rows from the same IP.
	for _, entry := range entries {
		if entry.Country != "" && entry.Country != "local" && entry.IP != "" {
			l.countries[entry.IP] = entry.Country
		}
	}
	for index := range entries {
		entry := &entries[index]
		if entry.Country == "" {
			if isPrivateClient(entry.IP) {
				entry.Country = "local"
			} else {
				entry.Country = l.countries[entry.IP]
			}
		}
		l.restoreSummary(*entry)
	}
	l.entries = entries
	return nil
}

func (l *requestLog) restoreSummary(entry RequestEntry) {
	l.summary.Total++
	if entry.Allowed {
		l.summary.Allowed++
	} else {
		l.summary.Blocked++
	}
	if entry.DurationMs > 0 || entry.Status > 0 {
		l.durationSumMs += entry.DurationMs
		l.timed++
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
		Target:     event.Target,
		DurationMs: event.DurationMs,
		DialMs:     event.DialMs,
		PolicyMs:   event.PolicyMs,
		QueueMs:    event.QueueMs,
		BackendMs:  event.BackendMs,
		ReusedConn: event.ReusedConn,
		HeaderMs:   event.HeaderMs,
		TransferMs: event.TransferMs,
	}
	l.mu.Lock()

	// A request from this machine or from a private address has no country to look
	// up, and calling that "unknown" hides the addresses the IP API really did not
	// answer for. A public address the API did not answer for keeps an empty
	// country, so the UI can say why instead of guessing.
	if entry.Country == "" && isPrivateClient(entry.IP) {
		entry.Country = "local"
	}
	if entry.Country == "" {
		entry.Country = l.countries[entry.IP]
	} else if entry.Country != "local" && entry.IP != "" {
		l.countries[entry.IP] = entry.Country
	}
	// The API answers when it answers: a lookup that was too slow for one request
	// still resolves the address, and every earlier request from it should show the
	// country once it is known. Otherwise the same address reads as a country at
	// the top of the list and as unknown further down.
	if entry.Country != "" && entry.Country != "local" {
		for index := range l.entries {
			older := &l.entries[index]
			if older.IP != entry.IP || older.Country != "" {
				continue
			}
			older.Country = entry.Country
			// The counters move with it, so the charts and the list keep telling
			// the same story.
			l.moveFromUnknownLocked(entry.Country, older.Allowed)
		}
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
	if l.db != nil {
		l.pending = append(l.pending, entry)
	}
	l.mu.Unlock()
	l.markDirty()
}

func (l *requestLog) markDirty() {
	if l.dirty == nil {
		return
	}
	select {
	case l.dirty <- struct{}{}:
	default:
	}
}

// persistLoop coalesces bursts so request logging never waits on disk I/O.
func (l *requestLog) persistLoop() {
	defer close(l.done)
	for {
		select {
		case <-l.dirty:
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-timer.C:
				l.save()
			case <-l.stop:
				if !timer.Stop() {
					<-timer.C
				}
				l.save()
				return
			}
		case <-l.stop:
			l.save()
			return
		}
	}
}

func (l *requestLog) save() {
	if l.db == nil {
		return
	}
	l.mu.Lock()
	if len(l.pending) == 0 {
		l.mu.Unlock()
		return
	}
	pending := append([]RequestEntry(nil), l.pending...)
	count := l.dbCount
	l.mu.Unlock()
	err := l.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(requestBucket)
		for _, entry := range pending {
			raw, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			sequence, err := bucket.NextSequence()
			if err != nil {
				return err
			}
			var key [8]byte
			binary.BigEndian.PutUint64(key[:], sequence)
			if err := bucket.Put(key[:], raw); err != nil {
				return err
			}
			count++
		}
		cursor := bucket.Cursor()
		for count > requestLogSize {
			key, _ := cursor.First()
			if key == nil {
				break
			}
			if err := cursor.Delete(); err != nil {
				return err
			}
			count--
		}
		return nil
	})
	l.mu.Lock()
	l.lastSaveError = err
	if err == nil {
		l.pending = l.pending[len(pending):]
		l.dbCount = count
	}
	l.mu.Unlock()
}

func (l *requestLog) close() {
	if l.stop == nil {
		return
	}
	l.closeOnce.Do(func() {
		close(l.stop)
		<-l.done
		if err := l.db.Close(); err != nil {
			l.mu.Lock()
			l.lastSaveError = err
			l.mu.Unlock()
		}
	})
}

func (l *requestLog) persistenceError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastSaveError
}

// moveFromUnknownLocked moves one request from the unknown count to a country,
// which is what happens to an entry whose address the API has now answered for.
func (l *requestLog) moveFromUnknownLocked(country string, allowed bool) {
	if l.summary.Unknown > 0 {
		l.summary.Unknown--
	}
	if stat, ok := l.byCountry["unknown"]; ok {
		stat.Total--
		if !allowed {
			stat.Blocked--
		}
		if stat.Total <= 0 {
			delete(l.byCountry, "unknown")
		}
	}
	bump(l.byCountry, country, allowed)
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
