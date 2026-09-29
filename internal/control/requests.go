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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proxy"
	bolt "go.etcd.io/bbolt"
)

// requestLiveSize bounds only the rows included in live state snapshots.
const requestLiveSize = 200
const requestPageSize = 30
const requestMaxPageSize = 200

var requestBucket = []byte("requests")
var requestCountryBucket = []byte("request_countries")

// RequestEntry is one logged request for the Logs tab.
type RequestEntry struct {
	Time       string `json:"time"`
	ResourceID uint32 `json:"resourceId,omitempty"`
	Resource   string `json:"resource"`
	Host       string `json:"host"`
	IP         string `json:"ip"`
	Country    string `json:"country,omitempty"`
	Account    string `json:"account,omitempty"`
	Protocol   string `json:"protocol"`
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason,omitempty"`
	Status     int    `json:"status,omitempty"`
	Path       string `json:"path,omitempty"`
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

type unknownRequestCounts struct {
	allowed int
	blocked int
}

// requestLog keeps recent requests in memory and the complete history in Bolt.
type requestLog struct {
	mu        sync.Mutex
	persistMu sync.Mutex
	entries   []RequestEntry
	byCountry map[string]*CountryStat
	byHost    map[string]*CountryStat
	// countries makes the country consistent for every row from an address,
	// even if one proxy path did not have a lookup result on that request.
	countries map[string]string
	// resolved holds country answers that still need to be written to Bolt.
	resolved    map[string]string
	unknownByIP map[string]unknownRequestCounts
	summary     RequestSummary
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
		byCountry:   map[string]*CountryStat{},
		byHost:      map[string]*CountryStat{},
		countries:   map[string]string{},
		resolved:    map[string]string{},
		unknownByIP: map[string]unknownRequestCounts{},
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
		if _, err := tx.CreateBucketIfNotExists(requestBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(requestCountryBucket)
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
	if err := l.restoreMigratedJSON(legacy + ".migrated"); err != nil {
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

// Older installations kept a recoverable copy of the initial JSON log. Rows
// rotated out by the former Bolt cap can be put back at their original keys.
func (l *requestLog) restoreMigratedJSON(path string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var disk requestLogDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return fmt.Errorf("parse migrated request log: %w", err)
	}
	return l.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(requestBucket)
		for index := len(disk.Entries) - 1; index >= 0; index-- {
			var key [8]byte
			binary.BigEndian.PutUint64(key[:], uint64(len(disk.Entries)-index))
			if bucket.Get(key[:]) != nil {
				continue
			}
			value, err := json.Marshal(disk.Entries[index])
			if err != nil {
				return err
			}
			if err := bucket.Put(key[:], value); err != nil {
				return err
			}
		}
		return nil
	})
}

func (l *requestLog) loadDatabase() error {
	var entries []RequestEntry
	err := l.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(requestCountryBucket).ForEach(func(ip, country []byte) error {
			l.countries[string(ip)] = string(country)
			return nil
		}); err != nil {
			return err
		}
		bucket := tx.Bucket(requestBucket)
		l.dbCount = bucket.Stats().KeyN
		cursor := bucket.Cursor()
		for _, value := cursor.First(); value != nil; _, value = cursor.Next() {
			var entry RequestEntry
			if err := json.Unmarshal(value, &entry); err != nil {
				return fmt.Errorf("decode request: %w", err)
			}
			if entry.Country != "" && entry.Country != "local" && entry.IP != "" {
				l.learnCountryLocked(entry.IP, entry.Country)
			} else if entry.Country == "" {
				if isPrivateClient(entry.IP) {
					entry.Country = "local"
				} else {
					entry.Country = l.countries[entry.IP]
				}
			}
			l.restoreSummary(entry)
		}
		for _, value := cursor.Last(); value != nil && len(entries) < requestLiveSize; _, value = cursor.Prev() {
			var entry RequestEntry
			if err := json.Unmarshal(value, &entry); err != nil {
				return fmt.Errorf("decode request: %w", err)
			}
			l.fillCountryLocked(&entry)
			entries = append(entries, entry)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("load request database: %w", err)
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
		counts := l.unknownByIP[entry.IP]
		if entry.Allowed {
			counts.allowed++
		} else {
			counts.blocked++
		}
		l.unknownByIP[entry.IP] = counts
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
		ResourceID: event.ResourceID,
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
	if entry.Country != "" && entry.Country != "local" && entry.IP != "" {
		l.learnCountryLocked(entry.IP, entry.Country)
		l.resolved[entry.IP] = entry.Country
	} else {
		l.fillCountryLocked(&entry)
	}
	l.entries = append([]RequestEntry{entry}, l.entries...)
	if l.db != nil && len(l.entries) > requestLiveSize {
		l.entries = l.entries[:requestLiveSize]
	}
	l.restoreSummary(entry)
	if l.db != nil {
		l.pending = append(l.pending, entry)
	}
	l.mu.Unlock()
	l.markDirty()
}

func (l *requestLog) fillCountryLocked(entry *RequestEntry) {
	if entry.Country != "" {
		return
	}
	if isPrivateClient(entry.IP) {
		entry.Country = "local"
	} else {
		entry.Country = l.countries[entry.IP]
	}
}

func (l *requestLog) learnCountryLocked(ip, country string) {
	l.countries[ip] = country
	if counts, ok := l.unknownByIP[ip]; ok {
		amount := counts.allowed + counts.blocked
		l.summary.Unknown -= amount
		if unknown := l.byCountry["unknown"]; unknown != nil {
			unknown.Total -= amount
			unknown.Blocked -= counts.blocked
			if unknown.Total <= 0 {
				delete(l.byCountry, "unknown")
			}
		}
		stat := l.byCountry[country]
		if stat == nil {
			stat = &CountryStat{Country: country}
			l.byCountry[country] = stat
		}
		stat.Total += amount
		stat.Blocked += counts.blocked
		delete(l.unknownByIP, ip)
	}
	for index := range l.entries {
		if l.entries[index].IP == ip && l.entries[index].Country == "" {
			l.entries[index].Country = country
		}
	}
}

// resolveCountry fills rows from an address as soon as a background lookup
// completes, even when that address never makes another request.
func (l *requestLog) resolveCountry(ip, country string) bool {
	if ip == "" || country == "" || isPrivateClient(ip) {
		return false
	}
	l.mu.Lock()
	counts := l.unknownByIP[ip]
	changed := counts.allowed+counts.blocked > 0
	l.learnCountryLocked(ip, country)
	l.resolved[ip] = country
	l.mu.Unlock()
	l.markDirty()
	return changed
}

// unknownIPs returns recent public addresses that still need a lookup after a
// restart. Limit the number so restoring the log cannot flood the IP API.
func (l *requestLog) unknownIPs(limit int) []netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	seen := make(map[netip.Addr]bool)
	addresses := make([]netip.Addr, 0, limit)
	for _, entry := range l.entries {
		if entry.Country != "" {
			continue
		}
		addr, err := netip.ParseAddr(entry.IP)
		if err != nil || isPrivateClient(entry.IP) || seen[addr] {
			continue
		}
		seen[addr] = true
		addresses = append(addresses, addr)
		if len(addresses) >= limit {
			break
		}
	}
	return addresses
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
	l.persistMu.Lock()
	defer l.persistMu.Unlock()
	l.mu.Lock()
	if len(l.pending) == 0 && len(l.resolved) == 0 {
		l.mu.Unlock()
		return
	}
	pending := append([]RequestEntry(nil), l.pending...)
	resolved := make(map[string]string, len(l.resolved))
	for ip, country := range l.resolved {
		resolved[ip] = country
	}
	count := l.dbCount
	l.mu.Unlock()
	err := l.db.Update(func(tx *bolt.Tx) error {
		countries := tx.Bucket(requestCountryBucket)
		for ip, country := range resolved {
			if err := countries.Put([]byte(ip), []byte(country)); err != nil {
				return err
			}
		}
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
		return nil
	})
	l.mu.Lock()
	l.lastSaveError = err
	if err == nil {
		l.pending = l.pending[len(pending):]
		for ip, country := range resolved {
			if l.resolved[ip] == country {
				delete(l.resolved, ip)
			}
		}
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
	if len(entries) > requestLiveSize {
		entries = entries[:requestLiveSize]
	}
	return summary, entries
}

type requestQuery struct {
	page               int
	limit              int
	sort               string
	direction          string
	filters            map[string][]string
	searches           map[string]string
	allowedResourceIDs map[uint32]bool
}

type requestFacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// requestFacet returns choices from every stored row for one column. Large
// columns are searched on demand so the browser never downloads all clients or
// paths just to open a filter popup.
func (l *requestLog) requestFacet(field, search string, limit int, query requestQuery) ([]requestFacetValue, bool, error) {
	l.persistMu.Lock()
	defer l.persistMu.Unlock()
	l.mu.Lock()
	countries := make(map[string]string, len(l.countries))
	for ip, country := range l.countries {
		countries[ip] = country
	}
	pending := append([]RequestEntry(nil), l.pending...)
	entries := append([]RequestEntry(nil), l.entries...)
	l.mu.Unlock()
	counts := make(map[string]int)
	search = strings.ToLower(search)
	visit := func(entry RequestEntry) {
		if query.allowedResourceIDs != nil && !query.allowedResourceIDs[entry.ResourceID] {
			return
		}
		if entry.Country == "" {
			if isPrivateClient(entry.IP) {
				entry.Country = "local"
			} else {
				entry.Country = countries[entry.IP]
			}
		}
		if !matchesRequest(entry, query) {
			return
		}
		value := requestField(entry, field)
		if value == "" {
			value = "—"
		}
		if search == "" || strings.Contains(strings.ToLower(value), search) {
			counts[value]++
		}
	}
	if l.db == nil {
		for _, entry := range entries {
			visit(entry)
		}
	} else {
		err := l.db.View(func(tx *bolt.Tx) error {
			cursor := tx.Bucket(requestBucket).Cursor()
			for _, value := cursor.First(); value != nil; _, value = cursor.Next() {
				var entry RequestEntry
				if err := json.Unmarshal(value, &entry); err != nil {
					return err
				}
				visit(entry)
			}
			return nil
		})
		if err != nil {
			return nil, false, err
		}
		for _, entry := range pending {
			visit(entry)
		}
	}
	values := make([]requestFacetValue, 0, len(counts))
	for value, count := range counts {
		values = append(values, requestFacetValue{Value: value, Count: count})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Count != values[j].Count {
			return values[i].Count > values[j].Count
		}
		return values[i].Value < values[j].Value
	})
	more := len(values) > limit
	if more {
		values = values[:limit]
	}
	return values, more, nil
}

func (l *requestLog) requestPage(query requestQuery) (RequestSummary, []RequestEntry, int, int, error) {
	l.persistMu.Lock()
	defer l.persistMu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if query.allowedResourceIDs != nil {
		return l.requestPageScoped(query)
	}

	summary := l.summary
	if l.timed > 0 {
		summary.AvgMs = int(l.durationSumMs / l.timed)
	}
	summary.Countries = topCounters(l.byCountry, 12)
	summary.Hosts = topCounters(l.byHost, 8)
	retained := l.dbCount + len(l.pending)
	if l.db == nil {
		retained = len(l.entries)
	}
	offset := (query.page - 1) * query.limit
	rows := make([]RequestEntry, 0, query.limit)
	matched := 0
	defaultOrder := query.sort == "time" && query.direction == "desc"
	filtered := false
	for _, values := range query.filters {
		if len(values) > 0 {
			filtered = true
			break
		}
	}
	if !filtered {
		for _, search := range query.searches {
			if search != "" {
				filtered = true
				break
			}
		}
	}
	if defaultOrder && !filtered {
		skip := offset
		appendRow := func(entry RequestEntry) {
			if skip > 0 {
				skip--
				return
			}
			if len(rows) < query.limit {
				l.fillCountryLocked(&entry)
				rows = append(rows, entry)
			}
		}
		if l.db == nil {
			for _, entry := range l.entries {
				appendRow(entry)
				if len(rows) == query.limit {
					break
				}
			}
		} else {
			for index := len(l.pending) - 1; index >= 0; index-- {
				appendRow(l.pending[index])
				if len(rows) == query.limit {
					break
				}
			}
			if len(rows) < query.limit {
				err := l.db.View(func(tx *bolt.Tx) error {
					cursor := tx.Bucket(requestBucket).Cursor()
					for _, value := cursor.Last(); value != nil; _, value = cursor.Prev() {
						if skip > 0 {
							skip--
							continue
						}
						var entry RequestEntry
						if err := json.Unmarshal(value, &entry); err != nil {
							return err
						}
						appendRow(entry)
						if len(rows) == query.limit {
							break
						}
					}
					return nil
				})
				if err != nil {
					return summary, nil, 0, retained, err
				}
			}
		}
		return summary, rows, retained, retained, nil
	}
	if defaultOrder {
		visit := func(entry RequestEntry) {
			l.fillCountryLocked(&entry)
			if !matchesRequest(entry, query) {
				return
			}
			if matched >= offset && len(rows) < query.limit {
				rows = append(rows, entry)
			}
			matched++
		}
		if l.db == nil {
			for _, entry := range l.entries {
				visit(entry)
			}
		} else {
			for index := len(l.pending) - 1; index >= 0; index-- {
				visit(l.pending[index])
			}
			err := l.db.View(func(tx *bolt.Tx) error {
				cursor := tx.Bucket(requestBucket).Cursor()
				for _, value := cursor.Last(); value != nil; _, value = cursor.Prev() {
					var entry RequestEntry
					if err := json.Unmarshal(value, &entry); err != nil {
						return err
					}
					visit(entry)
				}
				return nil
			})
			if err != nil {
				return summary, nil, 0, retained, err
			}
		}
		return summary, rows, matched, retained, nil
	}

	// An alternate sort needs the matching rows. Keep this work on the server so
	// a browser still receives only one page, even for a very large history.
	all := make([]RequestEntry, 0)
	visit := func(entry RequestEntry) {
		l.fillCountryLocked(&entry)
		if matchesRequest(entry, query) {
			all = append(all, entry)
		}
	}
	if l.db == nil {
		for _, entry := range l.entries {
			visit(entry)
		}
	} else {
		for index := len(l.pending) - 1; index >= 0; index-- {
			visit(l.pending[index])
		}
		err := l.db.View(func(tx *bolt.Tx) error {
			cursor := tx.Bucket(requestBucket).Cursor()
			for _, value := cursor.Last(); value != nil; _, value = cursor.Prev() {
				var entry RequestEntry
				if err := json.Unmarshal(value, &entry); err != nil {
					return err
				}
				visit(entry)
			}
			return nil
		})
		if err != nil {
			return summary, nil, 0, retained, err
		}
	}
	matched = len(all)
	sort.SliceStable(all, func(i, j int) bool {
		comparison := compareRequests(all[i], all[j], query.sort)
		if query.direction == "asc" {
			return comparison < 0
		}
		return comparison > 0
	})
	if offset < matched {
		end := offset + query.limit
		if end > matched {
			end = matched
		}
		rows = append(rows, all[offset:end]...)
	}
	return summary, rows, matched, retained, nil
}

// requestPageScoped scans only resources owned by the caller. It builds the
// aggregates from those rows as well, so totals and filter choices stay private.
// The caller holds persistMu and mu, matching requestPage's other paths.
func (l *requestLog) requestPageScoped(query requestQuery) (RequestSummary, []RequestEntry, int, int, error) {
	summary := RequestSummary{Countries: []CountryStat{}, Hosts: []CountryStat{}}
	countries := map[string]*CountryStat{}
	hosts := map[string]*CountryStat{}
	all := make([]RequestEntry, 0)
	retained := 0
	durationSum, timed := int64(0), int64(0)
	visit := func(entry RequestEntry) {
		if !query.allowedResourceIDs[entry.ResourceID] {
			return
		}
		retained++
		l.fillCountryLocked(&entry)
		summary.Total++
		if entry.Allowed {
			summary.Allowed++
		} else {
			summary.Blocked++
		}
		if entry.Country == "" {
			summary.Unknown++
		}
		bump(countries, entry.Country, entry.Allowed)
		bump(hosts, entry.Host, entry.Allowed)
		if entry.DurationMs > 0 {
			durationSum += entry.DurationMs
			timed++
		}
		if matchesRequest(entry, query) {
			all = append(all, entry)
		}
	}
	if l.db == nil {
		for _, entry := range l.entries {
			visit(entry)
		}
	} else {
		for i := len(l.pending) - 1; i >= 0; i-- {
			visit(l.pending[i])
		}
		err := l.db.View(func(tx *bolt.Tx) error {
			cursor := tx.Bucket(requestBucket).Cursor()
			for _, value := cursor.Last(); value != nil; _, value = cursor.Prev() {
				var entry RequestEntry
				if err := json.Unmarshal(value, &entry); err != nil {
					return err
				}
				visit(entry)
			}
			return nil
		})
		if err != nil {
			return summary, nil, 0, retained, err
		}
	}
	if timed > 0 {
		summary.AvgMs = int(durationSum / timed)
	}
	summary.Countries = topCounters(countries, 12)
	summary.Hosts = topCounters(hosts, 8)
	if query.sort != "time" || query.direction != "desc" {
		sort.SliceStable(all, func(i, j int) bool {
			comparison := compareRequests(all[i], all[j], query.sort)
			if query.direction == "asc" {
				return comparison < 0
			}
			return comparison > 0
		})
	}
	matched := len(all)
	start := (query.page - 1) * query.limit
	if start >= matched {
		return summary, []RequestEntry{}, matched, retained, nil
	}
	end := start + query.limit
	if end > matched {
		end = matched
	}
	return summary, all[start:end], matched, retained, nil
}

func requestField(entry RequestEntry, field string) string {
	switch field {
	case "host":
		return entry.Host
	case "path":
		return entry.Path
	case "client":
		return entry.IP
	case "country":
		if entry.Country == "" {
			return "unknown"
		}
		return strings.ToUpper(entry.Country)
	case "resource":
		return entry.Resource
	case "decision":
		if entry.Allowed {
			return "allowed"
		}
		return "blocked"
	case "time":
		return entry.Time
	default:
		return ""
	}
}

func matchesRequest(entry RequestEntry, query requestQuery) bool {
	for field, values := range query.filters {
		if len(values) == 0 {
			continue
		}
		value := requestField(entry, field)
		if value == "" {
			value = "—"
		}
		found := false
		for _, wanted := range values {
			if value == wanted {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for field, search := range query.searches {
		if search != "" && !strings.Contains(strings.ToLower(requestField(entry, field)), strings.ToLower(search)) {
			return false
		}
	}
	return true
}

func compareRequests(left, right RequestEntry, field string) int {
	if field == "durationMs" {
		switch {
		case left.DurationMs < right.DurationMs:
			return -1
		case left.DurationMs > right.DurationMs:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(strings.ToLower(requestField(left, field)), strings.ToLower(requestField(right, field)))
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
	allowed := map[uint32]bool{}
	who := principalFrom(r)
	for _, resource := range s.store.Resources() {
		if ownsMeshObject(who, resource.OwnerID, resource.MeshSlot) {
			allowed[resource.ID] = true
		}
	}
	if field := r.URL.Query().Get("facet"); field != "" {
		if field != "host" && field != "path" && field != "client" && field != "country" && field != "resource" && field != "decision" {
			http.Error(w, "invalid facet", http.StatusBadRequest)
			return
		}
		search := strings.TrimSpace(r.URL.Query().Get("q"))
		if len(search) > 256 {
			http.Error(w, "facet search is too long", http.StatusBadRequest)
			return
		}
		limit := 200
		if field == "country" {
			limit = 512
		}
		facetQuery := requestQuery{filters: map[string][]string{}, searches: map[string]string{}, allowedResourceIDs: allowed}
		for _, other := range []string{"host", "path", "client", "country", "resource", "decision"} {
			if other == field {
				continue
			}
			facetQuery.filters[other] = r.URL.Query()[other]
			facetQuery.searches[other] = strings.TrimSpace(r.URL.Query().Get("search_" + other))
		}
		values, more, err := s.requests.requestFacet(field, search, limit, facetQuery)
		if err != nil {
			http.Error(w, "could not read request filter choices", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"values": values, "more": more})
		return
	}
	limit := requestPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > requestMaxPageSize {
			http.Error(w, "limit must be between 1 and 200", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > int(^uint(0)>>1)/limit {
			http.Error(w, "invalid page", http.StatusBadRequest)
			return
		}
		page = parsed
	}
	query := requestQuery{page: page, limit: limit, sort: "time", direction: "desc", filters: map[string][]string{}, searches: map[string]string{}}
	query.allowedResourceIDs = allowed
	if raw := r.URL.Query().Get("sort"); raw != "" {
		if raw != "time" && raw != "durationMs" && raw != "host" && raw != "path" && raw != "client" && raw != "country" && raw != "resource" && raw != "decision" {
			http.Error(w, "invalid sort", http.StatusBadRequest)
			return
		}
		query.sort = raw
	}
	if raw := r.URL.Query().Get("dir"); raw != "" {
		if raw != "asc" && raw != "desc" {
			http.Error(w, "invalid direction", http.StatusBadRequest)
			return
		}
		query.direction = raw
	}
	for _, field := range []string{"host", "path", "client", "country", "resource", "decision"} {
		query.filters[field] = r.URL.Query()[field]
		query.searches[field] = strings.TrimSpace(r.URL.Query().Get("search_" + field))
	}
	summary, entries, matched, retained, err := s.requests.requestPage(query)
	if err != nil {
		http.Error(w, "could not read request history", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "requests": entries, "total": matched, "retained": retained, "page": page, "limit": limit})
}

// requestSummaryView is what the dashboard shows: aggregates plus recent rows.
func (s *Server) requestSummaryView() map[string]any {
	summary, entries := s.requests.snapshot()
	return map[string]any{"summary": summary, "recent": entries}
}
