package control

import (
	"sync"
	"time"
)

// ErrorEntry is one thing that went wrong, for the Logs tab's Errors view. The
// control node keeps the most recent ones in memory so the UI can show why a
// domain is not updating, a certificate is missing or a listener is not up.
type ErrorEntry struct {
	Time    time.Time `json:"time"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
	Detail  string    `json:"detail,omitempty"`
	Hint    string    `json:"hint,omitempty"`
}

// maxErrors is how many entries are kept, newest first.
const maxErrors = 200

// errorLog is a bounded, concurrency safe list of recent errors.
type errorLog struct {
	mu      sync.Mutex
	entries []ErrorEntry
}

func newErrorLog() *errorLog { return &errorLog{} }

// record adds an error. Consecutive duplicates are collapsed so a retry loop
// cannot fill the list with the same line.
func (l *errorLog) record(source, message, detail, hint string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > 0 {
		last := l.entries[0]
		if last.Source == source && last.Message == message && last.Detail == detail {
			// Same failure again: keep the newest time without repeating it.
			last.Time = time.Now().UTC()
			l.entries[0] = last
			return
		}
	}
	entry := ErrorEntry{
		Time:    time.Now().UTC(),
		Source:  source,
		Message: message,
		Detail:  detail,
		Hint:    hint,
	}
	l.entries = append([]ErrorEntry{entry}, l.entries...)
	if len(l.entries) > maxErrors {
		l.entries = l.entries[:maxErrors]
	}
}

// recent returns the entries, newest first.
func (l *errorLog) recent() []ErrorEntry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]ErrorEntry(nil), l.entries...)
}

// clear empties the list, which is what the UI's "Clear" button calls.
func (l *errorLog) clear() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = nil
}
