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
	// The same failure happening again moves its entry back to the top with a
	// fresh time instead of stacking up: a retrying sync should not fill the list.
	for i, existing := range l.entries {
		if existing.Source != source || existing.Message != message || existing.Detail != detail {
			continue
		}
		existing.Time = time.Now().UTC()
		if i > 0 {
			l.entries = append(l.entries[:i], l.entries[i+1:]...)
			l.entries = append([]ErrorEntry{existing}, l.entries...)
		} else {
			l.entries[0] = existing
		}
		return
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

// remove deletes only the entries named by fingerprint. Errors recorded while a
// health recheck is running are therefore preserved unless that exact failure
// was clean on every retry.
func (l *errorLog) remove(fingerprints map[string]bool) {
	if l == nil || len(fingerprints) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.entries[:0]
	for _, entry := range l.entries {
		if !fingerprints[errorFingerprint(entry)] {
			kept = append(kept, entry)
		}
	}
	l.entries = kept
}

func errorFingerprint(entry ErrorEntry) string {
	return entry.Source + "\x00" + entry.Message + "\x00" + entry.Detail
}
