package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Event is a line in the control node's activity log.
type Event struct {
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
	Time    time.Time `json:"time"`
}

// eventHub fans state snapshots out to SSE subscribers and keeps a short log.
type eventHub struct {
	mu     sync.Mutex
	subs   map[chan []byte]struct{}
	events []Event
}

func newEventHub() *eventHub {
	return &eventHub{subs: map[chan []byte]struct{}{}}
}

func (h *eventHub) subscribe() chan []byte {
	ch := make(chan []byte, 8)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *eventHub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *eventHub) broadcast(v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	payload := append([]byte("data: "), raw...)
	payload = append(payload, '\n', '\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- payload:
		default:
			// Slow client: skip this frame, the next one carries full state.
		}
	}
}

func (h *eventHub) record(ev Event) {
	h.mu.Lock()
	h.events = append(h.events, ev)
	if len(h.events) > 200 {
		h.events = h.events[len(h.events)-200:]
	}
	h.mu.Unlock()
}

func (h *eventHub) recent() []Event {
	h.mu.Lock()
	out := append([]Event(nil), h.events...)
	h.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.events.subscribe()
	defer s.events.unsubscribe(ch)

	if err := writeSSE(w, s.StateSnapshot()); err != nil {
		return
	}
	flusher.Flush()

	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case payload, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write(payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", raw)
	return err
}

func (s *Server) handleEventLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": s.events.recent()})
}

// Checks returns the cached preflight results.
func (s *Server) Checks() []Check {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checks == nil {
		return []Check{}
	}
	return append([]Check(nil), s.checks...)
}

func (s *Server) handleChecks(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("refresh") != "" {
		s.mu.Lock()
		s.checks = s.RunChecks(r.Context())
		s.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": s.Checks()})
}
