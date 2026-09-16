package control

import "net/http"

// recordError adds an entry to the Errors view of the Logs tab. It is safe to
// call with a server that has no log yet (tests construct the struct directly).
func (s *Server) recordError(source, message, detail, hint string) {
	if s == nil || s.errors == nil {
		return
	}
	s.errors.record(source, message, detail, hint)
}

// handleErrors lists the recent errors, or clears them.
func (s *Server) handleErrors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"errors": notNil(s.errors.recent())})
	case http.MethodDelete:
		s.errors.clear()
		s.recordEvent("errors", "cleared the error log")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or DELETE"))
	}
}
