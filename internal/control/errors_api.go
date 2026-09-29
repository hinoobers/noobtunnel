package control

import "net/http"

// recordErrorFor adds an error tagged with its owning account. A blank owner
// means a global control-node error, visible only to administrators.
func (s *Server) recordErrorFor(ownerID, source, message, detail, hint string) {
	if s == nil || s.errors == nil {
		return
	}
	s.errors.recordOwned(ownerID, source, message, detail, hint)
}

func (s *Server) errorsFor(who principal) []ErrorEntry {
	entries := s.errors.recent()
	visible := make([]ErrorEntry, 0)
	for _, entry := range entries {
		if (entry.OwnerID != "" && entry.OwnerID == who.UserID) || (entry.OwnerID == "" && who.canAdmin()) {
			visible = append(visible, entry)
		}
	}
	return visible
}

// handleErrors lists the recent errors, or clears them.
func (s *Server) handleErrors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"errors": s.errorsFor(principalFrom(r))})
	case http.MethodDelete:
		if !principalFrom(r).canAdmin() {
			writeJSON(w, http.StatusForbidden, errBody("only an administrator can clear errors"))
			return
		}
		s.errors.clear()
		s.recordEvent("errors", "cleared the error log")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or DELETE"))
	}
}
