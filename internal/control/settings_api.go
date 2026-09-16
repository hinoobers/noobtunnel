package control

import (
	"net/http"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// handleSettings replaces the control node settings.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"settings": s.store.Settings()})
	case http.MethodPost, http.MethodPatch:
		existing := s.store.Settings()
		body := existing
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		// Fields the UI does not expose keep their current values.
		if body.StatsIntervalSec == 0 {
			body.StatsIntervalSec = existing.StatsIntervalSec
		}
		if body.DirectFreshSec == 0 {
			body.DirectFreshSec = existing.DirectFreshSec
		}
		if body.DirectProbeSec == 0 {
			body.DirectProbeSec = existing.DirectProbeSec
		}
		if body.AgentInactivitySec == 0 {
			body.AgentInactivitySec = existing.AgentInactivitySec
		}
		if body.ControlListenAddr == "" {
			body.ControlListenAddr = existing.ControlListenAddr
		}
		if body.PublicEndpoint == "" {
			body.PublicEndpoint = existing.PublicEndpoint
		}
		if body.Interface == "" {
			body.Interface = existing.Interface
		}
		if err := s.store.Update(func(st *store.State) error {
			st.Settings = body
			return nil
		}); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if err := s.Sync(r.Context()); err != nil {
			s.log.Warn("failed to apply settings to the hub", "error", err)
		}
		s.recordEvent("settings", "mesh settings updated")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"settings": s.store.Settings()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}
