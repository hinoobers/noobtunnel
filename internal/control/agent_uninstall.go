package control

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func (s *Server) removeAgent(r *http.Request, agent *store.Agent, reason string) error {
	if err := s.store.RemoveAgent(agent.ID); err != nil {
		return err
	}
	s.finishAgentRemoval(r, agent, reason)
	return nil
}

func (s *Server) finishAgentRemoval(r *http.Request, agent *store.Agent, reason string) {
	s.Revoke(r.Context(), agent.ID, reason)
	s.recordEventFor(agent.OwnerID, "enrollment", "agent "+agent.Name+" removed")
	s.broadcastState()
}

// The installed agent's local token authorizes its own removal. This endpoint
// does not use browser sessions, and never accepts a token for a different ID.
func (s *Server) handleAgentUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST"))
		return
	}
	textID := strings.TrimPrefix(r.URL.Path, "/api/agent-uninstall/")
	id64, err := strconv.ParseUint(textID, 10, 32)
	if err != nil || id64 == 0 {
		writeJSON(w, http.StatusNotFound, errBody("no such agent"))
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, errBody("invalid agent token"))
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if _, ok := store.TokenID(token); !ok {
		writeJSON(w, http.StatusUnauthorized, errBody("invalid agent token"))
		return
	}
	agent, err := s.store.Agent(uint32(id64))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody("invalid agent token"))
		return
	}
	if err := s.store.RemoveAgentWithToken(agent.ID, token); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusInternalServerError, errBody("agent removal failed"))
			return
		}
		writeJSON(w, http.StatusUnauthorized, errBody("invalid agent token"))
		return
	}
	s.finishAgentRemoval(r, agent, "agent uninstalled on its machine")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
