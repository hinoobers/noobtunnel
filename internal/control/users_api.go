package control

import (
	"net/http"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// handleUsers lists and creates control node accounts.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !principalFrom(r).canAdmin() {
		writeJSON(w, http.StatusForbidden, errBody("only admins can manage users"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"users": s.auth.Users()})
	case http.MethodPost:
		var body struct {
			Username string     `json:"username"`
			Password string     `json:"password"`
			Role     store.Role `json:"role"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if body.Role == "" {
			body.Role = store.RoleViewer
		}
		user, err := s.auth.AddUser(body.Username, body.Password, body.Role)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("security", "user created: "+user.Username+" ("+string(user.Role)+")")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"user": user})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

// handleUserItem changes or removes one account.
func (s *Server) handleUserItem(w http.ResponseWriter, r *http.Request) {
	who := principalFrom(r)
	rest := strings.TrimPrefix(r.URL.Path, "/api/users/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusBadRequest, errBody("missing user id"))
		return
	}
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if !who.canAdmin() {
		writeJSON(w, http.StatusForbidden, errBody("only admins can manage users"))
		return
	}

	switch {
	case action == "" && r.Method == http.MethodGet:
		user, err := s.auth.UserByID(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, errBody("no such user"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": user})

	case action == "" && r.Method == http.MethodPatch:
		var body struct {
			Username *string     `json:"username"`
			Role     *store.Role `json:"role"`
			Disabled *bool       `json:"disabled"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		user, err := s.auth.UpdateUser(id, func(u *store.User) error {
			if body.Username != nil {
				u.Username = strings.TrimSpace(*body.Username)
			}
			if body.Role != nil {
				u.Role = *body.Role
			}
			if body.Disabled != nil {
				u.Disabled = *body.Disabled
			}
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("security", "user updated: "+user.Username)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"user": user})

	case action == "" && r.Method == http.MethodDelete:
		user, err := s.auth.UserByID(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, errBody("no such user"))
			return
		}
		if err := s.auth.RemoveUser(id); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("security", "user removed: "+user.Username)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case action == "password" && r.Method == http.MethodPost:
		if _, err := s.auth.UserByID(id); err != nil {
			writeJSON(w, http.StatusNotFound, errBody("no such user"))
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if err := s.auth.SetUserPassword(id, body.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("security", "password reset for user "+id)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("unsupported operation"))
	}
}
