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
			Email    string     `json:"email"`
			Password string     `json:"password"`
			Role     store.Role `json:"role"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if body.Role == "" {
			body.Role = store.RoleRegular
		}
		if s.auth.SMTP().Host != "" && strings.TrimSpace(body.Email) == "" {
			writeJSON(w, http.StatusBadRequest, errBody("email address is required"))
			return
		}
		user, err := s.auth.AddUserWithEmail(body.Username, body.Email, body.Password, body.Role)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if user.Email != "" {
			if err := s.sendEmailToken(r.Context(), user, user.Email, "verify"); err != nil {
				_ = s.auth.RemoveUser(user.ID)
				writeJSON(w, http.StatusBadGateway, errBody("could not send verification email"))
				return
			}
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
			Email    *string     `json:"email"`
			Role     *store.Role `json:"role"`
			Disabled *bool       `json:"disabled"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if body.Email != nil {
			current, err := s.auth.UserByID(id)
			if err != nil {
				writeJSON(w, http.StatusNotFound, errBody("no such user"))
				return
			}
			proposed := strings.ToLower(strings.TrimSpace(*body.Email))
			if proposed != current.Email {
				if proposed == "" {
					writeJSON(w, http.StatusBadRequest, errBody("email address cannot be removed"))
					return
				}
				if err := s.sendEmailToken(r.Context(), current, proposed, "change"); err != nil {
					writeJSON(w, http.StatusBadGateway, errBody("could not send verification email"))
					return
				}
			}
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
		if user.CanAdmin() && s.auth.AdminCount() <= 1 {
			writeJSON(w, http.StatusBadRequest, errBody(store.ErrLastAdmin.Error()))
			return
		}
		if user.MeshSlot > 0 {
			for _, resource := range s.store.Resources() {
				if resource.OwnerID == user.ID {
					if err := s.store.RemoveResource(resource.ID); err != nil {
						s.log.Error("could not remove resource after account deletion", "resource", resource.ID, "error", err)
						writeJSON(w, http.StatusInternalServerError, errBody("a resource could not be removed"))
						return
					}
				}
			}
			for _, domain := range s.store.Domains() {
				if domain.OwnerID == user.ID {
					if err := s.store.RemoveDomain(domain.Hostname); err != nil {
						s.log.Error("could not remove domain after account deletion", "domain", domain.Hostname, "error", err)
						writeJSON(w, http.StatusInternalServerError, errBody("a domain could not be removed"))
						return
					}
				}
			}
			for _, agent := range s.store.View().Agents {
				if agent.MeshSlot != user.MeshSlot || agent.OwnerID != user.ID {
					continue
				}
				if err := s.store.RemoveAgent(agent.ID); err != nil {
					s.log.Error("could not remove agent after account deletion", "agent", agent.ID, "error", err)
					writeJSON(w, http.StatusInternalServerError, errBody("an agent could not be removed"))
					return
				}
				s.Revoke(r.Context(), agent.ID, "account removed")
			}
			s.reconcileResources()
		}
		if err := s.auth.RemoveUser(id); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if user.MeshSlot > 0 && s.tenantFirewallReady.Load() {
			if err := s.syncTenantFirewall(r.Context()); err != nil {
				s.log.Error("could not update private mesh firewall after account deletion", "error", err)
				writeJSON(w, http.StatusInternalServerError, errBody("account removed but private mesh firewall could not be updated"))
				return
			}
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
