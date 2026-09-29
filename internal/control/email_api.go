package control

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

var recoveryLimiter = &loginLimiter{attempts: map[string][]time.Time{}}
var signupLimiter = &loginLimiter{attempts: map[string][]time.Time{}}

func (s *Server) emailLink(path, token string) string {
	if s.opts.Domain == "" {
		return ""
	}
	return "https://" + s.opts.Domain + path + "?token=" + url.QueryEscape(token)
}

func (s *Server) sendEmailToken(ctx context.Context, user store.User, email, purpose string) error {
	config := s.auth.SMTP()
	if err := config.Validate(); err != nil {
		return err
	}
	if config.Host == "" || s.opts.Domain == "" {
		return errors.New("SMTP and a public domain are required")
	}
	token, err := s.auth.IssueEmailToken(user.ID, email, purpose)
	if err != nil {
		return err
	}
	path, subject, message := "/verify-email", "Confirm your noobtunnel email", "Confirm your email address using this link:\n"
	if purpose == "reset" {
		path, subject, message = "/reset-password", "Reset your noobtunnel password", "Reset your password using this link:\n"
	}
	link := s.emailLink(path, token)
	return sendSMTP(ctx, config, email, subject, message+link+"\n\nThis link expires in one hour. If you did not request it, ignore this email.\n")
}

func (s *Server) handleEmailConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST"))
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	if err := s.auth.ConfirmEmail(body.Token); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("this confirmation link is invalid or expired"))
		return
	}
	s.recordEvent("security", "email address confirmed")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePasswordForgot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST"))
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	ip := clientIP(r)
	if !recoveryLimiter.allow(ip, s.now()) {
		writeJSON(w, http.StatusTooManyRequests, errBody("too many requests, wait a few minutes"))
		return
	}
	recoveryLimiter.fail(ip, s.now())
	identifier := strings.TrimSpace(body.Email)
	if user, err := s.auth.FindByUsername(identifier); err == nil && user.Email != "" && user.EmailVerified && !user.Disabled {
		go func() {
			if err := s.sendEmailToken(context.Background(), user, user.Email, "reset"); err != nil && !errors.Is(err, store.ErrEmailTokenCooldown) {
				s.log.Warn("could not send password reset email", "error", err)
			}
		}()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "If that account has a verified email, a reset link will be sent."})
}

func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST"))
		return
	}
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	if len(body.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, errBody("password must be at least 8 characters"))
		return
	}
	email, err := s.auth.ResetPassword(body.Token, body.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("this reset link is invalid or expired"))
		return
	}
	s.recordEvent("security", "password reset by email")
	config := s.auth.SMTP()
	if config.Host != "" {
		go func() {
			_ = sendSMTP(context.Background(), config, email, "Your noobtunnel password changed", "Your password was reset. If this was not you, contact the administrator.\n")
		}()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSignupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET"))
		return
	}
	registered, maximum := s.auth.SignupCapacity()
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.auth.SignupEnabled() && s.signupIsolationReady() && registered < maximum, "limitReached": registered >= maximum})
}

func (s *Server) handleSignupSettings(w http.ResponseWriter, r *http.Request) {
	if !principalFrom(r).canAdmin() {
		writeJSON(w, http.StatusForbidden, errBody("only admins can change sign-up settings"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		registered, maximum := s.auth.SignupCapacity()
		writeJSON(w, http.StatusOK, map[string]any{"enabled": s.auth.SignupEnabled(), "available": s.signupIsolationReady(), "maxUsers": maximum, "registeredUsers": registered})
	case http.MethodPost:
		var body struct {
			Enabled  bool `json:"enabled"`
			MaxUsers *int `json:"maxUsers"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if body.Enabled && !s.signupIsolationReady() {
			writeJSON(w, http.StatusPreconditionFailed, errBody("mesh isolation is not ready"))
			return
		}
		_, maximum := s.auth.SignupCapacity()
		if body.MaxUsers != nil {
			maximum = *body.MaxUsers
		}
		if err := s.auth.SetSignupSettings(body.Enabled, maximum); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		registered, _ := s.auth.SignupCapacity()
		writeJSON(w, http.StatusOK, map[string]any{"enabled": body.Enabled, "maxUsers": maximum, "registeredUsers": registered})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

func (s *Server) signupIsolationReady() bool {
	if !s.tenantFirewallReady.Load() {
		return false
	}
	_, err := store.TenantPrefix(s.store.Settings().MeshCIDR, 1)
	config := s.auth.SMTP()
	return err == nil && config.Host != "" && config.Validate() == nil && s.opts.Domain != ""
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST"))
		return
	}
	if !s.auth.SignupEnabled() || !s.signupIsolationReady() {
		writeJSON(w, http.StatusForbidden, errBody("sign-ups are disabled"))
		return
	}
	registered, maximum := s.auth.SignupCapacity()
	if registered >= maximum {
		writeJSON(w, http.StatusConflict, errBody("registration limit reached"))
		return
	}
	ip := clientIP(r)
	if !signupLimiter.allow(ip, s.now()) {
		writeJSON(w, http.StatusTooManyRequests, errBody("too many sign-ups, try again later"))
		return
	}
	signupLimiter.fail(ip, s.now())
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	if strings.TrimSpace(body.Email) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("email is required"))
		return
	}
	user, err := s.auth.AddUserWithEmail(body.Username, body.Email, body.Password, store.RoleOwner)
	if err != nil {
		if errors.Is(err, store.ErrUserLimit) {
			writeJSON(w, http.StatusConflict, errBody("registration limit reached"))
			return
		}
		writeJSON(w, http.StatusBadRequest, errBody("account could not be created; check the username, email and password"))
		return
	}
	if err := s.syncTenantFirewall(r.Context()); err != nil {
		_ = s.auth.RemoveUser(user.ID)
		writeJSON(w, http.StatusServiceUnavailable, errBody("private mesh firewall is unavailable"))
		return
	}
	if err := s.sendEmailToken(r.Context(), user, user.Email, "verify"); err != nil {
		_ = s.auth.RemoveUser(user.ID)
		writeJSON(w, http.StatusBadGateway, errBody("could not send confirmation email"))
		return
	}
	s.recordEvent("security", "new private mesh account created")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Check your email to confirm this account."})
}
