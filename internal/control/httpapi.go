package control

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proto"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/version"
	"github.com/noobtunnel/noobtunnel/internal/web"
)

// sessionCookie is the browser session cookie name.
const sessionCookie = "noobtunnel_session"

// psHeader guards mutating requests against CSRF: a cross-site form post cannot
// set a custom header, and we never enable CORS.
const psHeader = "X-Noobtunnel"

// principal is the authenticated caller of an API request.
type principal struct {
	UserID   string
	Username string
	Role     store.Role
	// ViaToken marks requests authenticated with a bearer token.
	ViaToken bool
}

func (p principal) canAdmin() bool { return p.Role == store.RoleAdmin }

type principalKey struct{}

func principalFrom(r *http.Request) principal {
	if p, ok := r.Context().Value(principalKey{}).(principal); ok {
		return p
	}
	return principal{}
}

// Handler returns the full HTTP handler of the control node.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints. Enrollment happens before any credential exists on the
	// new machine, so these must work unauthenticated.
	mux.HandleFunc(proto.AgentPath, s.handleAgentConnect)
	mux.HandleFunc("/install.sh", s.handleInstallScript)
	mux.HandleFunc("/cert.pem", s.handleCert)
	mux.HandleFunc("/download/", s.handleDownload)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/session", s.handleSession)

	mux.Handle("/assets/", http.FileServer(http.FS(web.Assets())))
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = io.WriteString(w, web.Favicon())
	})
	mux.HandleFunc("/logo", s.handleLogo)
	// The stylesheet is public: the login screen wears the operator's theme too.
	mux.HandleFunc("/custom.css", s.handleCustomCSS)

	authed := http.NewServeMux()
	authed.HandleFunc("/api/state", s.handleState)
	authed.HandleFunc("/api/events", s.handleEvents)
	authed.HandleFunc("/api/agents", s.handleAgents)
	authed.HandleFunc("/api/agents/", s.handleAgentItem)
	authed.HandleFunc("/api/settings", s.handleSettings)
	authed.HandleFunc("/api/checks", s.handleChecks)
	authed.HandleFunc("/api/tokens", s.handleAPITokens)
	authed.HandleFunc("/api/tokens/", s.handleAPITokenItem)
	authed.HandleFunc("/api/password", s.handlePassword)
	authed.HandleFunc("/api/log", s.handleEventLog)
	authed.HandleFunc("/api/users", s.handleUsers)
	authed.HandleFunc("/api/users/", s.handleUserItem)
	authed.HandleFunc("/api/resources", s.handleResources)
	authed.HandleFunc("/api/resources/", s.handleResourceItem)
	authed.HandleFunc("/api/domains", s.handleDomains)
	authed.HandleFunc("/api/domains/", s.handleDomainItem)
	authed.HandleFunc("/api/exitnodes", s.handleExitNodes)
	authed.HandleFunc("/api/exitnodes/", s.handleExitNodeItem)
	authed.HandleFunc("/api/dns/providers", s.handleDNSProviders)
	authed.HandleFunc("/api/geoip", s.handleGeoIP)
	authed.HandleFunc("/api/requests", s.handleRequests)
	authed.HandleFunc("/api/errors", s.handleErrors)
	authed.HandleFunc("/api/diagnose", s.handleDiagnose)
	authed.HandleFunc("/api/dns/providers/", s.handleDNSProviderItem)
	authed.HandleFunc("/api/logo", s.handleLogoUpload)
	authed.HandleFunc("/api/css", s.handleBrandCSS)

	mux.Handle("/api/", s.requireAuth(authed))
	mux.HandleFunc("/", s.handleIndex)
	return s.logRequests(mux)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") ||
			strings.HasPrefix(r.URL.Path, "/api/events") ||
			r.URL.Path == proto.AgentPath {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start).Round(time.Millisecond).String(),
			"remote", clientIP(r))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Hijack keeps the agent control channel upgrade working through the recorder.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("control: hijacking unsupported")
	}
	return hijacker.Hijack()
}

// Flush keeps server sent events streaming through the recorder.
func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Any path the API, installer, agent channel or assets do not own serves the
	// single page app, so refreshing on /settings (or any tab) works.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	page, err := web.Index()
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.StateSnapshot())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": version.Version,
		"time":    s.now().UTC(),
	})
}

// --- authentication ---------------------------------------------------------

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var who principal
		if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
			token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
			if token != "" {
				if role, ok := s.auth.VerifyAPIToken(token); ok {
					who = principal{Username: "api-token", Role: role, ViaToken: true}
				}
			}
		}
		if who.Role == "" {
			if cookie, err := r.Cookie(sessionCookie); err == nil {
				if userID, ok := s.validSession(cookie.Value); ok {
					if user, err := s.auth.UserByID(userID); err == nil && !user.Disabled {
						who = principal{UserID: user.ID, Username: user.Username, Role: user.Role}
					}
				}
			}
		}
		if who.Role == "" {
			writeJSON(w, http.StatusUnauthorized, errBody("authentication required"))
			return
		}
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead
		// Everyone may change their own password; everything else that changes
		// state needs an admin.
		if mutating && r.URL.Path != "/api/password" && r.URL.Path != "/api/logout" && !who.canAdmin() {
			writeJSON(w, http.StatusForbidden, errBody("this account is read-only"))
			return
		}
		if mutating {
			if r.Header.Get(psHeader) == "" && r.Header.Get("Authorization") == "" {
				writeJSON(w, http.StatusForbidden, errBody("missing "+psHeader+" header"))
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, who)))
	})
}

func (s *Server) signSession(userID string, expiry time.Time) string {
	payload := userID + "|" + strconv.FormatInt(expiry.Unix(), 10)
	mac := hmac.New(sha256.New, s.auth.SessionKey())
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validSession returns the user id carried by a signed session cookie.
func (s *Server) validSession(value string) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, s.auth.SessionKey())
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return "", false
	}
	fields := strings.Split(string(payload), "|")
	if len(fields) != 2 {
		return "", false
	}
	expiry, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || !s.now().Before(time.Unix(expiry, 0)) {
		return "", false
	}
	return fields[0], true
}

// loginLimiter throttles password guessing.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

var limiter = &loginLimiter{attempts: map[string][]time.Time{}}

func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	window := now.Add(-5 * time.Minute)
	var kept []time.Time
	for _, t := range l.attempts[key] {
		if t.After(window) {
			kept = append(kept, t)
		}
	}
	l.attempts[key] = kept
	return len(kept) < 10
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts[key] = append(l.attempts[key], now)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST"))
		return
	}
	ip := clientIP(r)
	if !limiter.allow(ip, s.now()) {
		writeJSON(w, http.StatusTooManyRequests, errBody("too many attempts, wait a few minutes"))
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	if !s.auth.HasUsers() {
		writeJSON(w, http.StatusPreconditionFailed, errBody("no accounts exist on this control node yet"))
		return
	}
	username := strings.TrimSpace(body.Username)
	if username == "" {
		// Convenience for scripts written before usernames existed.
		username = "admin"
	}
	user, err := s.auth.Authenticate(username, body.Password)
	if err != nil {
		limiter.fail(ip, s.now())
		s.log.Warn("failed login", "remote", ip, "username", username)
		writeJSON(w, http.StatusUnauthorized, errBody("incorrect username or password"))
		return
	}
	expiry := s.now().Add(12 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    s.signSession(user.ID, expiry),
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	s.auth.MarkLogin(user.ID)
	s.recordEvent("login", user.Username+" signed in from "+ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "expires": expiry.UTC(), "username": user.Username, "role": user.Role,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	who := principal{}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if userID, ok := s.validSession(cookie.Value); ok {
			if user, err := s.auth.UserByID(userID); err == nil && !user.Disabled {
				who = principal{UserID: user.ID, Username: user.Username, Role: user.Role}
			}
		}
	}
	if who.Role == "" {
		if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
			if role, ok := s.auth.VerifyAPIToken(strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))); ok {
				who = principal{Username: "api-token", Role: role, ViaToken: true}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": who.Role != "",
		"username":      who.Username,
		"role":          string(who.Role),
		"canAdmin":      who.canAdmin(),
		"passwordSet":   s.auth.HasUsers(),
		"meshName":      s.store.Settings().MeshName,
		"brandName":     s.BrandName(),
		"version":       version.Version,
	})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST"))
		return
	}
	var body struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	who := principalFrom(r)
	if who.UserID == "" {
		writeJSON(w, http.StatusForbidden, errBody("API tokens cannot change passwords"))
		return
	}
	user, err := s.auth.UserByID(who.UserID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody("account no longer exists"))
		return
	}
	if _, err := s.auth.Authenticate(user.Username, body.Current); err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody("current password is incorrect"))
		return
	}
	if err := s.auth.SetUserPassword(user.ID, body.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: s.signSession(user.ID, s.now().Add(12*time.Hour)),
		Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	s.recordEvent("security", user.Username+" changed their password")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAPITokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"tokens": s.auth.APITokens()})
	case http.MethodPost:
		var body struct {
			Name string     `json:"name"`
			Role store.Role `json:"role"`
		}
		_ = decodeJSON(r, &body)
		token, meta, err := s.auth.AddAPITokenWithRole(body.Name, body.Role)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.recordEvent("security", "API token created: "+meta.ID)
		writeJSON(w, http.StatusOK, map[string]any{"token": token, "meta": meta})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

func (s *Server) handleAPITokenItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/tokens/")
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use DELETE"))
		return
	}
	if err := s.auth.RemoveAPIToken(id); err != nil {
		writeJSON(w, http.StatusNotFound, errBody("no such token"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
