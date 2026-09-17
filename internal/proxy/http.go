package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/access"
)

// dialTiming carries how long a connection to the backend took, from the dialer
// (which runs on the transport's own goroutine) back to the request that caused
// it.
type dialTimingKey struct{}

type dialTiming struct {
	ms        atomic.Int64
	started   time.Time
	wroteAt   atomic.Int64
	firstByte atomic.Int64
	reused    atomic.Bool
}

type backendTiming struct {
	dialMs     int64
	queueMs    int64
	backendMs  int64
	reusedConn bool
}

// maxRetryBody is how much of a request body is buffered so a failed target can
// be retried without sending a truncated body.
const maxRetryBody = 1 << 20

// httpResource is the reverse proxy used for plain HTTP resources. Several
// resources can share one port and are told apart by the Host header, and each
// resource spreads requests over its targets.
type httpResource struct {
	group   *group
	server  *http.Server
	timeout time.Duration

	mu         sync.Mutex
	transports map[string]*http.Transport
	authCache  map[string]authEntry
}

// clientInfoKey carries the client address down to the dialer so a PROXY
// protocol header can be written when the resource asks for one.
type clientInfoKey struct{}

type clientInfo struct {
	addr    net.Addr
	version string
}

func newHTTPResource(g *group, dialTimeout time.Duration) *httpResource {
	h := &httpResource{
		group:      g,
		timeout:    dialTimeout,
		transports: map[string]*http.Transport{},
		authCache:  map[string]authEntry{},
	}
	h.server = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return h
}

func (h *httpResource) serve(ln net.Listener) error {
	return h.server.Serve(ln)
}

func (h *httpResource) close() {
	h.server.Close()
	h.mu.Lock()
	for _, transport := range h.transports {
		transport.CloseIdleConnections()
	}
	h.transports = map[string]*http.Transport{}
	h.mu.Unlock()
}

// transportFor returns the transport for one backend address. Resources that
// need a PROXY protocol header get their own connection per request, because the
// header describes a single client.
func (h *httpResource) transportFor(candidate TargetSpec, proxyProtocol string) *http.Transport {
	key := candidate.Address() + "|" + proxyProtocol
	h.mu.Lock()
	defer h.mu.Unlock()
	if transport, ok := h.transports[key]; ok {
		return transport
	}
	dialer := &net.Dialer{Timeout: h.timeout}
	// Connecting and being answered are timed separately: the request log can then
	// say whether a slow request spent its time getting to the service or waiting
	// for it. The transport dials on its own goroutine, so the measurement travels
	// in the request's context.
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		started := time.Now()
		conn, err := dialer.DialContext(ctx, network, candidate.Address())
		if timing, ok := ctx.Value(dialTimingKey{}).(*dialTiming); ok {
			timing.ms.Store(time.Since(started).Milliseconds())
		}
		return conn, err
	}
	transport := &http.Transport{
		DialContext:           dial,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	if proxyProtocol != ProxyProtocolNone {
		transport.DisableKeepAlives = true
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			info, ok := ctx.Value(clientInfoKey{}).(clientInfo)
			if ok && info.addr != nil {
				if err := writeProxyHeader(conn, info.version, info.addr, conn.RemoteAddr()); err != nil {
					_ = conn.Close()
					return nil, err
				}
			}
			return conn, nil
		}
	}
	h.transports[key] = transport
	return transport
}

// ServeHTTP routes by the Host header and forwards to one of the resource's
// targets, trying the next one when a backend cannot be reached.
func (h *httpResource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	// ACME HTTP-01 challenges are answered by the control node itself.
	if h.group.manager.ACMEChallenge != nil && strings.HasPrefix(r.URL.Path, acmeChallengePath) {
		h.group.manager.ACMEChallenge.ServeHTTP(w, r)
		return
	}
	res, ok := h.group.route(r.Host)
	if !ok {
		h.writeUnknownHost(w, r)
		return
	}
	// The control node's own UI is published on this port too: its route is
	// answered here instead of being dialled through an agent.
	if res.spec.Control {
		handler := h.group.manager.ControlHandler
		if handler == nil {
			h.writeUnknownHost(w, r)
			return
		}
		res.stat.set.active.Add(1)
		res.stat.set.total.Add(1)
		defer res.stat.set.active.Add(-1)
		handler.ServeHTTP(w, r)
		return
	}
	if res.spec.BlockExploits {
		if reason := commonExploit(r); reason != "" {
			h.group.manager.observe(RequestEvent{
				ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
				Country: h.countryForLog(r.RemoteAddr), Protocol: string(res.spec.Protocol),
				Allowed: false, Reason: "common exploit filter: " + reason,
				Status: http.StatusForbidden, Path: r.URL.Path,
				DurationMs: time.Since(started).Milliseconds(),
			})
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(h.group.manager.brand() + ": request blocked by the common exploit filter\n"))
			return
		}
	}
	if res.spec.Identity {
		account, handled := h.requireIdentity(w, r, res)
		if handled {
			if account == "" {
				h.group.manager.observe(RequestEvent{
					ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
					Country: h.countryForLog(r.RemoteAddr), Protocol: string(res.spec.Protocol), Allowed: false,
					Reason: "identity required", Status: http.StatusUnauthorized, Path: r.URL.Path,
					DurationMs: time.Since(started).Milliseconds(),
				})
			}
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), accountKey{}, account))
		// Control-node credentials and signed sessions are proxy credentials, not
		// backend credentials. Never leak either one to the published service.
		r.Header.Del("Authorization")
		removeRequestCookie(r, "noobtunnel_session")
	}
	// Access rules run after authentication, so a rule can look at the account.
	if len(res.spec.Rules) > 0 {
		country := ""
		for _, rule := range res.spec.Rules {
			if rule.Field == access.FieldCountry {
				country = h.countryOf(r.RemoteAddr)
				break
			}
		}
		decision := access.Evaluate(res.spec.Rules, access.Request{
			IP: clientIP(r.RemoteAddr),
			// A rule that tests a country cannot be evaluated without one, so this
			// path does wait - briefly - for an answer.
			Country: country,
			Host:    r.Host,
			Path:    r.URL.Path,
			Account: accountOf(r),
		})
		if !decision.Allow {
			h.group.manager.observe(RequestEvent{
				ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
				Country: h.countryForLog(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
				Allowed: false, Reason: decision.Reason, Status: http.StatusForbidden, Path: r.URL.Path,
				DurationMs: time.Since(started).Milliseconds(),
			})
			res.stat.setError(fmt.Errorf("blocked: %s", decision.Reason))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(h.group.manager.brand() + ": access denied\n"))
			return
		}
	}
	// A protocol upgrade (WebSocket) becomes a tunnel between the client and the
	// service, not a request and a response.
	if isUpgrade(r) {
		if !res.spec.WebSockets {
			h.group.manager.observe(RequestEvent{
				ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
				Country: h.countryForLog(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
				Allowed: false, Reason: "websockets are disabled for this resource",
				Status: http.StatusNotImplemented, Path: r.URL.Path,
				DurationMs: time.Since(started).Milliseconds(),
			})
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte(h.group.manager.brand() + ": websockets are disabled for this resource\n"))
			return
		}
		h.serveUpgrade(w, r, res, started)
		return
	}
	res.stat.set.active.Add(1)
	res.stat.set.total.Add(1)
	defer res.stat.set.active.Add(-1)

	if res.spec.ProxyProtocol != ProxyProtocolNone {
		r = r.WithContext(context.WithValue(r.Context(), clientInfoKey{}, clientInfo{
			addr:    remoteAddr(r.RemoteAddr),
			version: res.spec.ProxyProtocol,
		}))
	}
	if r.Body != nil {
		r.Body = &countingBody{ReadCloser: r.Body, target: &res.stat.set}
	}

	policyMs := time.Since(started).Milliseconds()
	response, chosen, timing, err := h.roundTrip(res, r)
	if err != nil {
		if callerGaveUp(r.Context(), err) {
			// The caller went away before anything was served: nothing to record
			// against the resource or the target, and the request was not blocked
			// either.
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		res.stat.setError(err)
		h.group.manager.observe(RequestEvent{
			ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
			Country: h.countryForLog(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
			Allowed: false, Reason: "no target answered", Status: http.StatusBadGateway, Path: r.URL.Path,
			DurationMs: time.Since(started).Milliseconds(), DialMs: timing.dialMs,
			PolicyMs: policyMs, QueueMs: timing.queueMs, BackendMs: timing.backendMs,
		})
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(h.group.manager.brand() + ": none of the targets answered\n"))
		return
	}
	headerMs := time.Since(started).Milliseconds()
	defer response.Body.Close()
	res.stat.setError(nil)

	response.Body = &countingBody{ReadCloser: response.Body, target: &res.stat.set, also: &res.stat.targetFor(chosen.ID).set, read: true}
	removeHopHeaders(response.Header)
	copyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	var dst io.Writer = w
	if response.ContentLength < 0 || strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		// Flush headers and each chunk for event streams and streaming responses.
		_ = http.NewResponseController(w).Flush()
		dst = flushWriter{w}
	}
	copyResponse(dst, response.Body)
	totalMs := time.Since(started).Milliseconds()
	res.stat.targetFor(chosen.ID).set.total.Add(1)
	h.group.manager.observe(RequestEvent{
		ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
		Country: h.countryForLog(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
		Allowed: true, Status: response.StatusCode, Path: r.URL.Path,
		DurationMs: totalMs, DialMs: timing.dialMs, HeaderMs: headerMs,
		PolicyMs: policyMs, QueueMs: timing.queueMs, BackendMs: timing.backendMs,
		ReusedConn: timing.reusedConn,
		TransferMs: max(0, totalMs-headerMs), Target: chosen.Published(),
	})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// isUpgrade reports whether the request asks to change protocol, which is how a
// WebSocket connection starts.
func isUpgrade(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("Upgrade")) == "" {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// serveUpgrade hands the client's connection to the service and copies bytes both
// ways until either side closes. Everything before the upgrade - the identity
// check and the access rules - has already run, so a rule can still refuse it.
func (h *httpResource) serveUpgrade(w http.ResponseWriter, r *http.Request, res *resource, started time.Time) {
	response, chosen, timing, err := h.roundTrip(res, r)
	if err != nil {
		if callerGaveUp(r.Context(), err) {
			// The caller went away; the target and the resource are not at fault.
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		res.stat.setError(err)
		h.group.manager.observe(RequestEvent{
			ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
			Country: h.countryForLog(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
			Allowed: false, Reason: "no target answered", Status: http.StatusBadGateway, Path: r.URL.Path,
			DurationMs: time.Since(started).Milliseconds(), DialMs: timing.dialMs,
		})
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(h.group.manager.brand() + ": none of the targets answered\n"))
		return
	}
	defer response.Body.Close()
	res.stat.setError(nil)

	// The service did not upgrade (an ordinary request, or it refused): relay the
	// answer as usual so the client sees why.
	if response.StatusCode != http.StatusSwitchingProtocols {
		copyHeader(w.Header(), response.Header)
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
		h.group.manager.observe(RequestEvent{
			ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
			Country: h.countryForLog(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
			Allowed: true, Status: response.StatusCode, Path: r.URL.Path,
			DurationMs: time.Since(started).Milliseconds(),
		})
		return
	}

	upstream, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(h.group.manager.brand() + ": the service upgraded, but the connection is not usable\n"))
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(h.group.manager.brand() + ": this connection cannot be upgraded\n"))
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		res.stat.setError(err)
		return
	}
	defer client.Close()
	defer upstream.Close()

	// Replay the handshake the service sent, and then step aside.
	_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_ = response.Header.Write(buffered)
	_, _ = buffered.WriteString("\r\n")
	if err := buffered.Flush(); err != nil {
		return
	}
	h.group.manager.observe(RequestEvent{
		ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
		Country: h.countryForLog(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
		Allowed: true, Status: http.StatusSwitchingProtocols, Path: r.URL.Path,
		DurationMs: time.Since(started).Milliseconds(),
	})

	// Count the bytes the same way a TCP resource does, so the counters stay
	// meaningful for a socket that can live for hours.
	sets := []*counters{&res.stat.set, &res.stat.targetFor(chosen.ID).set}
	for _, set := range sets {
		set.active.Add(1)
		set.total.Add(1)
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, io.TeeReader(buffered, countWriter{sets}))
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, io.TeeReader(upstream, reverseWriter{sets}))
		done <- struct{}{}
	}()
	<-done
	// Closing both ends unblocks the other direction.
	_ = client.Close()
	_ = upstream.Close()
	<-done
	for _, set := range sets {
		set.active.Add(-1)
	}
}

// clientIP extracts the address of a client.
func clientIP(raw string) netip.Addr {
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		host = raw
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// countryOf looks the client's country up when a database is loaded.
func (h *httpResource) countryOf(raw string) string {
	if h.group.manager.CountryOf == nil {
		return ""
	}
	return h.group.manager.CountryOf(clientIP(raw))
}

// countryForLog is the same answer for the request log, which must never wait for
// it: a lookup that is not cached yet starts in the background and the country is
// filled in for this request - and every earlier one from the address - as soon as
// the API answers.
func (h *httpResource) countryForLog(raw string) string {
	addr := clientIP(raw)
	if h.group.manager.CountryOfFast != nil {
		return h.group.manager.CountryOfFast(addr)
	}
	if h.group.manager.CountryOf == nil {
		return ""
	}
	return h.group.manager.CountryOf(addr)
}

// accountOf reports the signed in account, when identity control ran first.
func accountOf(r *http.Request) string {
	if account, ok := r.Context().Value(accountKey{}).(string); ok {
		return account
	}
	user, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	return user
}

type accountKey struct{}

const identityLoginPath = "/.noobtunnel/identity"

// requireIdentity returns handled=true when it has answered the request with a
// login challenge/form. A false handled result carries the authenticated account
// that access rules and request logs should see.
func (h *httpResource) requireIdentity(w http.ResponseWriter, r *http.Request, res *resource) (string, bool) {
	if res.spec.IdentityMode != "login" {
		username, _, ok := r.BasicAuth()
		if ok && h.authorised(res, r) {
			return username, false
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="`+h.group.manager.brand()+`", charset="UTF-8"`)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(h.group.manager.brand() + ": this resource requires a control node account\n"))
		return "", true
	}

	if r.URL.Path == identityLoginPath && r.Method == http.MethodPost {
		return h.handleIdentityLogin(w, r)
	}
	if check := h.group.manager.IdentitySession; check != nil {
		if account, ok := check(r); ok {
			return account, false
		}
	}
	next := r.URL.RequestURI()
	if r.URL.Path == identityLoginPath || !safeIdentityNext(next) {
		next = "/"
	}
	h.writeIdentityLogin(w, next, "")
	return "", true
}

func (h *httpResource) handleIdentityLogin(w http.ResponseWriter, r *http.Request) (string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		h.writeIdentityLogin(w, "/", "Could not read that sign-in request.")
		return "", true
	}
	next := r.Form.Get("next")
	if !safeIdentityNext(next) {
		next = "/"
	}
	login := h.group.manager.IdentityLogin
	if login == nil {
		h.writeIdentityLogin(w, next, "Identity login is unavailable.")
		return "", true
	}
	account, err := login(w, r, r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		h.writeIdentityLogin(w, next, err.Error())
		return "", true
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
	return account, true
}

func safeIdentityNext(next string) bool {
	return strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") && !strings.ContainsAny(next, "\r\n")
}

func (h *httpResource) writeIdentityLogin(w http.ResponseWriter, next, message string) {
	brand := html.EscapeString(h.group.manager.brand())
	errorLine := ""
	if message != "" {
		errorLine = `<p class="error">` + html.EscapeString(message) + `</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<title>Sign in · `+brand+`</title><style>`+
		`:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#070b14;color:#eef2ff}`+
		`*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at top,#17203b 0,#070b14 48%)}`+
		`form{width:min(420px,calc(100% - 32px));padding:30px;border:1px solid #293451;border-radius:16px;background:#101725;box-shadow:0 24px 70px #0008}`+
		`h1{font-size:1.45rem;margin:0 0 8px}.sub{color:#9ba8c7;margin:0 0 24px}.field{display:grid;gap:7px;margin:14px 0;font-size:.88rem;color:#c8d1e8}`+
		`input{width:100%;padding:12px 13px;border-radius:10px;border:1px solid #34415f;background:#080e1a;color:#fff;font:inherit}`+
		`button{width:100%;margin-top:10px;padding:12px;border:0;border-radius:10px;background:#6574f7;color:#fff;font-weight:700;cursor:pointer}`+
		`.error{padding:10px 12px;border-radius:9px;background:#ef444422;color:#fca5a5;font-size:.88rem}</style></head><body>`+
		`<form method="post" action="`+identityLoginPath+`"><h1>`+brand+`</h1><p class="sub">Sign in to continue to this resource.</p>`+errorLine+
		`<input type="hidden" name="next" value="`+html.EscapeString(next)+`">`+
		`<label class="field">Username<input name="username" autocomplete="username" autofocus required></label>`+
		`<label class="field">Password<input type="password" name="password" autocomplete="current-password" required></label>`+
		`<button type="submit">Sign in</button></form></body></html>`)
}

// removeRequestCookie strips a proxy-owned cookie before the request is sent to
// the backend while leaving application cookies untouched.
func removeRequestCookie(r *http.Request, name string) {
	var kept []string
	for _, cookie := range r.Cookies() {
		if cookie.Name != name {
			kept = append(kept, cookie.String())
		}
	}
	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}

// acmeChallengePath is where ACME HTTP-01 validation happens.
const acmeChallengePath = "/.well-known/acme-challenge/"

// authorised checks the Basic credentials of an identity controlled resource.
func (h *httpResource) authorised(res *resource, r *http.Request) bool {
	check := h.group.manager.IdentityCheck
	if check == nil {
		// Without an account store there is nothing to check against; fail closed.
		return false
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return h.cachedAuth(res, username, password, func() error { return check(username, password) })
}

// authCacheTTL keeps successful logins from paying the password hash cost on
// every request.
const authCacheTTL = 60 * time.Second
const authCacheMax = 512

func (h *httpResource) cachedAuth(res *resource, username, password string, verify func() error) bool {
	// The key includes a digest of the password so a wrong password can never
	// match a cached success.
	sum := sha256.Sum256([]byte(username + "\x00" + password))
	key := fmt.Sprintf("%d:%x", res.spec.ID, sum[:16])

	h.mu.Lock()
	if entry, ok := h.authCache[key]; ok && time.Now().Before(entry.expiry) {
		h.mu.Unlock()
		return true
	}
	h.mu.Unlock()

	if err := verify(); err != nil {
		return false
	}
	h.mu.Lock()
	if len(h.authCache) >= authCacheMax {
		h.authCache = map[string]authEntry{}
	}
	h.authCache[key] = authEntry{expiry: time.Now().Add(authCacheTTL)}
	h.mu.Unlock()
	return true
}

type authEntry struct{ expiry time.Time }

// roundTrip tries each candidate target in order.
func (h *httpResource) roundTrip(res *resource, r *http.Request) (*http.Response, TargetSpec, backendTiming, error) {
	candidates := res.candidates()
	// Only buffer bounded, known-size bodies when there is a fallback target.
	// Large and chunked uploads must start flowing immediately and stay bounded
	// in memory. Never consume a prefix and then forward a closed/truncated body.
	var buffered []byte
	replayable := r.Body == nil || r.Body == http.NoBody
	if !replayable && len(candidates) > 1 && r.ContentLength >= 0 && r.ContentLength <= maxRetryBody {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxRetryBody+1))
		_ = r.Body.Close()
		if err != nil {
			return nil, TargetSpec{}, backendTiming{}, err
		}
		if int64(len(raw)) != r.ContentLength {
			return nil, TargetSpec{}, backendTiming{}, fmt.Errorf("request body length does not match Content-Length")
		}
		buffered = raw
		replayable = true
	}
	var lastErr error
	var lastTiming backendTiming
	for index, candidate := range candidates {
		if index > 0 && !replayable {
			// The body cannot be resent, so stop after the first attempt.
			break
		}
		outbound := r.Clone(r.Context())
		upgrade := isUpgrade(r)
		removeHopHeaders(outbound.Header)
		if upgrade {
			outbound.Header.Set("Connection", "Upgrade")
			outbound.Header.Set("Upgrade", r.Header.Get("Upgrade"))
		}
		if buffered != nil {
			outbound.Body = io.NopCloser(bytes.NewReader(buffered))
			outbound.ContentLength = int64(len(buffered))
		}
		outbound.URL = &url.URL{
			Scheme: "http",
			// The URL host is only what the transport dials; the Host header sent
			// to the service is the client's own (below), so a rewritten dial
			// address must not leak into the request.
			Host:     candidate.Published(),
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
		}
		outbound.RequestURI = ""
		outbound.Host = r.Host
		outbound.Close = false
		timing := &dialTiming{started: time.Now()}
		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				timing.reused.Store(info.Reused)
			},
			WroteRequest: func(httptrace.WroteRequestInfo) {
				timing.wroteAt.CompareAndSwap(0, time.Now().UnixNano())
			},
			GotFirstResponseByte: func() {
				timing.firstByte.CompareAndSwap(0, time.Now().UnixNano())
			},
		}
		outbound = outbound.WithContext(httptrace.WithClientTrace(
			context.WithValue(outbound.Context(), dialTimingKey{}, timing), trace))
		transport := h.transportFor(candidate, res.spec.ProxyProtocol)
		response, err := transport.RoundTrip(outbound)
		lastTiming = timing.snapshot()
		if err == nil {
			res.stat.targetFor(candidate.ID).setError(nil)
			return response, candidate, lastTiming, nil
		}
		lastErr = err
		// A caller that went away says nothing about the target. Recording it made
		// a healthy resource flap between live and error: a browser closing a tab,
		// a health check giving up, or the country lookup that runs while a request
		// is being served all cancel a dial, and every cancellation was being
		// written down as "the target is not reachable".
		if !callerGaveUp(r.Context(), err) {
			res.stat.targetFor(candidate.ID).setError(err)
			res.stat.setError(fmt.Errorf("target %s: %w", candidate.Published(), err))
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no targets are configured")
	}
	return nil, TargetSpec{}, lastTiming, lastErr
}

func (t *dialTiming) snapshot() backendTiming {
	wroteAt := t.wroteAt.Load()
	firstByte := t.firstByte.Load()
	dialMs := t.ms.Load()
	queueMs := int64(0)
	backendMs := int64(0)
	if wroteAt > 0 {
		queueMs = max(0, time.Unix(0, wroteAt).Sub(t.started).Milliseconds()-dialMs)
	}
	if wroteAt > 0 && firstByte >= wroteAt {
		backendMs = time.Duration(firstByte - wroteAt).Milliseconds()
	}
	return backendTiming{dialMs: dialMs, queueMs: queueMs, backendMs: backendMs, reusedConn: t.reused.Load()}
}

// Connection header tokens are hop-specific even when their names are custom.
func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

var responseBuffers = sync.Pool{New: func() any { return new([32 * 1024]byte) }}

func copyResponse(dst io.Writer, src io.Reader) {
	buf := responseBuffers.Get().(*[32 * 1024]byte)
	defer responseBuffers.Put(buf)
	// Hide ReaderFrom so the destination uses this buffer rather than allocating
	// another one. The counting source already requires a userspace copy.
	_, _ = io.CopyBuffer(struct{ io.Writer }{dst}, src, buf[:])
}

type flushWriter struct{ http.ResponseWriter }

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}

// callerGaveUp reports whether a failed connection says anything about the target.
//
// The transport dials with the request's context, so a client that disconnected, a
// deadline the caller set, or a surrounding request that was cancelled all end as
// an error on the dial - and none of them is the target's fault. Treating them as
// target failures is what made a working service alternate between "live" and
// "error" with "context canceled" as the reason.
func callerGaveUp(ctx context.Context, err error) bool {
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (h *httpResource) writeUnknownHost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	host := strings.Split(r.Host, ":")[0]
	_, _ = w.Write([]byte(h.group.manager.brand() + ": no resource is published for \"" + host + "\"\n"))
	if domains := h.group.domains(); len(domains) > 0 {
		_, _ = w.Write([]byte("configured domains: " + strings.Join(domains, ", ") + "\n"))
	} else {
		_, _ = w.Write([]byte("no domains are configured on this port\n"))
	}
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// remoteAddr turns a string address into a net.Addr for the header writers.
func remoteAddr(raw string) net.Addr {
	addr, err := net.ResolveTCPAddr("tcp", raw)
	if err != nil {
		return nil
	}
	return addr
}

// countingBody counts bytes in one direction for a resource and, when known, the
// target that served the request.
type countingBody struct {
	io.ReadCloser
	target *counters
	also   *counters
	read   bool
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	add := func(set *counters, bytes int) {
		if set == nil {
			return
		}
		if c.read {
			set.rx.Add(uint64(bytes))
		} else {
			set.tx.Add(uint64(bytes))
		}
	}
	add(c.target, n)
	add(c.also, n)
	return n, err
}
