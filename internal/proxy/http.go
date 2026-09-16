package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/access"
)

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
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConnsPerHost:   8,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	if proxyProtocol != ProxyProtocolNone {
		transport.DisableKeepAlives = true
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
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
	if res.spec.Identity && !h.authorised(res, r) {
		h.group.manager.observe(RequestEvent{
			ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
			Protocol: string(res.spec.Protocol), Allowed: false, Reason: "identity required",
			Status: http.StatusUnauthorized, Path: r.URL.Path,
			DurationMs: time.Since(started).Milliseconds(),
		})
		w.Header().Set("WWW-Authenticate", `Basic realm="`+h.group.manager.brand()+`", charset="UTF-8"`)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(h.group.manager.brand() + ": this resource requires a control node account\n"))
		return
	}
	// Access rules run after authentication, so a rule can look at the account.
	if len(res.spec.Rules) > 0 {
		decision := access.Evaluate(res.spec.Rules, access.Request{
			IP:      clientIP(r.RemoteAddr),
			Country: h.countryOf(r.RemoteAddr),
			Host:    r.Host,
			Path:    r.URL.Path,
			Account: accountOf(r),
		})
		if !decision.Allow {
			h.group.manager.observe(RequestEvent{
				ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
				Country: h.countryOf(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
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
	res.stat.set.active.Add(1)
	res.stat.set.total.Add(1)
	defer res.stat.set.active.Add(-1)

	client := remoteAddr(r.RemoteAddr)
	if res.spec.ProxyProtocol != ProxyProtocolNone {
		r = r.WithContext(context.WithValue(r.Context(), clientInfoKey{}, clientInfo{
			addr:    client,
			version: res.spec.ProxyProtocol,
		}))
	}
	if r.Body != nil {
		r.Body = &countingBody{ReadCloser: r.Body, target: &res.stat.set}
	}

	response, chosen, err := h.roundTrip(res, r)
	if err != nil {
		res.stat.setError(err)
		h.group.manager.observe(RequestEvent{
			ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
			Country: h.countryOf(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
			Allowed: false, Reason: "no target answered", Status: http.StatusBadGateway, Path: r.URL.Path,
			DurationMs: time.Since(started).Milliseconds(),
		})
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(h.group.manager.brand() + ": none of the targets answered\n"))
		return
	}
	defer response.Body.Close()
	res.stat.setError(nil)

	response.Body = &countingBody{ReadCloser: response.Body, target: &res.stat.set, also: &res.stat.targetFor(chosen.ID).set, read: true}
	copyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
	res.stat.targetFor(chosen.ID).set.total.Add(1)
	h.group.manager.observe(RequestEvent{
		ResourceID: res.spec.ID, Resource: res.spec.Name, Host: r.Host, IP: clientIP(r.RemoteAddr),
		Country: h.countryOf(r.RemoteAddr), Account: accountOf(r), Protocol: string(res.spec.Protocol),
		Allowed: true, Status: response.StatusCode, Path: r.URL.Path,
		DurationMs: time.Since(started).Milliseconds(),
	})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
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

// accountOf reports the signed in account, when identity control ran first.
func accountOf(r *http.Request) string {
	user, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	return user
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
func (h *httpResource) roundTrip(res *resource, r *http.Request) (*http.Response, TargetSpec, error) {
	candidates := res.candidates()
	// Buffer a request body so that a retry sends the whole thing again.
	var buffered []byte
	replayable := true
	if r.Body != nil && r.ContentLength != 0 {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxRetryBody+1))
		_ = r.Body.Close()
		if err != nil || len(raw) > maxRetryBody {
			replayable = false
		} else {
			buffered = raw
		}
	}
	var lastErr error
	for index, candidate := range candidates {
		if index > 0 && !replayable {
			// The body cannot be resent, so stop after the first attempt.
			break
		}
		outbound := r.Clone(r.Context())
		if buffered != nil {
			outbound.Body = io.NopCloser(bytes.NewReader(buffered))
			outbound.ContentLength = int64(len(buffered))
		}
		outbound.URL = &url.URL{
			Scheme:   "http",
			Host:     candidate.Address(),
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
		}
		outbound.RequestURI = ""
		outbound.Host = r.Host
		outbound.Close = false
		transport := h.transportFor(candidate, res.spec.ProxyProtocol)
		response, err := transport.RoundTrip(outbound)
		if err == nil {
			res.stat.targetFor(candidate.ID).setError(nil)
			return response, candidate, nil
		}
		lastErr = err
		res.stat.targetFor(candidate.ID).setError(err)
		res.stat.setError(fmt.Errorf("target %s: %w", candidate.Address(), err))
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no targets are configured")
	}
	return nil, TargetSpec{}, lastErr
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
