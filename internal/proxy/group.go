package proxy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// group is one listening socket, shared by every resource routed through it.
type group struct {
	manager *Manager
	log     *slog.Logger
	key     string
	proto   string
	bind    string
	port    int

	mu       sync.RWMutex
	routes   map[string]*resource
	fallback *resource
	single   *resource
	closed   bool

	listener  net.Listener
	packet    net.PacketConn
	httpSrv   *httpResource
	httpsSrv  *httpsResource
	closeOnce sync.Once
}

// setTargets swaps the routing table for this listener.
func (g *group) setTargets(resources []*resource) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routes = map[string]*resource{}
	g.fallback = nil
	g.single = nil

	switch g.proto {
	case ProtoTCP, ProtoUDP:
		if len(resources) > 0 {
			g.single = resources[0]
		}
	default:
		for _, r := range resources {
			domain := strings.ToLower(strings.TrimSpace(r.spec.Domain))
			if domain == "" {
				if g.fallback == nil {
					g.fallback = r
				}
				continue
			}
			g.routes[domain] = r
		}
	}
}

// route picks the resource for a hostname (HTTP Host header or TLS SNI).
func (g *group) route(host string) (*resource, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	name := strings.ToLower(strings.TrimSpace(host))
	name = strings.TrimSuffix(name, ".")
	if colon := strings.IndexByte(name, ':'); colon >= 0 {
		name = name[:colon]
	}
	if r, ok := g.routes[name]; ok {
		return r, true
	}
	for alias, r := range g.routes {
		if strings.HasSuffix(name, "."+alias) {
			return r, true
		}
	}
	// A resource without a domain only serves when nothing else claims the port,
	// so a typo cannot silently land on the wrong service.
	if g.fallback != nil && len(g.routes) == 0 {
		return g.fallback, true
	}
	return nil, false
}

func (g *group) domains() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0, len(g.routes))
	for name := range g.routes {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (g *group) currentSingle() (*resource, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.single == nil {
		return nil, false
	}
	return g.single, true
}

func (g *group) addr() string {
	if g.listener != nil {
		return g.listener.Addr().String()
	}
	if g.packet != nil {
		return g.packet.LocalAddr().String()
	}
	return ""
}

// start binds the socket and begins serving.
func (g *group) start(dialTimeout time.Duration) error {
	addr := net.JoinHostPort(g.bind, strconv.Itoa(g.port))
	switch g.proto {
	case ProtoTCP:
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on tcp/%d%s: %w", g.port, bindSuffix(g.bind), err)
		}
		g.listener = ln
		go g.serveTCP(ln, dialTimeout)
	case ProtoUDP:
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fmt.Errorf("listen on udp/%d%s: %w", g.port, bindSuffix(g.bind), err)
		}
		g.packet = pc
		go g.serveUDP(pc, dialTimeout)
	case ProtoHTTP:
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on tcp/%d%s: %w", g.port, bindSuffix(g.bind), err)
		}
		g.listener = ln
		g.httpSrv = newHTTPResource(g, dialTimeout)
		go func() {
			if err := g.httpSrv.serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
				g.log.Debug("http resource listener stopped", "port", g.port, "error", err)
			}
		}()
	case ProtoHTTPS:
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on tcp/%d%s: %w", g.port, bindSuffix(g.bind), err)
		}
		g.listener = ln
		provider := g.manager.Certificates
		if provider == nil {
			provider = NewSelfSignedProvider()
		}
		g.httpsSrv = newHTTPSResource(g, dialTimeout, provider)
		go func() {
			if err := g.httpsSrv.serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
				g.log.Debug("https resource listener stopped", "port", g.port, "error", err)
			}
		}()
	case ProtoHTTPSPassthrough:
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on tcp/%d%s: %w", g.port, bindSuffix(g.bind), err)
		}
		g.listener = ln
		go g.serveTLSPassthrough(ln, dialTimeout)
	default:
		return fmt.Errorf("unsupported protocol %q", g.proto)
	}
	return nil
}

func bindSuffix(bind string) string {
	if bind == "" {
		return ""
	}
	return " on " + bind
}

func (g *group) close() {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.closed = true
		g.mu.Unlock()
		if g.httpSrv != nil {
			g.httpSrv.close()
		}
		if g.httpsSrv != nil {
			g.httpsSrv.close()
		}
		if g.listener != nil {
			_ = g.listener.Close()
		}
		if g.packet != nil {
			_ = g.packet.Close()
		}
	})
}

func (g *group) isClosed() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.closed
}

// countWriter counts bytes flowing in one direction.
type countWriter struct{ sets []*counters }

func (c countWriter) Write(p []byte) (int, error) {
	for _, set := range c.sets {
		set.tx.Add(uint64(len(p)))
	}
	return len(p), nil
}

// dialTarget opens the tunnel side of a connection to a backend.
func dialTarget(target string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.Dial("tcp", target)
}

// dialCandidates connects to the first backend that answers. Every failing
// target is recorded so the UI can show which one is broken.
func dialCandidates(r *resource, timeout time.Duration) (net.Conn, TargetSpec, error) {
	var lastErr error
	for _, candidate := range r.candidates() {
		conn, err := dialTarget(candidate.Address(), timeout)
		if err == nil {
			r.stat.targetFor(candidate.ID).setError(nil)
			return conn, candidate, nil
		}
		lastErr = err
		r.stat.targetFor(candidate.ID).setError(err)
		r.stat.setError(fmt.Errorf("target %s: %w", candidate.Published(), err))
	}
	if lastErr == nil {
		lastErr = errors.New("no targets are configured")
	}
	return nil, TargetSpec{}, lastErr
}

// serveTCP forwards a dedicated port to one resource.
func (g *group) serveTCP(ln net.Listener, dialTimeout time.Duration) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if g.isClosed() {
				return
			}
			g.log.Debug("accept failed", "port", g.port, "error", err)
			return
		}
		target, ok := g.currentSingle()
		if !ok {
			_ = conn.Close()
			continue
		}
		go func(conn net.Conn, r *resource) {
			upstream, chosen, err := dialCandidates(r, dialTimeout)
			if err != nil {
				_ = conn.Close()
				return
			}
			if r.spec.ProxyProtocol != ProxyProtocolNone {
				if err := writeProxyHeader(upstream, r.spec.ProxyProtocol, conn.RemoteAddr(), upstream.RemoteAddr()); err != nil {
					r.stat.setError(err)
					_ = upstream.Close()
					_ = conn.Close()
					return
				}
			}
			r.stat.setError(nil)
			pipe(conn, upstream, &r.stat.set, &r.stat.targetFor(chosen.ID).set)
		}(conn, target)
	}
}

// serveTLSPassthrough routes TLS connections by the SNI in the ClientHello and
// forwards the stream untouched, so the service behind the tunnel keeps its own
// certificate and the control node never sees plaintext.
func (g *group) serveTLSPassthrough(ln net.Listener, dialTimeout time.Duration) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if g.isClosed() {
				return
			}
			g.log.Debug("accept failed", "port", g.port, "error", err)
			return
		}
		go func(conn net.Conn) {
			_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			hello, err := peekClientHello(conn)
			if err != nil {
				g.log.Debug("could not read TLS ClientHello", "error", err)
				_ = conn.Close()
				return
			}
			_ = conn.SetReadDeadline(time.Time{})
			target, ok := g.route(hello.ServerName)
			if !ok {
				g.log.Debug("no resource matches that TLS server name",
					"serverName", hello.ServerName, "configured", strings.Join(g.domains(), ", "))
				_ = conn.Close()
				return
			}
			upstream, chosen, err := dialCandidates(target, dialTimeout)
			if err != nil {
				_ = conn.Close()
				return
			}
			if target.spec.ProxyProtocol != ProxyProtocolNone {
				if err := writeProxyHeader(upstream, target.spec.ProxyProtocol, conn.RemoteAddr(), upstream.RemoteAddr()); err != nil {
					target.stat.setError(err)
					_ = upstream.Close()
					_ = conn.Close()
					return
				}
			}
			target.stat.setError(nil)
			// Replay the bytes we already consumed, then pipe the rest.
			if _, err := upstream.Write(hello.Raw); err != nil {
				_ = upstream.Close()
				_ = conn.Close()
				return
			}
			pipe(conn, upstream, &target.stat.set, &target.stat.targetFor(chosen.ID).set)
		}(conn)
	}
}

// pipe copies traffic between a client and a backend, counting bytes into every
// supplied counter set (the resource and the chosen target) and closing both ends
// when either direction finishes.
func pipe(client, upstream net.Conn, sets ...*counters) {
	for _, set := range sets {
		set.active.Add(1)
		set.total.Add(1)
	}
	defer func() {
		for _, set := range sets {
			set.active.Add(-1)
		}
	}()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, io.TeeReader(client, countWriter{sets}))
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, io.TeeReader(upstream, reverseWriter{sets}))
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = client.Close()
	_ = upstream.Close()
}

// reverseWriter counts bytes coming back from the service.
type reverseWriter struct{ sets []*counters }

func (c reverseWriter) Write(p []byte) (int, error) {
	for _, set := range c.sets {
		set.rx.Add(uint64(len(p)))
	}
	return len(p), nil
}
