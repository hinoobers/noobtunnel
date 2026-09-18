package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

// forwardTimeout bounds reaching the loopback service behind a forward.
const forwardTimeout = 5 * time.Second

// udpForwardIdleTimeout forgets a UDP client's return path once it has been
// quiet. A fresh datagram recreates it immediately.
const udpForwardIdleTimeout = 60 * time.Second

type forwardKey struct {
	network string
	port    int
}

// forwarder carries one loopback service for the control node: it listens on this
// agent's own mesh address and passes connections to a service that only listens
// on this machine's loopback.
//
// A loopback address means "this machine" to whoever dials it, so the control
// node can never reach `127.0.0.1:3306` on an agent: it would reach its own. The
// agent is the machine that can, which is what these forwards are for.
type forwarder struct {
	agent          *Agent
	target         string
	resolvedTarget string
	port           int
	network        string

	mu   sync.Mutex
	ln   net.Listener
	pc   net.PacketConn
	done chan struct{}
}

// syncForwards starts the forwards that should be running and stops the rest.
//
// It is called again on a timer: binding the agent's mesh address fails until the
// device has that address, and a listener that could not be opened has to be
// retried rather than quietly forgotten.
func (a *Agent) syncForwards(ctx context.Context) {
	a.mu.Lock()
	if a.session == nil {
		a.mu.Unlock()
		return
	}
	forwards := append([]proto.Forward(nil), a.session.forwards...)
	mesh, err := netip.ParseAddr(a.session.welcome.Address)
	if err != nil {
		a.mu.Unlock()
		return
	}
	current := a.forwards
	next := map[forwardKey]*forwarder{}
	for _, want := range forwards {
		if want.Port <= 0 || want.Port > 65535 || want.Target == "" {
			continue
		}
		network := strings.ToLower(strings.TrimSpace(want.Protocol))
		if network != "udp" {
			network = "tcp"
		}
		key := forwardKey{network: network, port: want.Port}
		if existing, ok := current[key]; ok && existing.target == want.Target {
			next[key] = existing
			continue
		}
		next[key] = &forwarder{agent: a, target: want.Target, port: want.Port, network: network, done: make(chan struct{})}
	}
	a.forwards = next
	a.mu.Unlock()

	for port, f := range current {
		if next[port] != f {
			f.stop()
		}
	}
	for key, f := range next {
		if current[key] == f {
			continue
		}
		if err := f.start(ctx, mesh); err != nil {
			// Not carried, so a later pass tries again - the address may only need
			// to come up first.
			a.mu.Lock()
			if a.forwards[key] == f {
				delete(a.forwards, key)
			}
			if a.forwardErrors == nil {
				a.forwardErrors = map[forwardKey]string{}
			}
			changed := a.forwardErrors[key] != err.Error()
			a.forwardErrors[key] = err.Error()
			a.mu.Unlock()
			if changed {
				a.log.Warn("could not carry a loopback service", "protocol", f.network, "port", f.port, "target", f.target, "error", err)
			}
			continue
		}
		a.mu.Lock()
		delete(a.forwardErrors, key)
		a.mu.Unlock()
		a.log.Info("carrying a loopback service for the control node",
			"protocol", f.network, "listen", net.JoinHostPort(mesh.String(), strconv.Itoa(f.port)), "target", f.target)
	}
}

// start opens the listener on the agent's mesh address, which is the only place
// the control node can reach it.
func (f *forwarder) start(ctx context.Context, mesh netip.Addr) error {
	resolved, err := resolveForwardTarget(f.target)
	if err != nil {
		return err
	}
	f.resolvedTarget = resolved
	address := net.JoinHostPort(mesh.String(), strconv.Itoa(f.port))
	if f.network == "udp" {
		pc, err := net.ListenPacket("udp", address)
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.pc = pc
		f.mu.Unlock()
		go f.servePackets(ctx, pc)
		return nil
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()
	go f.serve(ctx, ln)
	return nil
}

// resolveForwardTarget turns the Pterodactyl-local marker into the address
// Wings really binds on this machine. Reading the host interface is enough; the
// agent deliberately does not mount Docker's root-equivalent control socket.
func resolveForwardTarget(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || !strings.EqualFold(host, "pterodactyl") {
		return target, err
	}
	iface, err := net.InterfaceByName("pterodactyl0")
	if err != nil {
		return "", fmt.Errorf("find Pterodactyl bridge pterodactyl0: %w", err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("read Pterodactyl bridge pterodactyl0: %w", err)
	}
	for _, raw := range addresses {
		prefix, err := netip.ParsePrefix(raw.String())
		if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
			return net.JoinHostPort(prefix.Addr().String(), port), nil
		}
	}
	return "", fmt.Errorf("Pterodactyl bridge pterodactyl0 has no IPv4 address")
}

// servePackets keeps one connected loopback socket per mesh-side client. The
// control node already uses one source socket per public UDP client, so this
// second mapping preserves replies and concurrent game sessions end to end.
func (f *forwarder) servePackets(ctx context.Context, pc net.PacketConn) {
	type session struct {
		client net.Addr
		conn   net.Conn
		mu     sync.Mutex
		last   time.Time
	}
	touch := func(s *session) {
		s.mu.Lock()
		s.last = time.Now()
		s.mu.Unlock()
	}
	lastSeen := func(s *session) time.Time {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.last
	}

	sessions := map[string]*session{}
	var sessionsMu sync.Mutex
	done := make(chan struct{})
	defer func() {
		close(done)
		sessionsMu.Lock()
		defer sessionsMu.Unlock()
		for _, s := range sessions {
			_ = s.conn.Close()
		}
	}()

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = pc.Close()
				return
			case <-f.done:
				return
			case <-done:
				return
			case now := <-ticker.C:
				sessionsMu.Lock()
				for key, s := range sessions {
					if now.Sub(lastSeen(s)) > udpForwardIdleTimeout {
						_ = s.conn.Close()
						delete(sessions, key)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		n, client, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		key := client.String()
		sessionsMu.Lock()
		s := sessions[key]
		if s == nil {
			conn, err := net.DialTimeout("udp", f.resolvedTarget, forwardTimeout)
			if err != nil {
				sessionsMu.Unlock()
				f.agent.log.Debug("forwarded UDP service is not reachable", "target", f.resolvedTarget, "error", err)
				continue
			}
			s = &session{client: client, conn: conn, last: time.Now()}
			sessions[key] = s
			go func(key string, s *session) {
				reply := make([]byte, 64*1024)
				for {
					n, err := s.conn.Read(reply)
					if err != nil {
						break
					}
					if _, err := pc.WriteTo(reply[:n], s.client); err != nil {
						break
					}
					touch(s)
				}
				sessionsMu.Lock()
				if sessions[key] == s {
					delete(sessions, key)
				}
				sessionsMu.Unlock()
				_ = s.conn.Close()
			}(key, s)
		}
		sessionsMu.Unlock()
		touch(s)
		if _, err := s.conn.Write(buf[:n]); err != nil {
			sessionsMu.Lock()
			if sessions[key] == s {
				delete(sessions, key)
			}
			sessionsMu.Unlock()
			_ = s.conn.Close()
		}
	}
}

func (f *forwarder) serve(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go f.handle(ctx, conn)
	}
}

// handle connects to the loopback service and passes the stream through, in both
// directions, until either side closes.
func (f *forwarder) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	dialCtx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	upstream, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", f.resolvedTarget)
	if err != nil {
		f.agent.log.Debug("forwarded service is not reachable", "target", f.resolvedTarget, "error", err)
		return
	}
	defer upstream.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
		case <-f.done:
		case <-finished:
			return
		}
		_ = client.Close()
		_ = upstream.Close()
	}()
	done := make(chan struct{}, 2)
	copyStream := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok && err == nil {
			_ = tcp.CloseWrite()
		} else {
			_ = client.Close()
			_ = upstream.Close()
		}
		done <- struct{}{}
	}
	go copyStream(upstream, client)
	go copyStream(client, upstream)
	// EOF in one direction can mean a request has finished, while the reply
	// is still being generated. Preserve that TCP half-close.
	<-done
	<-done
}

func (f *forwarder) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		_ = f.ln.Close()
		f.ln = nil
	}
	if f.pc != nil {
		_ = f.pc.Close()
		f.pc = nil
	}
	select {
	case <-f.done:
	default:
		close(f.done)
	}
}
