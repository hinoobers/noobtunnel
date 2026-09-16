package agent

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

// forwardTimeout bounds reaching the loopback service behind a forward.
const forwardTimeout = 5 * time.Second

// forwarder carries one loopback service for the control node: it listens on this
// agent's own mesh address and passes connections to a service that only listens
// on this machine's loopback.
//
// A loopback address means "this machine" to whoever dials it, so the control
// node can never reach `127.0.0.1:3306` on an agent: it would reach its own. The
// agent is the machine that can, which is what these forwards are for.
type forwarder struct {
	agent  *Agent
	target string
	port   int

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
	next := map[int]*forwarder{}
	for _, want := range forwards {
		if want.Port <= 0 || want.Port > 65535 || want.Target == "" {
			continue
		}
		if existing, ok := current[want.Port]; ok && existing.target == want.Target {
			next[want.Port] = existing
			continue
		}
		next[want.Port] = &forwarder{agent: a, target: want.Target, port: want.Port, done: make(chan struct{})}
	}
	a.forwards = next
	a.mu.Unlock()

	for port, f := range current {
		if next[port] != f {
			f.stop()
		}
	}
	for port, f := range next {
		if current[port] == f {
			continue
		}
		if err := f.start(ctx, mesh); err != nil {
			// Not carried, so a later pass tries again - the address may only need
			// to come up first.
			a.mu.Lock()
			if a.forwards[port] == f {
				delete(a.forwards, port)
			}
			if a.forwardErrors == nil {
				a.forwardErrors = map[int]string{}
			}
			changed := a.forwardErrors[port] != err.Error()
			a.forwardErrors[port] = err.Error()
			a.mu.Unlock()
			if changed {
				a.log.Warn("could not carry a loopback service", "port", port, "target", f.target, "error", err)
			}
			continue
		}
		a.mu.Lock()
		delete(a.forwardErrors, port)
		a.mu.Unlock()
		a.log.Info("carrying a loopback service for the control node",
			"listen", net.JoinHostPort(mesh.String(), strconv.Itoa(port)), "target", f.target)
	}
}

// start opens the listener on the agent's mesh address, which is the only place
// the control node can reach it.
func (f *forwarder) start(ctx context.Context, mesh netip.Addr) error {
	address := net.JoinHostPort(mesh.String(), strconv.Itoa(f.port))
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
	upstream, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", f.target)
	if err != nil {
		f.agent.log.Debug("forwarded service is not reachable", "target", f.target, "error", err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
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
