package agent

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

// probeTimeout bounds one connection an agent tries on the control node's
// behalf. It is deliberately short: the answer is "does this answer at all",
// and the operator is waiting for it.
const probeTimeout = 3 * time.Second

// probeTargets answers the control node's "can you reach this from where you
// are" question.
//
// The point is to separate a broken service from a broken path. A service inside
// a container answers a plain connection from its own host and still times out
// through the tunnel, so each target is tried twice: normally, and with this
// agent's mesh address as the source - which is what the connection looks like on
// the wire when it arrives through the tunnel. The route the machine would use is
// reported with it, so a bridge interface or a missing route is visible without
// anyone having to ssh in.
func (a *Agent) probeTargets(cmd proto.Command, writer *connWriter) {
	result := proto.ProbeResult{T: proto.TProbe, Seq: cmd.Seq}
	mesh := a.meshAddress()
	for _, target := range cmd.Targets {
		target = strings.TrimSpace(target)
		if !validProbeTarget(target) {
			continue
		}
		result.Results = append(result.Results, a.probeOne(target, netip.Addr{}))
		if mesh.IsValid() {
			result.Results = append(result.Results, a.probeOne(target, mesh))
		}
		if result.Route == "" {
			result.Route = a.routeFor(target)
		}
	}
	if err := writer.send(result); err != nil {
		a.log.Warn("could not send probe results", "error", err)
	}
}

// probeOne makes one connection attempt, optionally with a chosen source
// address.
func (a *Agent) probeOne(target string, source netip.Addr) proto.ProbeEntry {
	entry := proto.ProbeEntry{Target: target, Meshed: source.IsValid()}
	dialer := &net.Dialer{Timeout: probeTimeout}
	if source.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(source.AsSlice())}
	}
	start := time.Now()
	conn, err := dialer.Dial("tcp", target)
	entry.Millis = time.Since(start).Milliseconds()
	if err != nil {
		entry.Error = err.Error()
	} else {
		entry.OK = true
		entry.LocalAddr = conn.LocalAddr().String()
		_ = conn.Close()
	}
	if entry.LocalAddr == "" {
		// A failed connection cannot report its source, so ask the routing table
		// with a connectionless dial: nothing is sent, but the kernel still
		// picks the address it would have used.
		if udp, err := dialer.Dial("udp", target); err == nil {
			entry.LocalAddr = udp.LocalAddr().String()
			_ = udp.Close()
		}
	}
	return entry
}

// routeFor asks the host which interface and source it would use for a target.
func (a *Agent) routeFor(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	out, err := a.host().Run(context.Background(), "ip", "route", "get", host)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// meshAddress is this agent's own overlay address, empty until it has enrolled.
func (a *Agent) meshAddress() netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(a.session.welcome.Address)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// validProbeTarget keeps the agent from being asked to connect to anything but a
// plain host:port, so a probe cannot be turned into a request for something else.
func validProbeTarget(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number > 0 && number <= 65535
}
