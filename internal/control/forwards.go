package control

import (
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/proto"
	"github.com/noobtunnel/noobtunnel/internal/store"
)

// isLoopbackTarget reports whether a target address can only be reached by the
// machine it names: 127.0.0.0/8, ::1.
func isLoopbackTarget(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// DialAddress is the address the control node dials for a target.
//
// For a loopback target that is the agent's own mesh address: `127.0.0.1` means
// "this machine" to whoever dials it, and the kernel resolves it locally before
// any route the mesh installs, so the agent is the only machine that can reach
// it - and it listens there for exactly this purpose.
func (s *Server) DialAddress(target store.ResourceTarget) string {
	if !isLoopbackTarget(target.Host) {
		return target.Target()
	}
	agent, err := s.store.Agent(target.AgentID)
	if err != nil {
		return target.Target()
	}
	return net.JoinHostPort(agent.Address, itoa(target.Port))
}

// loopbackTargetOf answers where the control node should dial a target: the
// agent's mesh address when the service only listens on that machine's loopback.
func loopbackTargetOf(s *Server, agentID uint32, address string) (string, bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !isLoopbackTarget(host) {
		return "", false
	}
	agent, err := s.store.Agent(agentID)
	if err != nil {
		return "", false
	}
	return net.JoinHostPort(agent.Address, port), true
}

// Forwards is what an agent has to carry for the control node. It is exported so
// a diagnosis or a test can ask the same question the agent is asked.
func (s *Server) Forwards(agentID uint32) []proto.Forward {
	return s.forwardsFor(agentID)
}

// forwardsFor is what a given agent has to carry for the control node: the
// loopback services published through it, one entry per port.
func (s *Server) forwardsFor(agentID uint32) []proto.Forward {
	type key struct {
		protocol string
		port     int
	}
	byPort := map[key]string{}
	for _, resource := range s.store.Resources() {
		if !resource.Enabled {
			continue
		}
		for _, target := range resource.Targets {
			if !target.Enabled || target.AgentID != agentID || !isLoopbackTarget(target.Host) {
				continue
			}
			protocol := "tcp"
			if resource.Protocol == store.ProtocolUDP {
				protocol = "udp"
			}
			k := key{protocol: protocol, port: target.Port}
			if _, taken := byPort[k]; taken {
				continue
			}
			byPort[k] = target.Target()
		}
	}
	out := make([]proto.Forward, 0, len(byPort))
	for key, target := range byPort {
		out = append(out, proto.Forward{Port: key.port, Target: target, Protocol: key.protocol})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return strings.Compare(out[i].Protocol, out[j].Protocol) < 0
	})
	return out
}
