package control

import (
	"net"
	"sort"

	"github.com/noobtunnel/noobtunnel/internal/proto"
	"github.com/noobtunnel/noobtunnel/internal/store"
)

// forwardPorts assigns a stable mesh-side port to every enabled resource target
// behind an agent. The port is scoped to the agent and protocol; collisions are
// resolved deterministically so two resources can use the same private IP:port.
func (s *Server) forwardPorts(agentID uint32) map[[2]uint32]int {
	resources := s.store.Resources()
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	ports := map[[2]uint32]int{}
	occupied := map[string]map[int]bool{"tcp": {}, "udp": {}}
	for _, resource := range resources {
		if !resource.Enabled {
			continue
		}
		protocol := "tcp"
		if resource.Protocol == store.ProtocolUDP {
			protocol = "udp"
		}
		for _, target := range resource.Targets {
			if !target.Enabled || target.AgentID != agentID {
				continue
			}
			agent, err := s.store.Agent(agentID)
			if err != nil || target.Host == agent.Address {
				continue
			}
			port := 30000 + int((uint64(resource.ID)*1315423911+uint64(target.ID)*2654435761)%30000)
			for occupied[protocol][port] {
				port++
				if port == 60000 {
					port = 30000
				}
			}
			occupied[protocol][port] = true
			ports[[2]uint32{resource.ID, target.ID}] = port
		}
	}
	return ports
}

// DialAddress is where the control node connects for a resource target. Every
// non-mesh address is dialled by its selected agent, avoiding ambiguous private
// ranges on the control node.
func (s *Server) DialAddress(resourceID uint32, target store.ResourceTarget) string {
	agent, err := s.store.Agent(target.AgentID)
	if err != nil || target.Host == agent.Address {
		return target.Target()
	}
	if port := s.forwardPorts(target.AgentID)[[2]uint32{resourceID, target.ID}]; port != 0 {
		return net.JoinHostPort(agent.Address, itoa(port))
	}
	return target.Target()
}

// loopbackTargetOf is used by diagnosis for an agent-local address.
func loopbackTargetOf(s *Server, agentID uint32, address string) (string, bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !store.IsAgentLocalTarget(host) {
		return "", false
	}
	agent, err := s.store.Agent(agentID)
	if err != nil {
		return "", false
	}
	return net.JoinHostPort(agent.Address, port), true
}

// Forwards is the service list an agent has to carry for the control node.
func (s *Server) Forwards(agentID uint32) []proto.Forward { return s.forwardsFor(agentID) }

func (s *Server) forwardsFor(agentID uint32) []proto.Forward {
	ports := s.forwardPorts(agentID)
	var out []proto.Forward
	if cfg := s.geoIPCredentials(); cfg.AgentID == agentID && cfg.Host != "" && (cfg.Provider != "ipapi" || cfg.FallbackEnabled) {
		if target, err := geoIPForwardTarget(cfg.Host); err == nil {
			out = append(out, proto.Forward{Port: geoIPForwardPort, Target: target, Protocol: "tcp"})
		}
	}
	for _, resource := range s.store.Resources() {
		protocol := "tcp"
		if resource.Protocol == store.ProtocolUDP {
			protocol = "udp"
		}
		for _, target := range resource.Targets {
			if port := ports[[2]uint32{resource.ID, target.ID}]; port != 0 {
				out = append(out, proto.Forward{Port: port, Target: target.Target(), Protocol: protocol})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}
