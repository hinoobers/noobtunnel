package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proto"
	"github.com/noobtunnel/noobtunnel/internal/store"
)

// DiagnoseStep is one check the control node runs on itself, so an operator does
// not have to SSH in to find out which side of a published service is broken.
type DiagnoseStep struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail"`
	// Hint is what to do when the step is not ok.
	Hint string `json:"hint,omitempty"`
}

// DiagnoseResult is the answer to "why can nobody reach this target".
type DiagnoseResult struct {
	Target        string         `json:"target"`
	Resource      string         `json:"resource"`
	Steps         []DiagnoseStep `json:"steps"`
	Verdict       string         `json:"verdict"`
	VerdictStatus string         `json:"verdictStatus"`
}

// handleDiagnose checks one target of one resource from this machine.
func (s *Server) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use POST"))
		return
	}
	var body struct {
		ResourceID uint32 `json:"resourceId"`
		TargetID   uint32 `json:"targetId"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	resource, err := s.store.Resource(body.ResourceID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("no such resource"))
		return
	}
	address, agentID, found := "", uint32(0), false
	for _, target := range resource.Targets {
		if target.ID == body.TargetID {
			address, agentID, found = target.Target(), target.AgentID, true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("no such target"))
		return
	}
	writeJSON(w, http.StatusOK, s.diagnoseTarget(r.Context(), resource, agentID, address))
}

// diagnoseTarget walks the path a connection takes: the control node's own
// WireGuard device, its route and handshake with the agent that hosts the target,
// and finally a real TCP connection attempt.
func (s *Server) diagnoseTarget(ctx context.Context, resource store.Resource, agentID uint32, address string) DiagnoseResult {
	result := DiagnoseResult{Target: address, Resource: resource.Name, Steps: []DiagnoseStep{}}
	add := func(name, status, detail, hint string) {
		result.Steps = append(result.Steps, DiagnoseStep{Name: name, Status: status, Detail: detail, Hint: hint})
	}

	backend := s.backend.Name()
	if strings.HasPrefix(backend, "fake") {
		add("WireGuard backend", "fail",
			"this control node runs the simulated backend ("+backend+")",
			"restart the control node without --backend fake: no interface exists on this host, so no target can be reached")
	} else {
		add("WireGuard backend", "ok", backend, "")
	}

	settings := s.store.Settings()
	// The connection this node makes is answered into its own INPUT chain, so a
	// host firewall that rejects the mesh interface breaks every target here while
	// the agent side looks perfect.
	if runtime.GOOS == "linux" {
		if inbound := s.inboundCheck(ctx, settings.Interface); inbound.Status == statusFail {
			add("Inbound mesh traffic", "fail", inbound.Detail, inbound.Fix)
		}
	}
	status, err := s.backend.Status(ctx, settings.Interface)
	switch {
	case err != nil:
		add("Hub interface", "fail", err.Error(),
			"load the module (modprobe wireguard) and check that wg(8) and ip(8) are installed")
	case !status.Exists:
		add("Hub interface", "fail", settings.Interface+" does not exist on this host",
			"load the module (modprobe wireguard) and look at journalctl -u noobtunnel-server")
	default:
		add("Hub interface", "ok", fmt.Sprintf("%s is up with %d peer(s)", status.Name, len(status.Peers)), "")
	}

	// The handshake is the proof that the tunnel to that agent works: an agent
	// whose device was never configured has no handshake at all.
	s.mu.Lock()
	hubStatus := s.hubStatus
	s.mu.Unlock()
	var peerKey string
	if agent, err := s.store.Agent(agentID); err == nil {
		peerKey = agent.PublicKey
	}
	handshake := time.Time{}
	for _, peer := range hubStatus.Peers {
		if peerKey != "" && peer.PublicKey == peerKey {
			handshake = peer.LatestHandshake
		}
	}
	switch {
	case peerKey == "":
		add("Tunnel handshake", "warn", "the agent behind this target has not enrolled yet",
			"enroll the agent first; a target cannot be reached before its machine is on the mesh")
	case handshake.IsZero():
		add("Tunnel handshake", "fail", "no WireGuard handshake with the agent behind this target",
			"the agent is connected but its device is not configured: update and restart the agent on that machine")
	default:
		add("Tunnel handshake", "ok", "last handshake "+s.now().Sub(handshake).Round(time.Second).String()+" ago", "")
	}

	// `ip route get` wants an address, not host:port: passing the target as the
	// operator types it makes it answer "any valid prefix is expected rather
	// than "10.0.0.5:4702"".
	routeTarget := address
	if host, _, splitErr := net.SplitHostPort(address); splitErr == nil && host != "" {
		routeTarget = host
	}
	if out, err := s.runner().Run(ctx, "ip", "route", "get", routeTarget); err != nil {
		detail := strings.TrimSpace(out)
		if detail == "" {
			// No output to show: the command itself is what failed.
			detail = err.Error()
		}
		add("Route from the control node", "warn", firstLine(detail),
			"the route is normally installed with the interface: check journalctl -u noobtunnel-server")
	} else {
		add("Route from the control node", "ok", firstLine(strings.TrimSpace(out)), "")
	}

	if resource.Protocol == store.ProtocolUDP {
		// A UDP service has no handshake to test, so the tunnel, the route and the
		// agent's own view are the whole diagnosis.
		add("Connect to the target", "warn",
			"UDP cannot be tested with a connection attempt",
			"check the service on the agent side, and that the resource forwards to the right port")
		result.Verdict = "the checks above are what can be verified for a UDP target"
		result.VerdictStatus = "warn"
		return result
	}

	host := routeTarget
	// Whose traffic is this? A network is routed to exactly one agent, so a
	// target that another agent carries never arrives where the resource thinks
	// it is going - and nothing on this side of the tunnel can see that, because
	// nothing arrives at all.
	routingBroken := false
	if err := s.store.CheckTargetReachability(agentID, host); err != nil {
		routingBroken = true
		add("Mesh routing", "fail", err.Error(),
			"a network is routed to one agent only: drop it from one of them, or advertise a range only that machine can reach")
		result.Verdict = err.Error()
		result.VerdictStatus = "fail"
	} else if agent, err := s.store.Agent(agentID); err == nil {
		// Say out loud where the address goes: it is pinned to the agent the
		// resource names, which is what makes two machines with the same private
		// range work at once, and the one thing a capture on that machine cannot
		// show.
		add("Mesh routing", "ok",
			host+"/32 is delivered to "+agent.Name+", the agent this target names",
			"")
	}
	// Anything that already failed before the connection attempt is the cause,
	// and the agent's answer is only a consequence of it: a control node whose own
	// hub is not up cannot reach anything, no matter what the agent sees.
	priorFailures := 0
	for _, step := range result.Steps {
		if step.Status == "fail" {
			priorFailures++
		}
	}
	// Set when the agent's own answer explains the failure: it knows more about
	// that side than any step the control node can run on itself.
	verdictFromProbe := routingBroken
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	switch {
	case dialErr != nil:
		add("Connect to the target", "fail", dialErr.Error(), dialHint(dialErr, address, host))
		result.Verdict = "the control node cannot open a connection to " + address
		result.VerdictStatus = "fail"
		// The control node can see the tunnel and its own route, but not what
		// happens on the other side of it. Ask the agent: does the service answer
		// on its own machine at all, and does it answer a connection whose source
		// is the mesh address, which is what the tunnel looks like on the wire?
		probe, probeErr := s.ProbeTargets(ctx, agentID, []string{address})
		switch {
		case probeErr != nil:
			add("Reach the target from the agent", "warn", probeErr.Error(),
				"the agent could not be asked to try it itself; update the agent on that machine and run this again")
		default:
			reached, meshed, local := probeReading(probe)
			verdictFromProbe = priorFailures == 0
			switch {
			case reached && !meshed:
				add("Reach the target from the agent", "fail",
					"the agent reaches "+address+" in "+probeMillis(probe)+" from "+local+", but not from its own mesh address",
					"the service answers on this machine and refuses mesh-sourced traffic: check the host firewall and rp_filter on the interface the service is on")
				result.Verdict = "the service is healthy on that machine; the traffic coming from the mesh is what it will not answer"
			case reached && meshed:
				add("Reach the target from the agent", "ok",
					"the agent reaches "+address+" from "+local+", and also from its mesh address",
					"")
				result.Verdict = "the service answers the agent, from the mesh address too, so the break is on the path between the two machines"
			default:
				add("Reach the target from the agent", "fail",
					"the agent cannot reach "+address+" either: "+probeError(probe),
					"the service is not reachable from the machine that hosts it: check the listener and the container network")
				result.Verdict = "the service does not answer on the agent's own machine either"
			}
			if route := strings.TrimSpace(probe.Route); route != "" {
				add("Route on the agent", "ok", firstLine(route), "")
			}
		}
	default:
		_ = conn.Close()
		add("Connect to the target", "ok", "connected to "+address, "")
		result.Verdict = "the control node reached " + address + ": the service and the tunnel are both fine"
		result.VerdictStatus = "ok"
	}

	if result.VerdictStatus != "ok" && !verdictFromProbe {
		for _, step := range result.Steps {
			if step.Status == "fail" {
				result.Verdict = step.Name + ": " + step.Detail
				break
			}
		}
	}
	return result
}

// firstLine keeps a command's output to one readable line.
func firstLine(raw string) string {
	if index := strings.IndexByte(raw, '\n'); index >= 0 {
		return strings.TrimSpace(raw[:index])
	}
	return raw
}

// dialHint explains a failed connection attempt in terms of what it means.
//
// The distinction matters: "no route to host" is the tunnel, "connection
// refused" is nothing listening, and a silent timeout is the case that sends
// operators hunting for a healthy service - the packets arrive, the answers do
// not come back.
// probeReading is the control node's half of a probe: whether the target answers
// on the machine that hosts it, whether it answers a connection whose source is
// the mesh address, and which source the agent actually used.
func probeReading(probe proto.ProbeResult) (reached, meshed bool, local string) {
	for _, entry := range probe.Results {
		if entry.Meshed {
			meshed = meshed || entry.OK
			continue
		}
		if entry.OK {
			reached = true
			local = entry.LocalAddr
		}
	}
	return reached, meshed, local
}

// probeError is the first failure the agent saw, for a step's detail.
func probeError(probe proto.ProbeResult) string {
	for _, entry := range probe.Results {
		if entry.Error != "" {
			return entry.Error
		}
	}
	return "no answer"
}

// probeMillis names how long the agent's successful attempt took.
func probeMillis(probe proto.ProbeResult) string {
	for _, entry := range probe.Results {
		if entry.OK && !entry.Meshed {
			return fmt.Sprintf("%dms", entry.Millis)
		}
	}
	return "no time"
}

func dialHint(dialErr error, address, host string) string {
	message := strings.ToLower(dialErr.Error())
	var netErr net.Error
	timedOut := errors.As(dialErr, &netErr) && netErr.Timeout()
	switch {
	case strings.Contains(message, "no route to host"):
		return "the tunnel did not deliver the packet: check that the agent is online and that the control node's hub is up (noobtunnel server --print-info)"
	case strings.Contains(message, "connection refused"), strings.Contains(message, "connection reset"):
		return "the packet arrived and was refused: nothing is listening on " + address + " on the agent's side"
	case timedOut || strings.Contains(message, "timeout"):
		port := address
		if _, p, err := net.SplitHostPort(address); err == nil {
			port = p
		}
		return "the packets go out and nothing answers, so the service may still be healthy. Start " +
			"`sudo tcpdump -ni any port " + port + "` on the agent, leave it running, then run this diagnose again: " +
			"a SYN with no answer means the host is not forwarding to that network, and an answer arriving from an " +
			"address other than " + host + " means host NAT rewrote it (Docker masquerade). " +
			"An agent that has been updated keeps the mesh out of host NAT by itself."
	default:
		return "check that the service listens on " + host + " on the agent's side, and that the agent's firewall allows it"
	}
}
