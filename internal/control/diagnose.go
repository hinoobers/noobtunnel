package control

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

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

	if out, err := s.runner().Run(ctx, "ip", "route", "get", address); err != nil {
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

	host, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		host = address
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	switch {
	case dialErr != nil:
		add("Connect to the target", "fail", dialErr.Error(),
			"check that the service listens on "+host+" on the agent's side, and that the agent's firewall allows it")
		result.Verdict = "the control node cannot open a connection to " + address
		result.VerdictStatus = "fail"
	default:
		_ = conn.Close()
		add("Connect to the target", "ok", "connected to "+address, "")
		result.Verdict = "the control node reached " + address + ": the service and the tunnel are both fine"
		result.VerdictStatus = "ok"
	}

	if result.VerdictStatus != "ok" {
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
