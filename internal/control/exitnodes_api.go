package control

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// ExitNodeView is an exit node as the UI sees it.
type ExitNodeView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Address     string `json:"address,omitempty"`
	BindAddress string `json:"bindAddress,omitempty"`
	Enabled     bool   `json:"enabled"`
	Deletable   bool   `json:"deletable"`
	// Status is ready, not-configured or disabled.
	Status       string   `json:"status"`
	StatusDetail string   `json:"statusDetail,omitempty"`
	Resources    []string `json:"resources"`
	// Public address users dial, including the control node's own address.
	Public string `json:"public,omitempty"`

	TunnelInterface string `json:"tunnelInterface,omitempty"`
	LocalEndpoint   string `json:"localEndpoint,omitempty"`
	PeerEndpoint    string `json:"peerEndpoint,omitempty"`
	LocalTunnelAddr string `json:"localTunnelAddress,omitempty"`
	PeerTunnelAddr  string `json:"peerTunnelAddress,omitempty"`

	// Setup holds the commands to bring the address up, if it is not there yet.
	Setup SetupCommands `json:"setup"`
}

// SetupCommands is the generated configuration for an exit node.
type SetupCommands struct {
	Local  []string `json:"local,omitempty"`
	Remote []string `json:"remote,omitempty"`
	Notes  string   `json:"notes,omitempty"`
}

// localAddresses returns every address this host can bind.
func localAddresses() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip := ipNet.IP.To4(); ip != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

// exitNodeViews builds the UI representation of every exit node.
func (s *Server) exitNodeViews() []ExitNodeView {
	local := localAddresses()
	hasLocal := func(address string) bool {
		for _, candidate := range local {
			if candidate == address {
				return true
			}
		}
		return false
	}
	resources := s.store.Resources()
	public := s.publicHost()

	out := make([]ExitNodeView, 0)
	for _, node := range s.store.ExitNodes() {
		view := ExitNodeView{
			ID:              node.ID,
			Name:            node.Name,
			Kind:            string(node.Kind),
			Address:         node.Address,
			BindAddress:     node.BindAddress(),
			Enabled:         node.Enabled,
			Deletable:       node.Deletable(),
			Resources:       []string{},
			TunnelInterface: node.TunnelInterface,
			LocalEndpoint:   node.LocalEndpoint,
			PeerEndpoint:    node.PeerEndpoint,
			LocalTunnelAddr: node.LocalTunnelAddr,
			PeerTunnelAddr:  node.PeerTunnelAddr,
		}
		for _, r := range resources {
			if r.ExitNodeID == node.ID {
				view.Resources = append(view.Resources, r.Name)
			}
		}
		switch node.Kind {
		case store.ExitNodeControl:
			view.Public = public
			view.Status = "ready"
			if public == "" {
				view.StatusDetail = "the control node's public address is not known yet"
			} else {
				view.StatusDetail = "resources listen on every address of this host, including " + public
			}
		default:
			view.Public = node.Address
			view.Setup = exitNodeSetup(node, public)
			if !node.Enabled {
				view.Status = "disabled"
				view.StatusDetail = "disabled, so resources on it are not published"
				break
			}
			if hasLocal(node.Address) {
				view.Status = "ready"
				view.StatusDetail = node.Address + " is configured on this host"
			} else {
				view.Status = "not-configured"
				view.StatusDetail = node.Address + " is not present on this host yet; run the setup commands"
			}
		}
		out = append(out, view)
	}
	return out
}

// exitNodeSetup renders the commands that bring an exit node's address up. The
// commands are generated rather than guessed, so they can be reviewed and run
// anywhere (or applied locally with one click).
func exitNodeSetup(node store.ExitNode, public string) SetupCommands {
	switch node.Kind {
	case store.ExitNodeGRE:
		local := []string{
			fmt.Sprintf("ip tunnel add %s mode gre local %s remote %s ttl 255", node.TunnelInterface, node.LocalEndpoint, node.PeerEndpoint),
			fmt.Sprintf("ip link set %s up", node.TunnelInterface),
			fmt.Sprintf("ip addr add %s/30 dev %s", node.LocalTunnelAddr, node.TunnelInterface),
			fmt.Sprintf("ip addr add %s/32 dev %s", node.Address, node.TunnelInterface),
		}
		remote := []string{
			fmt.Sprintf("ip tunnel add %s mode gre local %s remote %s ttl 255", node.TunnelInterface, node.PeerEndpoint, node.LocalEndpoint),
			fmt.Sprintf("ip link set %s up", node.TunnelInterface),
			fmt.Sprintf("ip addr add %s/30 dev %s", node.PeerTunnelAddr, node.TunnelInterface),
			fmt.Sprintf("ip route replace %s/32 dev %s", node.Address, node.TunnelInterface),
		}
		return SetupCommands{
			Local:  local,
			Remote: remote,
			Notes: "Run the first block on this control node and the second on the host that lives at " +
				node.PeerEndpoint + ". Make them persistent with your distribution's networking config, " +
				"and make sure GRE (protocol 47) is allowed between the two hosts.",
		}
	default:
		commands := []string{fmt.Sprintf("ip addr add %s/32 dev %s", node.Address, node.Interface)}
		if public != "" {
			commands = append(commands, fmt.Sprintf("# then make sure %s is routed to this host (%s) by your provider", node.Address, public))
		}
		return SetupCommands{
			Local: commands,
			Notes: "Use this when the address is already routed to this host. If your provider routes it to another machine, use a GRE exit node instead so the address is carried here.",
		}
	}
}

// handleExitNodes lists and creates exit nodes.
func (s *Server) handleExitNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"exitNodes":      s.exitNodeViews(),
			"localAddresses": localAddresses(),
		})
	case http.MethodPost:
		var body exitNodePayload
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		node, err := s.store.AddExitNode(body.input())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.reconcileResources()
		s.recordEvent("exitnode", "added "+node.Name+" ("+string(node.Kind)+")")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"exitNode": s.exitNodeView(node.ID)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

// handleExitNodeItem changes, removes or applies an exit node.
func (s *Server) handleExitNodeItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/exitnodes/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errBody("missing exit node id"))
		return
	}
	if _, err := s.store.ExitNode(id); err != nil {
		writeJSON(w, http.StatusNotFound, errBody("no such exit node"))
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"exitNode": s.exitNodeView(id)})
	case action == "" && r.Method == http.MethodPatch:
		var body exitNodePayload
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		node, err := s.store.UpdateExitNode(id, body.input())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.reconcileResources()
		s.recordEvent("exitnode", "updated "+node.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"exitNode": s.exitNodeView(id)})
	case action == "" && r.Method == http.MethodDelete:
		node, _ := s.store.ExitNode(id)
		if err := s.store.RemoveExitNode(id); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.reconcileResources()
		s.recordEvent("exitnode", "removed "+node.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case action == "apply" && r.Method == http.MethodPost:
		node, _ := s.store.ExitNode(id)
		if node.Kind != store.ExitNodeGRE && node.Kind != store.ExitNodeAddress {
			writeJSON(w, http.StatusBadRequest, errBody("the control node exit node needs no setup"))
			return
		}
		output, err := s.applyExitNode(r.Context(), node, s.publicHost())
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "output": output, "error": err.Error()})
			return
		}
		s.recordEvent("exitnode", "applied local setup for "+node.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": output})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("unsupported operation"))
	}
}

// applyExitNode runs the local side of an exit node's setup on this host.
func (s *Server) applyExitNode(ctx context.Context, node store.ExitNode, public string) (string, error) {
	setup := exitNodeSetup(node, public)
	runner := s.runner()
	var output strings.Builder
	for _, command := range setup.Local {
		if strings.HasPrefix(strings.TrimSpace(command), "#") {
			continue
		}
		fields := strings.Fields(command)
		if len(fields) < 2 {
			continue
		}
		out, err := runner.Run(ctx, fields[0], fields[1:]...)
		output.WriteString("$ " + command + "\n" + out + "\n")
		if err != nil {
			if isAlreadyConfigured(err) {
				output.WriteString("(already configured)\n")
				continue
			}
			return output.String(), fmt.Errorf("could not run %q: %w", command, err)
		}
	}
	s.reconcileResources()
	return output.String(), nil
}

// isAlreadyConfigured recognises the harmless errors of re-applying setup.
func isAlreadyConfigured(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "file exists") ||
		strings.Contains(message, "exists") ||
		strings.Contains(message, "already")
}

func (s *Server) exitNodeView(id string) ExitNodeView {
	for _, view := range s.exitNodeViews() {
		if view.ID == id {
			return view
		}
	}
	return ExitNodeView{ID: id}
}

// exitNodePayload is the wire form of an exit node.
type exitNodePayload struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Address         string `json:"address"`
	Interface       string `json:"interface"`
	LocalEndpoint   string `json:"localEndpoint"`
	PeerEndpoint    string `json:"peerEndpoint"`
	LocalTunnelAddr string `json:"localTunnelAddress"`
	PeerTunnelAddr  string `json:"peerTunnelAddress"`
	TunnelInterface string `json:"tunnelInterface"`
	Enabled         *bool  `json:"enabled"`
}

func (p exitNodePayload) input() store.ExitNodeInput {
	return store.ExitNodeInput{
		Name:            p.Name,
		Kind:            p.Kind,
		Address:         p.Address,
		Interface:       p.Interface,
		LocalEndpoint:   p.LocalEndpoint,
		PeerEndpoint:    p.PeerEndpoint,
		LocalTunnelAddr: p.LocalTunnelAddr,
		PeerTunnelAddr:  p.PeerTunnelAddr,
		TunnelInterface: p.TunnelInterface,
		Enabled:         p.Enabled,
	}
}
