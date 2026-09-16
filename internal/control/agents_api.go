package control

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/ipam"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/topology"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.StateSnapshot())
	case http.MethodPost:
		var body struct {
			Name         string   `json:"name"`
			Advertise    []string `json:"advertise"`
			TTLHours     int      `json:"ttlHours"`
			AdvertiseAll bool     `json:"advertiseAll"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		agent, err := s.store.AddAgent(store.AddAgentParams{
			Name:         body.Name,
			Advertise:    body.Advertise,
			TTL:          time.Duration(body.TTLHours) * time.Hour,
			AdvertiseAll: body.AdvertiseAll,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("enrollment", "enrollment token created for "+agent.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{
			"agent":          s.agentView(agent, r),
			"installCommand": s.InstallCommand(agent, s.installOptions(r)),
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

func (s *Server) handleAgentItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/agents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusBadRequest, errBody("missing agent id"))
		return
	}
	id64, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("agent id must be a number"))
		return
	}
	id := uint32(id64)
	agent, err := s.store.Agent(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("no such agent"))
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case action == "" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"agent":          s.agentView(agent, r),
			"installCommand": s.InstallCommand(agent, s.installOptions(r)),
		})
	case action == "" && r.Method == http.MethodPatch:
		s.patchAgent(w, r, id, agent)
	case action == "" && r.Method == http.MethodDelete:
		if err := s.store.RemoveAgent(id); err != nil {
			writeJSON(w, http.StatusNotFound, errBody("no such agent"))
			return
		}
		s.Revoke(r.Context(), id, "agent removed by administrator")
		s.recordEvent("enrollment", "agent "+agent.Name+" removed")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case action == "rotate" && r.Method == http.MethodPost:
		err := s.store.UpdateAgent(id, func(a *store.Agent) error {
			token, err := store.NewToken()
			if err != nil {
				return err
			}
			psk, err := wg.GeneratePresharedKey()
			if err != nil {
				return err
			}
			a.Token = token
			a.HubPresharedKey = psk
			a.PublicKey = ""
			a.EnrolledAt = nil
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.Revoke(r.Context(), id, "token rotated by administrator")
		s.recordEvent("enrollment", "token rotated for "+agent.Name)
		rotated, _ := s.store.Agent(id)
		writeJSON(w, http.StatusOK, map[string]any{
			"agent":          s.agentView(rotated, r),
			"installCommand": s.InstallCommand(rotated, s.installOptions(r)),
		})
	case action == "ping" && r.Method == http.MethodPost:
		rtt, err := s.Ping(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"online": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"online": true, "latencyMs": rtt.Milliseconds()})
	case action == "command" && r.Method == http.MethodPost:
		var body struct {
			Action string `json:"action"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if err := s.Command(id, body.Action); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.recordEvent("command", agent.Name+" <- "+body.Action)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case action == "config" && r.Method == http.MethodGet:
		cfg, err := s.AgentConfigPreview(id)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"config": cfg})
	case action == "install" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"installCommand": s.InstallCommand(agent, s.installOptions(r)),
			"token":          agent.Token,
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("unsupported operation"))
	}
}

func (s *Server) patchAgent(w http.ResponseWriter, r *http.Request, id uint32, agent *store.Agent) {
	var body struct {
		Name         *string   `json:"name"`
		Advertise    *[]string `json:"advertise"`
		Enabled      *bool     `json:"enabled"`
		Notes        *string   `json:"notes"`
		AdvertiseAll *bool     `json:"advertiseAll"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	err := s.store.UpdateAgent(id, func(a *store.Agent) error {
		if body.Name != nil {
			name := strings.TrimSpace(*body.Name)
			if name == "" {
				return errors.New("name must not be empty")
			}
			a.Name = name
		}
		if body.Advertise != nil {
			advertise, err := store.NormalisePrefixes(*body.Advertise)
			if err != nil {
				return err
			}
			a.Advertise = advertise
		}
		if body.Enabled != nil {
			a.Enabled = *body.Enabled
		}
		if body.Notes != nil {
			a.Notes = *body.Notes
		}
		if body.AdvertiseAll != nil {
			a.AdvertiseAll = *body.AdvertiseAll
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	if body.Enabled != nil && !*body.Enabled {
		s.Revoke(r.Context(), id, "agent disabled by administrator")
	} else if err := s.Sync(r.Context()); err != nil {
		s.log.Warn("failed to apply agent change", "error", err)
	}
	s.broadcastState()
	updated, err := s.store.Agent(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("no such agent"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent": s.agentView(updated, r)})
}

// AgentConfigPreview renders the WireGuard configuration an agent would run,
// with all secrets replaced by placeholders.
func (s *Server) AgentConfigPreview(id uint32) (string, error) {
	agent, err := s.store.Agent(id)
	if err != nil {
		return "", err
	}
	if agent.PublicKey == "" {
		return "", errors.New("this agent has not connected yet, so it has no public key")
	}
	settings := s.store.Settings()
	st := s.store.View()
	pool, err := ipam.New(settings.MeshCIDR)
	if err != nil {
		return "", err
	}
	meshPrefix, err := netip.ParsePrefix(settings.MeshCIDR)
	if err != nil {
		return "", err
	}
	addr, err := netip.ParseAddr(agent.Address)
	if err != nil {
		return "", err
	}
	peers, err := s.peersFor(id)
	if err != nil {
		return "", err
	}
	in := topology.AgentInput{
		Mesh: topology.Mesh{
			CIDR:          meshPrefix,
			MTU:           settings.MTU,
			KeepaliveSec:  settings.KeepaliveSec,
			DirectEnabled: settings.DirectPaths,
		},
		Self: topology.Member{ID: id, Name: agent.Name, Address: addr},
		Hub: topology.HubMember{
			Address:      pool.HubAddress(),
			PublicKey:    st.Hub.PublicKey,
			Endpoint:     s.hubEndpoint(""),
			PresharedKey: agent.HubPresharedKey,
		},
		PairKeys:   map[uint32]string{},
		Direct:     map[uint32]bool{},
		PrivateKey: "<this agent's private key>",
	}
	for _, p := range peers {
		peerAddr, err := netip.ParseAddr(p.Address)
		if err != nil {
			continue
		}
		member := topology.Member{
			ID: p.ID, Name: p.Name, Address: peerAddr,
			PublicKey: p.PublicKey, Endpoint: p.Endpoint, Enabled: true, Online: p.Online,
		}
		for _, raw := range p.Advertise {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				member.Advertise = append(member.Advertise, prefix)
			}
		}
		in.Peers = append(in.Peers, member)
		in.PairKeys[p.ID] = p.PresharedKey
	}
	cfg, _ := topology.BuildAgentConfig(in)
	return cfg.Redacted(), nil
}

// agentView renders a single agent with its install command.
func (s *Server) agentView(agent *store.Agent, r *http.Request) AgentView {
	state := s.StateSnapshot()
	for _, av := range state.Agents {
		if av.ID == agent.ID {
			av.InstallCommand = s.InstallCommand(agent, s.installOptions(r))
			return av
		}
	}
	prefix, _ := agent.AddressPrefix()
	return AgentView{
		ID: agent.ID, Name: agent.Name, Address: agent.Address, Prefix: prefix.String(),
		PublicKey: agent.PublicKey, Advertise: agent.Advertise, Enabled: agent.Enabled,
		CreatedAt: agent.CreatedAt, Token: agent.Token,
		InstallCommand: s.InstallCommand(agent, s.installOptions(r)),
		Links:          []LinkView{},
	}
}
