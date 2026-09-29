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
	who := principalFrom(r)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.StateSnapshotFor(who))
	case http.MethodPost:
		if !who.canManageMesh() {
			writeJSON(w, http.StatusForbidden, errBody("this account cannot add agents"))
			return
		}
		if who.MeshSlot > 0 {
			if !s.tenantFirewallReady.Load() || s.syncTenantFirewall(r.Context()) != nil {
				writeJSON(w, http.StatusServiceUnavailable, errBody("private mesh firewall is unavailable"))
				return
			}
		}
		var body struct {
			Name         string   `json:"name"`
			MeshDNS      string   `json:"meshDns"`
			Advertise    []string `json:"advertise"`
			AdvertiseAll bool     `json:"advertiseAll"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		method := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("method")))
		if method == "" {
			method = "service"
		}
		if method != "service" && method != "docker" && method != "windows" {
			writeJSON(w, http.StatusBadRequest, errBody("choose Linux, Docker, or Windows"))
			return
		}
		agent, err := s.store.AddAgent(store.AddAgentParams{
			Name:          body.Name,
			MeshDNS:       body.MeshDNS,
			InstallMethod: method,
			OwnerID:       who.UserID,
			MeshSlot:      who.MeshSlot,
			Advertise:     body.Advertise,
			TTL:           15 * time.Minute,
			AdvertiseAll:  body.AdvertiseAll,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEventFor(agent.OwnerID, "enrollment", "enrollment token created for "+agent.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{
			"agent":          s.agentView(agent, r),
			"installCommand": s.InstallCommand(agent, s.installOptionsForAgent(r, agent)),
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
	if !ownsAgent(principalFrom(r), agent) {
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
			"installCommand": s.InstallCommand(agent, s.installOptionsForAgent(r, agent)),
		})
	case action == "" && r.Method == http.MethodPatch:
		s.patchAgent(w, r, id, agent)
	case action == "keepalive" && r.Method == http.MethodPost:
		if agent.EnrolledAt != nil {
			writeJSON(w, http.StatusConflict, errBody("agent is already enrolled"))
			return
		}
		expires := s.now().UTC().Add(15 * time.Minute)
		if err := s.store.UpdateAgent(id, func(a *store.Agent) error {
			if a.EnrolledAt != nil {
				return errors.New("agent is already enrolled")
			}
			a.ExpiresAt = &expires
			return nil
		}); err != nil {
			writeJSON(w, http.StatusConflict, errBody(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"expiresAt": expires})
	case action == "" && r.Method == http.MethodDelete:
		if err := s.removeAgent(r, agent, "agent removed by owner"); err != nil {
			writeJSON(w, http.StatusNotFound, errBody("no such agent"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case action == "uninstall" && r.Method == http.MethodGet:
		opts := s.installOptions(r)
		method := agent.InstallMethod
		if method == "" && agent.OS == "windows" {
			method = "windows"
		}
		if method == "" {
			method = "auto"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"method":  method,
			"command": s.UninstallCommand(id, opts, method),
		})
	case action == "rotate" && r.Method == http.MethodPost:
		expires := s.now().UTC().Add(15 * time.Minute)
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
			a.ExpiresAt = &expires
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.Revoke(r.Context(), id, "token rotated by administrator")
		s.recordEventFor(agent.OwnerID, "enrollment", "token rotated for "+agent.Name)
		rotated, _ := s.store.Agent(id)
		writeJSON(w, http.StatusOK, map[string]any{
			"agent":          s.agentView(rotated, r),
			"installCommand": s.InstallCommand(rotated, s.installOptionsForAgent(r, rotated)),
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
		s.recordEventFor(agent.OwnerID, "command", agent.Name+" <- "+body.Action)
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
			"installCommand": s.InstallCommand(agent, s.installOptionsForAgent(r, agent)),
			"token":          agent.Token,
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("unsupported operation"))
	}
}

func ownsAgent(who principal, agent *store.Agent) bool {
	return ownsMeshObject(who, agent.OwnerID, agent.MeshSlot)
}

func ownsMeshObject(who principal, ownerID string, meshSlot uint16) bool {
	if who.UserID == "" || meshSlot != who.MeshSlot {
		return false
	}
	if ownerID == who.UserID {
		return true
	}
	return ownerID == "" && meshSlot == 0 && who.canAdmin()
}

func (s *Server) patchAgent(w http.ResponseWriter, r *http.Request, id uint32, agent *store.Agent) {
	var body struct {
		Name         *string   `json:"name"`
		MeshDNS      *string   `json:"meshDns"`
		Advertise    *[]string `json:"advertise"`
		Enabled      *bool     `json:"enabled"`
		Notes        *string   `json:"notes"`
		AdvertiseAll *bool     `json:"advertiseAll"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	var presentNetworks []string
	s.mu.Lock()
	session := s.sessions[id]
	s.mu.Unlock()
	if session != nil {
		stats, _, _, _, _ := session.snapshot()
		for _, network := range stats.Networks {
			presentNetworks = append(presentNetworks, network.Prefix)
		}
	}
	err := s.store.Update(func(st *store.State) error {
		var a *store.Agent
		for _, candidate := range st.Agents {
			if candidate.ID == id {
				a = candidate
				break
			}
		}
		if a == nil {
			return store.ErrNotFound
		}
		var advertise []string
		if body.Advertise != nil {
			var err error
			advertise, err = store.NormalisePrefixes(*body.Advertise)
			if err != nil {
				return err
			}
			if a.MeshSlot > 0 {
				if err := store.ValidateTenantAdvertise(advertise); err != nil {
					return err
				}
			}
			if err := store.ValidateAdvertise(st, id, advertise); err != nil {
				return err
			}
		}
		if body.Name != nil {
			name := strings.TrimSpace(*body.Name)
			if name == "" {
				return errors.New("name must not be empty")
			}
			a.Name = name
		}
		if body.MeshDNS != nil {
			name, err := store.NormaliseMeshDNS(*body.MeshDNS)
			if err != nil {
				return err
			}
			if err := store.ValidateMeshDNSUnique(st, id, a.OwnerID, a.MeshSlot, name); err != nil {
				return err
			}
			a.MeshDNS = name
		}
		if body.Advertise != nil {
			a.Advertise = advertise
		}
		if body.Enabled != nil {
			a.Enabled = *body.Enabled
		}
		if body.Notes != nil {
			a.Notes = *body.Notes
		}
		if body.AdvertiseAll != nil {
			if *body.AdvertiseAll && !a.AdvertiseAll {
				a.AutoSeen, _ = store.NormalisePrefixes(presentNetworks)
			} else if !*body.AdvertiseAll {
				a.AutoSeen = nil
			}
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
		writeJSON(w, http.StatusServiceUnavailable, errBody("the agent change was saved but could not be applied to the mesh yet"))
		return
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
	subnet, err := store.TenantPrefix(settings.MeshCIDR, agent.MeshSlot)
	if err != nil {
		if agent.MeshSlot > 0 {
			return "", err
		}
	} else {
		settings.MeshCIDR = subnet.String()
	}
	st := s.store.View()
	pool, err := ipam.New(st.Settings.MeshCIDR)
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
		Self:   topology.Member{ID: id, Name: agent.Name, Address: addr},
		WGPort: 51820 + int(id%1000),
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
			av.InstallCommand = s.InstallCommand(agent, s.installOptionsForAgent(r, agent))
			return av
		}
	}
	prefix, _ := agent.AddressPrefix()
	return AgentView{
		ID: agent.ID, Name: agent.Name, MeshDNS: agent.MeshDNS, Address: agent.Address, Prefix: prefix.String(),
		PublicKey: agent.PublicKey, Advertise: agent.Advertise, Enabled: agent.Enabled,
		CreatedAt: agent.CreatedAt, Token: agent.Token,
		InstallMethod:  agent.InstallMethod,
		InstallCommand: s.InstallCommand(agent, s.installOptionsForAgent(r, agent)),
		Links:          []LinkView{},
	}
}
