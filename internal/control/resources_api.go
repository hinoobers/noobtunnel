package control

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/access"
	"github.com/noobtunnel/noobtunnel/internal/store"
)

// TargetView is one backend of a resource, with its own counters.
type TargetView struct {
	ID        uint32 `json:"id"`
	AgentID   uint32 `json:"agentId"`
	AgentName string `json:"agentName"`
	Address   string `json:"address"`
	Enabled   bool   `json:"enabled"`
	Active    int64  `json:"active"`
	Total     uint64 `json:"total"`
	RxBytes   uint64 `json:"rxBytes"`
	TxBytes   uint64 `json:"txBytes"`
	LastError string `json:"lastError,omitempty"`
}

// ResourceView is a published service as the UI sees it.
type ResourceView struct {
	ID           uint32       `json:"id"`
	Name         string       `json:"name"`
	Protocol     string       `json:"protocol"`
	Targets      []TargetView `json:"targets"`
	Strategy     string       `json:"strategy"`
	ExitNodeID   string       `json:"exitNodeId,omitempty"`
	ExitNodeName string       `json:"exitNodeName"`
	ExitNodeAddr string       `json:"exitNodeAddress,omitempty"`
	ListenPort   int          `json:"listenPort"`
	Domain       string       `json:"domain,omitempty"`
	Public       string       `json:"public"`
	Enabled      bool         `json:"enabled"`
	Listening    bool         `json:"listening"`
	LastError    string       `json:"lastError,omitempty"`
	// ProxyProtocol is "", "v1" or "v2": the header prepended for the service.
	ProxyProtocol string `json:"proxyProtocol,omitempty"`
	// Rules are the access rules, in evaluation order.
	Rules []access.Rule `json:"rules,omitempty"`
	// Identity means a control node account is required to reach the resource.
	Identity  bool   `json:"identity"`
	Active    int64  `json:"active"`
	Total     uint64 `json:"total"`
	RxBytes   uint64 `json:"rxBytes"`
	TxBytes   uint64 `json:"txBytes"`
	CreatedAt string `json:"createdAt"`
}

// DomainView is a hostname and what uses it.
type DomainView struct {
	Hostname string `json:"hostname"`
	// Pattern is what the operator typed, e.g. *.example.com.
	Pattern   string   `json:"pattern,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	CreatedAt string   `json:"createdAt"`
	Resources []string `json:"resources"`
	Address   string   `json:"address,omitempty"`
	Hint      string   `json:"hint,omitempty"`
	// Automation state.
	ProviderID   string `json:"providerId,omitempty"`
	ProviderName string `json:"providerName,omitempty"`
	ExitNodeName string `json:"exitNodeName,omitempty"`
	Synced       bool   `json:"synced"`
	LastSync     string `json:"lastSync,omitempty"`
	LastError    string `json:"lastError,omitempty"`
}

// DNSProviderView is a DNS provider without its token.
type DNSProviderView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Zone      string `json:"zone,omitempty"`
	Enabled   bool   `json:"enabled"`
	HasToken  bool   `json:"hasToken"`
	CreatedAt string `json:"createdAt"`
}

// dnsProviderViews lists providers without their tokens.
func (s *Server) dnsProviderViews() []DNSProviderView {
	providers := s.store.DNSProviders()
	out := make([]DNSProviderView, 0, len(providers))
	for _, p := range providers {
		out = append(out, DNSProviderView{
			ID:        p.ID,
			Name:      p.Name,
			Kind:      string(p.Kind),
			Zone:      p.Zone,
			Enabled:   p.Enabled,
			HasToken:  p.Token != "",
			CreatedAt: p.CreatedAt.UTC().Format(timeLayout),
		})
	}
	return out
}

// timeLayout is the timestamp format used in API views.
const timeLayout = "2006-01-02T15:04:05Z07:00"

// resourceViews builds the UI representation of every published service.
func (s *Server) resourceViews() []ResourceView {
	resources := s.store.Resources()
	agents := map[uint32]*store.Agent{}
	for _, a := range s.store.Agents() {
		agents[a.ID] = a
	}
	nodes := map[string]store.ExitNode{}
	controlName := "Control node"
	controlEnabled := true
	for _, node := range s.store.ExitNodes() {
		nodes[node.ID] = node
		if node.Kind == store.ExitNodeControl {
			controlName = node.Name
			controlEnabled = node.Enabled
		}
	}
	stats := s.proxies.Stats()
	publicHost := s.publicHost()

	out := make([]ResourceView, 0, len(resources))
	for _, r := range resources {
		view := ResourceView{
			ID:            r.ID,
			Name:          r.Name,
			Protocol:      string(r.Protocol),
			Targets:       []TargetView{},
			Strategy:      string(r.Strategy),
			ExitNodeID:    r.ExitNodeID,
			ExitNodeName:  controlName,
			ListenPort:    r.EffectiveListenPort(),
			Domain:        r.Domain,
			Enabled:       r.Enabled,
			ProxyProtocol: r.ProxyProtocol,
			Rules:         r.Rules,
			Identity:      r.Identity,
			CreatedAt:     r.CreatedAt.UTC().Format(timeLayout),
		}
		if node, ok := nodes[r.ExitNodeID]; ok && node.Kind != store.ExitNodeControl {
			view.ExitNodeName = node.Name
			view.ExitNodeAddr = node.Address
		}
		for _, target := range r.Targets {
			targetView := TargetView{
				ID:      target.ID,
				AgentID: target.AgentID,
				Address: target.Target(),
				Enabled: target.Enabled,
			}
			if agent := agents[target.AgentID]; agent != nil {
				targetView.AgentName = agent.Name
			}
			if stat, ok := stats[r.ID]; ok {
				if ts, ok := stat.Targets[target.ID]; ok {
					targetView.Active = ts.Active
					targetView.Total = ts.Total
					targetView.RxBytes = ts.RxBytes
					targetView.TxBytes = ts.TxBytes
					targetView.LastError = ts.LastError
				}
			}
			view.Targets = append(view.Targets, targetView)
		}
		if stat, ok := stats[r.ID]; ok {
			view.Listening = stat.Listening
			view.LastError = stat.LastError
			view.Active = stat.Active
			view.Total = stat.Total
			view.RxBytes = stat.RxBytes
			view.TxBytes = stat.TxBytes
		}
		// Explain why a resource stopped listening when its exit node was turned
		// off, instead of leaving a bare "stopped" in the UI.
		exitDisabled := r.ExitNodeID == "" && !controlEnabled
		if node, ok := exitNodeFor(nodes, r.ExitNodeID); ok && !node.Enabled {
			exitDisabled = true
			if node.Kind != store.ExitNodeControl {
				view.ExitNodeName = node.Name
			}
		}
		if exitDisabled {
			view.Listening = false
			view.LastError = "exit node " + view.ExitNodeName + " is disabled"
		}
		view.Public = publicEndpoint(r, view.ExitNodeAddr, publicHost)
		out = append(out, view)
	}
	return out
}

// publicEndpoint renders the URL or address a resource is reachable on.
func publicEndpoint(r store.Resource, exitAddress, controlAddress string) string {
	if r.Domain != "" {
		scheme := "http"
		if r.Protocol == store.ProtocolHTTPS {
			scheme = "https"
		}
		return scheme + "://" + r.Domain
	}
	host := controlAddress
	if exitAddress != "" {
		host = exitAddress
	}
	if host == "" {
		host = "<control-node>"
	}
	address := net.JoinHostPort(host, strconv.Itoa(r.EffectiveListenPort()))
	switch r.Protocol {
	case store.ProtocolHTTPS:
		return "https://" + address
	case store.ProtocolHTTP:
		return "http://" + address
	default:
		return string(r.Protocol) + "://" + address
	}
}

// publicHost is the address users and agents reach the control node on.
func (s *Server) publicHost() string {
	endpoint := s.hubEndpoint("")
	if host, _, err := net.SplitHostPort(endpoint); err == nil && host != "" {
		return host
	}
	return strings.Trim(endpoint, "[]")
}

// domainViews builds the UI representation of configured hostnames.
func (s *Server) domainViews() []DomainView {
	resources := s.store.Resources()
	publicHost := s.publicHost()
	out := make([]DomainView, 0)
	for _, d := range s.store.Domains() {
		address, exitName := s.desiredDomainAddress(d)
		view := DomainView{
			Hostname:     d.Hostname,
			Pattern:      d.Pattern(),
			Kind:         string(d.KindOrDefault()),
			CreatedAt:    d.CreatedAt.UTC().Format(timeLayout),
			Resources:    []string{},
			Address:      address,
			ExitNodeName: exitName,
			ProviderID:   d.ProviderID,
			LastError:    d.LastError,
		}
		if view.Address == "" {
			view.Address = publicHost
		}
		if !d.LastSync.IsZero() {
			view.LastSync = d.LastSync.UTC().Format(timeLayout)
			view.Synced = d.LastError == "" && d.Address == address
		}
		if d.ProviderID != "" {
			if provider, err := s.store.DNSProvider(d.ProviderID); err == nil {
				view.ProviderName = provider.Name
			}
		}
		switch {
		case view.ProviderName != "" && view.LastError != "":
			view.Hint = "automatic DNS through " + view.ProviderName + " failed: " + view.LastError
		case view.ProviderName != "":
			view.Hint = "managed automatically by " + view.ProviderName + " → " + view.Address
		case view.Address != "":
			view.Hint = "create an A record for " + d.Hostname + " pointing at " + view.Address +
				" (" + exitName + "), or configure a provider under Automation"
		default:
			view.Hint = "create an A record for " + d.Hostname
		}
		for _, r := range resources {
			if r.Domain == d.Hostname {
				view.Resources = append(view.Resources, r.Name)
			}
		}
		out = append(out, view)
	}
	return out
}

// checkControlDomain refuses a resource that claims the control node's own
// hostname: that name already serves the control node, so the resource would
// never see a request.
func (s *Server) checkControlDomain(in store.ResourceInput) error {
	domain := strings.ToLower(strings.TrimSpace(s.opts.Domain))
	if domain == "" || !strings.EqualFold(strings.TrimSpace(in.Domain), domain) {
		return nil
	}
	switch in.Protocol {
	case store.ProtocolHTTP, store.ProtocolHTTPS:
		return errors.New("that hostname serves the control node itself, publish this resource on another name")
	}
	return nil
}

// handleResources lists and creates published services.
func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"resources": s.resourceViews(),
			"domains":   s.domainViews(),
		})
	case http.MethodPost:
		var body resourcePayload
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if err := s.checkControlDomain(body.input()); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		resource, err := s.store.AddResource(body.input())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.reconcileResources()
		s.recordEvent("resource", "published "+resource.Name+" ("+string(resource.Protocol)+")")
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"resource": s.resourceView(resource.ID)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

// handleResourceItem reads, changes or deletes one published service.
func (s *Server) handleResourceItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/resources/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id64, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("resource id must be a number"))
		return
	}
	id := uint32(id64)
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if _, err := s.store.Resource(id); err != nil {
		writeJSON(w, http.StatusNotFound, errBody("no such resource"))
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"resource": s.resourceView(id)})
	case action == "" && r.Method == http.MethodPatch:
		var body resourcePayload
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		if err := s.checkControlDomain(body.input()); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		resource, err := s.store.UpdateResource(id, body.input())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.reconcileResources()
		s.recordEvent("resource", "updated "+resource.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"resource": s.resourceView(id)})
	case action == "" && r.Method == http.MethodDelete:
		name := ""
		if existing, err := s.store.Resource(id); err == nil {
			name = existing.Name
		}
		if err := s.store.RemoveResource(id); err != nil {
			writeJSON(w, http.StatusNotFound, errBody("no such resource"))
			return
		}
		s.reconcileResources()
		s.recordEvent("resource", "removed "+name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("unsupported operation"))
	}
}

func (s *Server) resourceView(id uint32) ResourceView {
	for _, view := range s.resourceViews() {
		if view.ID == id {
			return view
		}
	}
	return ResourceView{ID: id}
}

// resourcePayload is the wire form of a resource.
type resourcePayload struct {
	Name          string          `json:"name"`
	Protocol      string          `json:"protocol"`
	Targets       []targetPayload `json:"targets"`
	Strategy      string          `json:"strategy"`
	ExitNodeID    string          `json:"exitNodeId"`
	ListenPort    int             `json:"listenPort"`
	Domain        string          `json:"domain"`
	Enabled       *bool           `json:"enabled"`
	ProxyProtocol string          `json:"proxyProtocol"`
	Rules         []access.Rule   `json:"rules"`
	Identity      bool            `json:"identity"`
}

// targetPayload is one backend on the wire.
type targetPayload struct {
	AgentID uint32 `json:"agentId"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Enabled *bool  `json:"enabled"`
}

func (p resourcePayload) input() store.ResourceInput {
	targets := make([]store.ResourceTargetInput, 0, len(p.Targets))
	for _, t := range p.Targets {
		targets = append(targets, store.ResourceTargetInput{
			AgentID: t.AgentID,
			Host:    t.Host,
			Port:    t.Port,
			Enabled: t.Enabled,
		})
	}
	return store.ResourceInput{
		Name:          p.Name,
		Protocol:      store.Protocol(strings.ToLower(strings.TrimSpace(p.Protocol))),
		Targets:       targets,
		Strategy:      p.Strategy,
		ExitNodeID:    strings.TrimSpace(p.ExitNodeID),
		ListenPort:    p.ListenPort,
		Domain:        p.Domain,
		Enabled:       p.Enabled,
		ProxyProtocol: p.ProxyProtocol,
		Rules:         p.Rules,
		Identity:      p.Identity,
	}
}

// handleDomains lists and creates hostnames.
func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"domains": s.domainViews()})
	case http.MethodPost:
		var body struct {
			Hostname string `json:"hostname"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		domain, err := s.store.AddDomain(body.Hostname)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("domain", "added "+domain.Hostname)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"hostname": domain.Hostname})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

// handleDomainItem deletes a hostname.
func (s *Server) handleDomainItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/domains/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	hostname := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch {
	case hostname == "sync" && r.Method == http.MethodPost:
		// "Sync every domain now" is reachable at /api/domains/sync.
		s.syncDomains(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"domains": s.domainViews()})
	case action == "" && r.Method == http.MethodPatch:
		s.handleDomainPatch(w, r, hostname)
	case action == "sync" && r.Method == http.MethodPost:
		s.handleDomainSync(w, r, hostname)
	case action == "" && r.Method == http.MethodDelete:
		if err := s.store.RemoveDomain(hostname); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("domain", "removed "+hostname)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("unsupported operation"))
	}
}
