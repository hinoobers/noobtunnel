package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/dns"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/tlsutil"
)

// newDNSClient builds a provider client. Options.DNSFactory can override it, which
// is how tests point the control node at a fake provider.
var newDNSClient = func(provider store.DNSProvider) (DNSClient, error) {
	switch provider.Kind {
	case store.DNSProviderCloudflare:
		return dns.NewCloudflare(provider.Token), nil
	default:
		return nil, fmt.Errorf("no automatic DNS for provider kind %q", provider.Kind)
	}
}

// DNSClient is the part of a provider client the control node needs.
type DNSClient interface {
	EnsureA(ctx context.Context, hostname, address string) error
}

// desiredDomainAddress decides which address a domain should resolve to: the
// exit node its resources are published on, or the control node itself. It always
// answers with an IPv4 address, because an A record cannot hold a hostname.
func (s *Server) desiredDomainAddress(domain store.Domain) (address, exitNode string) {
	control := s.controlNodeAddress()
	for _, r := range s.store.Resources() {
		if r.Domain == "" || !domain.Covers(r.Domain) {
			continue
		}
		if r.ExitNodeID == "" {
			return control, "Control node"
		}
		if node, err := s.store.ExitNode(r.ExitNodeID); err == nil && node.Address != "" {
			return node.Address, node.Name
		}
	}
	return control, "Control node"
}

// controlNodeAddress is the address an A record of the control node itself should
// point at: the advertised endpoint when it is already an address, otherwise this
// machine's own public address, and only then the endpoint resolved by name (the
// installer advertises the domain, which may not resolve yet — or may resolve to
// a proxy — while the record is still being created).
func (s *Server) controlNodeAddress() string {
	host := s.publicHost()
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	public, private := machineIPv4s()
	if public != "" {
		return public
	}
	if host != "" && !strings.EqualFold(host, "localhost") {
		if addrs, err := net.LookupHost(host); err == nil {
			for _, addr := range addrs {
				if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
					return ip.To4().String()
				}
			}
		}
	}
	return private
}

// machineIPv4s returns this machine's first public and first private IPv4 address,
// if it has either.
func machineIPv4s() (public, private string) {
	for _, candidate := range tlsutil.LocalHosts() {
		ip := net.ParseIP(candidate)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.To4() == nil {
			continue
		}
		if !ip.IsPrivate() && public == "" {
			public = ip.To4().String()
		}
		if private == "" {
			private = ip.To4().String()
		}
	}
	return public, private
}

// syncDomains makes every domain's A record point at the right address, using the
// configured provider. Domains without a provider are left alone (the UI shows
// what to create by hand).
func (s *Server) syncDomains(ctx context.Context) {
	providers := map[string]store.DNSProvider{}
	for _, p := range s.store.DNSProviders() {
		providers[p.ID] = p
	}
	for _, domain := range s.store.Domains() {
		if domain.ProviderID == "" {
			continue
		}
		provider, ok := providers[domain.ProviderID]
		if !ok || !provider.Enabled {
			continue
		}
		address, exitName := s.desiredDomainAddress(domain)
		if address == "" {
			err := errors.New("no IPv4 address to point the record at")
			_ = s.store.RecordDomainSync(domain.Hostname, "", err)
			s.recordError("dns", "no address for "+domain.Hostname, err.Error(),
				"set the WireGuard endpoint to an address, or publish the domain on an exit node with one")
			continue
		}
		if domain.Address == address && domain.LastError == "" && !domain.LastSync.IsZero() &&
			time.Since(domain.LastSync) < verifyEvery {
			// Confirmed earlier and nothing changed: no need to ask the provider
			// again on every pass.
			continue
		}
		factory := s.opts.DNSFactory
		if factory == nil {
			factory = newDNSClient
		}
		client, err := factory(provider)
		if err != nil {
			_ = s.store.RecordDomainSync(domain.Hostname, address, err)
			s.recordError("dns", "could not update "+domain.Hostname, err.Error(), "")
			continue
		}
		recordName := domain.RecordName()
		if err := client.EnsureA(ctx, recordName, address); err != nil {
			s.log.Warn("could not update DNS", "domain", domain.Hostname, "provider", provider.Name, "error", err)
			_ = s.store.RecordDomainSync(domain.Hostname, address, err)
			s.recordError("dns", "could not update "+domain.Hostname, err.Error(),
				"check the provider token's DNS edit permission and that the zone is in this account")
			continue
		}
		s.log.Info("DNS updated", "domain", domain.Hostname, "record", recordName, "address", address,
			"exitNode", exitName, "provider", provider.Name)
		_ = s.store.RecordDomainSync(domain.Hostname, address, nil)
	}
	s.broadcastState()
}

// verifyEvery is how long a confirmed record is trusted before the control node
// checks the provider again, so a record deleted by hand is noticed.
const verifyEvery = 10 * time.Minute

// dnsLoop keeps records current, for example after an exit node address changes.
func (s *Server) dnsLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			s.syncDomains(syncCtx)
			cancel()
		}
	}
}

// handleDNSProviders lists and creates DNS providers.
func (s *Server) handleDNSProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"providers": s.dnsProviderViews()})
	case http.MethodPost:
		var body dnsProviderPayload
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		provider, err := s.store.AddDNSProvider(body.input())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("dns", "added provider "+provider.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"provider": s.dnsProviderView(provider.ID)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

// handleDNSProviderItem changes or removes a provider, and can test its token.
func (s *Server) handleDNSProviderItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/dns/providers/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if _, err := s.store.DNSProvider(id); err != nil {
		writeJSON(w, http.StatusNotFound, errBody("no such provider"))
		return
	}
	switch {
	case action == "" && r.Method == http.MethodPatch:
		var body dnsProviderPayload
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		provider, err := s.store.UpdateDNSProvider(id, body.input())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("dns", "updated provider "+provider.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"provider": s.dnsProviderView(id)})
	case action == "" && r.Method == http.MethodDelete:
		provider, _ := s.store.DNSProvider(id)
		if err := s.store.RemoveDNSProvider(id); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		s.recordEvent("dns", "removed provider "+provider.Name)
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case action == "sync" && r.Method == http.MethodPost:
		s.syncDomains(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domains": s.domainViews()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("unsupported operation"))
	}
}

// handleDomainItem also accepts a PATCH that attaches a provider.
func (s *Server) handleDomainPatch(w http.ResponseWriter, r *http.Request, hostname string) {
	var body struct {
		ProviderID *string `json:"providerId"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	if body.ProviderID == nil {
		writeJSON(w, http.StatusBadRequest, errBody("providerId is required"))
		return
	}
	if _, err := s.store.SetDomainProvider(hostname, *body.ProviderID); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	s.recordEvent("dns", "updated automation for "+hostname)
	s.syncDomains(r.Context())
	s.broadcastState()
	writeJSON(w, http.StatusOK, map[string]any{"domains": s.domainViews(), "providers": s.dnsProviderViews()})
}

// dnsProviderView hides the token but says whether one is stored.
func (s *Server) dnsProviderView(id string) DNSProviderView {
	for _, view := range s.dnsProviderViews() {
		if view.ID == id {
			return view
		}
	}
	return DNSProviderView{ID: id}
}

// dnsProviderPayload is the wire form of a provider.
type dnsProviderPayload struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Token   string `json:"token"`
	Zone    string `json:"zone"`
	Enabled *bool  `json:"enabled"`
}

func (p dnsProviderPayload) input() store.DNSProviderInput {
	return store.DNSProviderInput{
		Name:    p.Name,
		Kind:    p.Kind,
		Token:   p.Token,
		Zone:    p.Zone,
		Enabled: p.Enabled,
	}
}

// handleDomainSync forces one domain to be updated now.
func (s *Server) handleDomainSync(w http.ResponseWriter, r *http.Request, hostname string) {
	s.syncDomains(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"domains": s.domainViews()})
}
