package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/geoip"
	"github.com/noobtunnel/noobtunnel/internal/store"
)

// This port is outside the 30000-59999 range used by resource forwards.
const geoIPForwardPort = 29999

// geoIPForwardTarget is the address the selected agent must dial locally.
func geoIPForwardTarget(host string) (string, error) {
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	u, err := url.Parse(host)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return "", fmt.Errorf("IP API address must be an HTTP or HTTPS URL or hostname")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// startGeoIP points the country lookup at the operator's IP API.
//
// There is nothing to download and nothing to keep fresh: the API answers per
// address, and the client caches the answers. Until a host is configured,
// resources with country rules deny requests with unknown countries.
func (s *Server) startGeoIP(ctx context.Context) {
	api := s.geoIPClient()
	s.useGeoIP(api)
	if !api.Configured() {
		return
	}
	// Resume recent countries that the previous process had not yet resolved.
	// The callback fills the stored rows when each background answer arrives.
	go func() {
		for _, addr := range s.requests.unknownIPs(50) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				api.Country(addr)
			}
		}
	}()
	// A lookup of a well known address tells the operator straight away whether
	// the host and token work.
	go func() {
		info, err := api.Lookup(ctx, netip.MustParseAddr("1.1.1.1"))
		if err != nil {
			s.log.Warn("the IP API did not answer", "error", err)
			return
		}
		s.log.Info("IP API ready", "country", info.Country, "from", info.CountryFrom)
		s.broadcastState()
	}()
}

// geoIPClient builds the lookup client from the flags first, then the stored
// settings, so a control node started with --ipapi-host needs no UI step.
func (s *Server) geoIPClient() *geoip.API {
	settings := s.store.GeoIP()
	host := strings.TrimSpace(s.opts.IPAPIHost)
	if host == "" {
		host = settings.Host
	}
	token := strings.TrimSpace(s.opts.IPAPIToken)
	if token == "" {
		token = settings.Token
	}
	self := geoip.New(host, token)
	if settings.AgentID != 0 {
		address := ""
		if agent, err := s.store.Agent(settings.AgentID); err == nil {
			address = net.JoinHostPort(agent.Address, fmt.Sprint(geoIPForwardPort))
		}
		self = geoip.NewVia(host, token, address)
	}
	api := self
	if settings.Provider == "ipapi" && strings.TrimSpace(s.opts.IPAPIHost) == "" {
		publicToken := settings.PublicToken
		if publicToken == "" && settings.Host == "https://api.ipapi.is" {
			// Read configurations saved by the first public-provider version.
			publicToken = settings.Token
		}
		api = geoip.NewPublic(publicToken)
		if settings.FallbackEnabled && host != "" && host != "https://api.ipapi.is" {
			api.SetFallback(self)
		}
	}
	api.SetCacheFile(filepath.Join(s.opts.StateDir, "geoip-cache.json"))
	// A failing API is a failure like any other: it belongs in Logs, Errors, with
	// the reason, instead of only in the settings panel.
	api.OnError = s.reportGeoIPError
	api.OnCountry = func(addr netip.Addr, country string) {
		if s.requests.resolveCountry(addr.String(), country) {
			s.broadcastState()
		}
	}
	return api
}

// reportGeoIPError records an API failure once per distinct message. Country
// lookups happen on the request path, so an API that is down would otherwise fill
// the Errors view with one entry per request.
func (s *Server) reportGeoIPError(err error) {
	if err == nil || s.errors == nil {
		return
	}
	message := err.Error()
	s.mu.Lock()
	changed := s.geoIPReported != message
	s.geoIPReported = message
	s.mu.Unlock()
	if !changed {
		return
	}
	s.log.Warn("the IP API is not answering", "error", message)
	s.errors.record("geoip", "the IP API is not answering", message,
		"check the host and token in Settings -> IP API; resources with country rules deny requests until a country is known")
}

// geoIPCredentials is what the control node would use right now, for the panel.
func (s *Server) geoIPCredentials() store.GeoIPConfig {
	settings := s.store.GeoIP()
	host := strings.TrimSpace(s.opts.IPAPIHost)
	provider := settings.Provider
	if host != "" {
		provider = "self"
	}
	if host == "" {
		host = settings.Host
	}
	token := strings.TrimSpace(s.opts.IPAPIToken)
	if token == "" {
		token = settings.Token
	}
	return store.GeoIPConfig{Provider: provider, Host: host, AgentID: settings.AgentID, Token: token, PublicToken: settings.PublicToken, FallbackEnabled: settings.FallbackEnabled}
}

// useGeoIP swaps the client in and gives it to the proxy, which is what country
// rules on resources are evaluated against.
func (s *Server) useGeoIP(api *geoip.API) {
	s.mu.Lock()
	s.geoIP = api
	s.mu.Unlock()
	s.wireCountryLookup(api)
	s.broadcastState()
}
