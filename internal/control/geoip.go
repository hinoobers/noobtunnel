package control

import (
	"context"
	"net/netip"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/geoip"
	"github.com/noobtunnel/noobtunnel/internal/store"
)

// startGeoIP points the country lookup at the operator's IP API.
//
// There is nothing to download and nothing to keep fresh: the API answers per
// address, and the client caches the answers. Until a host is configured, country
// rules simply have no data to match against.
func (s *Server) startGeoIP(ctx context.Context) {
	api := s.geoIPClient()
	s.useGeoIP(api)
	if !api.Configured() {
		return
	}
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
	return geoip.New(host, token)
}

// geoIPCredentials is what the control node would use right now, for the panel.
func (s *Server) geoIPCredentials() store.GeoIPConfig {
	settings := s.store.GeoIP()
	host := strings.TrimSpace(s.opts.IPAPIHost)
	if host == "" {
		host = settings.Host
	}
	token := strings.TrimSpace(s.opts.IPAPIToken)
	if token == "" {
		token = settings.Token
	}
	return store.GeoIPConfig{Host: host, Token: token}
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
