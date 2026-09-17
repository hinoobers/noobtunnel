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
	api := geoip.New(host, token)
	// A failing API is a failure like any other: it belongs in Logs, Errors, with
	// the reason, instead of only in the settings panel.
	api.OnError = s.reportGeoIPError
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
		"check the host and token in Settings -> IP API; country rules have no data until it answers")
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
