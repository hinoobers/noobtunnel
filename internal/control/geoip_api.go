package control

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/geoip"
	"github.com/noobtunnel/noobtunnel/internal/store"
)

// ReportGeoIPErrorForTest lets a test drive what the API client would report,
// without standing up a failing API.
func (s *Server) ReportGeoIPErrorForTest(err error) { s.reportGeoIPError(err) }

// ErrorsForTest exposes the recorded errors, newest first.
func (s *Server) ErrorsForTest() []ErrorEntry {
	if s.errors == nil {
		return nil
	}
	return s.errors.recent()
}

// GeoIPStatus describes the IP API for the settings panel.
type GeoIPStatus struct {
	Configured bool   `json:"configured"`
	HasToken   bool   `json:"hasToken"`
	Host       string `json:"host,omitempty"`
	Ready      bool   `json:"ready"`
	Cached     int    `json:"cached,omitempty"`
	Lookups    int    `json:"lookups,omitempty"`
	LastAt     string `json:"lastAt,omitempty"`
	LastError  string `json:"lastError,omitempty"`
}

// geoIPStatus reports the current state of country lookups.
func (s *Server) geoIPStatus() GeoIPStatus {
	credentials := s.geoIPCredentials()
	status := GeoIPStatus{
		Configured: credentials.Host != "",
		HasToken:   credentials.Token != "",
		Host:       credentials.Host,
	}
	s.mu.Lock()
	api := s.geoIP
	s.mu.Unlock()
	if api == nil {
		return status
	}
	_, cached, lookups, lastAt, lastError := api.Stats()
	status.Ready = api.Ready()
	status.Cached = cached
	status.Lookups = lookups
	status.LastError = lastError
	if !lastAt.IsZero() {
		status.LastAt = lastAt.Format(timeLayout)
	}
	return status
}

// GeoIPLookupForTest exposes the lookup so tests can assert that a configured API
// is actually consulted, and that a country rule sees its answer.
func (s *Server) GeoIPLookupForTest(addr string) string {
	s.mu.Lock()
	api := s.geoIP
	s.mu.Unlock()
	if api == nil {
		return ""
	}
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	return api.Country(parsed)
}

// handleGeoIP reads or updates the IP API settings, and can test them.
func (s *Server) handleGeoIP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"geoip": s.geoIPStatus()})
	case http.MethodPost:
		var body struct {
			Host  string `json:"host"`
			Token string `json:"token"`
			Clear bool   `json:"clear"`
			// Check looks up one address with the settings as they are saved, so
			// the panel can say whether the host and token work.
			Check bool `json:"check"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		cfg := store.GeoIPConfig{Host: body.Host, Token: body.Token}
		switch {
		case body.Clear:
			cfg = store.GeoIPConfig{}
		case strings.TrimSpace(body.Host) == "":
			// Leaving the field empty keeps what is stored; the token is kept
			// unless a new one is typed.
			cfg.Host = s.store.GeoIP().Host
			if strings.TrimSpace(body.Token) == "" {
				cfg.Token = s.store.GeoIP().Token
			}
		case strings.TrimSpace(body.Token) == "":
			cfg.Token = s.store.GeoIP().Token
		}
		if err := s.store.SetGeoIP(cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		api := s.geoIPClient()
		api.Clear()
		s.useGeoIP(api)
		if body.Clear {
			s.recordEvent("geoip", "IP API removed")
		} else {
			s.recordEvent("geoip", "IP API updated")
		}
		if body.Check && !body.Clear {
			// The check may take longer than a request would: an API behind a
			// published service goes through the tunnel too.
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			info, err := api.Lookup(ctx, netip.MustParseAddr("1.1.1.1"))
			cancel()
			s.broadcastState()
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]any{"geoip": s.geoIPStatus(), "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"geoip":      s.geoIPStatus(),
				"check":      info,
				"checkedFor": "1.1.1.1",
			})
			return
		}
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"geoip": s.geoIPStatus()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}

// geoipLookupInfo is the lookup shape the panel shows after a test.
type geoipLookupInfo = geoip.Lookup
