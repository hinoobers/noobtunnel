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
	Provider           string  `json:"provider"`
	Configured         bool    `json:"configured"`
	HasToken           bool    `json:"hasToken"`
	Host               string  `json:"host,omitempty"`
	AgentID            uint32  `json:"agentId,omitempty"`
	IPLogConfigured    bool    `json:"iplogConfigured"`
	FallbackEnabled    bool    `json:"fallbackEnabled"`
	FallbackHost       string  `json:"fallbackHost,omitempty"`
	FallbackLookups    int     `json:"fallbackLookups,omitempty"`
	LastFallbackReason string  `json:"lastFallbackReason,omitempty"`
	Ready              bool    `json:"ready"`
	Cached             int     `json:"cached,omitempty"`
	AvgResponseMs      float64 `json:"avgResponseMs,omitempty"`
	Lookups            int     `json:"lookups,omitempty"`
	LastAt             string  `json:"lastAt,omitempty"`
	LastError          string  `json:"lastError,omitempty"`
}

// geoIPStatus reports the current state of country lookups.
func (s *Server) geoIPStatus() GeoIPStatus {
	credentials := s.geoIPCredentials()
	status := GeoIPStatus{
		Provider:        credentials.Provider,
		Configured:      credentials.Host != "",
		HasToken:        credentials.Token != "",
		Host:            credentials.Host,
		AgentID:         credentials.AgentID,
		IPLogConfigured: credentials.Host != "" && credentials.Host != "https://api.ipapi.is",
		FallbackEnabled: false,
	}
	if status.IPLogConfigured && credentials.AgentID != 0 {
		agent, err := s.store.Agent(credentials.AgentID)
		status.IPLogConfigured = err == nil && agent.Enabled && agent.PublicKey != ""
	}
	if status.IPLogConfigured {
		_, err := geoIPForwardTarget(credentials.Host)
		status.IPLogConfigured = err == nil
	}
	status.FallbackEnabled = credentials.Provider == "ipapi" && credentials.FallbackEnabled && status.IPLogConfigured
	if credentials.Provider == "ipapi" {
		status.Configured = credentials.PublicToken != ""
		status.HasToken = credentials.PublicToken != ""
		if status.FallbackEnabled {
			status.FallbackHost = credentials.Host
		}
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
	status.AvgResponseMs = float64(api.AverageResponse().Microseconds()) / 1000
	status.Lookups = lookups
	status.LastError = lastError
	status.FallbackLookups, status.LastFallbackReason = api.FallbackStats()
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
	// The waiting form: a caller of this wants an answer, not a promise of one.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return api.CountryForDecision(ctx, parsed)
}

// handleGeoIP reads or updates the IP API settings, and can test them.
func (s *Server) handleGeoIP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"geoip": s.geoIPStatus()})
	case http.MethodPost:
		var body struct {
			Provider        string  `json:"provider"`
			Host            string  `json:"host"`
			Token           string  `json:"token"`
			PublicToken     string  `json:"publicToken"`
			FallbackEnabled *bool   `json:"fallbackEnabled"`
			AgentID         *uint32 `json:"agentId"`
			Clear           bool    `json:"clear"`
			// Check looks up one address with the settings as they are saved, so
			// the panel can say whether the host and token work.
			Check bool `json:"check"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		previous := s.store.GeoIP()
		cfg := previous
		cfg.Provider = body.Provider
		if cfg.Provider == "" {
			cfg.Provider = "self"
		}
		if cfg.Provider != "self" && cfg.Provider != "ipapi" {
			writeJSON(w, http.StatusBadRequest, errBody("select a valid IP API provider"))
			return
		}
		if body.AgentID != nil {
			cfg.AgentID = *body.AgentID
		}
		if body.FallbackEnabled != nil {
			cfg.FallbackEnabled = *body.FallbackEnabled
		}
		switch {
		case body.Clear:
			cfg = store.GeoIPConfig{}
		case cfg.Provider == "ipapi":
			if body.Host != "" {
				cfg.Host = strings.TrimSpace(body.Host)
			}
			if previous.Host == "https://api.ipapi.is" && body.Host == "" {
				cfg.Host = ""
			}
			if body.Token != "" {
				cfg.Token = body.Token
			}
			if previous.Host == "https://api.ipapi.is" {
				cfg.Token = body.Token
			}
			if body.PublicToken != "" {
				cfg.PublicToken = body.PublicToken
			}
			if cfg.PublicToken == "" && previous.Host == "https://api.ipapi.is" {
				cfg.PublicToken = previous.Token
			}
			if cfg.PublicToken == "" {
				writeJSON(w, http.StatusBadRequest, errBody("enter an ipapi.is API key"))
				return
			}
		case strings.TrimSpace(body.Host) == "":
			if previous.Provider == "ipapi" && (previous.Host == "" || previous.Host == "https://api.ipapi.is") {
				writeJSON(w, http.StatusBadRequest, errBody("enter the self-hosted API address"))
				return
			}
			// Leaving the field empty keeps what is stored; the token is kept
			// unless a new one is typed.
			if body.Token != "" {
				cfg.Token = body.Token
			}
		default:
			cfg.Host = strings.TrimSpace(body.Host)
			if body.Token != "" {
				cfg.Token = body.Token
			}
		}
		if cfg.Provider == "ipapi" && cfg.FallbackEnabled && (cfg.Host == "" || cfg.Host == "https://api.ipapi.is") {
			writeJSON(w, http.StatusBadRequest, errBody("configure iplog before enabling fallback"))
			return
		}
		if cfg.Provider == "ipapi" && cfg.FallbackEnabled {
			if _, err := geoIPForwardTarget(cfg.Host); err != nil {
				writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
				return
			}
		}
		if cfg.AgentID != 0 && (cfg.Provider != "ipapi" || cfg.FallbackEnabled) {
			if cfg.Host == "" {
				writeJSON(w, http.StatusBadRequest, errBody("enter the iplog address for the selected agent"))
				return
			}
			agent, err := s.store.Agent(cfg.AgentID)
			if err != nil || !agent.Enabled || agent.PublicKey == "" {
				writeJSON(w, http.StatusBadRequest, errBody("select an enrolled, enabled agent for the IP API"))
				return
			}
			if _, err := geoIPForwardTarget(cfg.Host); err != nil {
				writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
				return
			}
		}
		if err := s.store.SetGeoIP(cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.markDirty()
		api := s.geoIPClient()
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
