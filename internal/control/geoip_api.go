package control

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// geoIPCredentials prefers the command line over the stored configuration, so a
// server started with flags always wins.
func (s *Server) geoIPCredentials() store.GeoIPConfig {
	stored := s.store.GeoIP()
	key := s.opts.GeoIPLicenceKey
	if key == "" {
		key = stored.LicenseKey
	}
	account := s.opts.GeoIPAccountID
	if account == "" {
		account = stored.AccountID
	}
	return store.GeoIPConfig{LicenseKey: key, AccountID: account}
}

// GeoIPStatus describes the country database for the UI.
type GeoIPStatus struct {
	Configured bool   `json:"configured"`
	HasKey     bool   `json:"hasKey"`
	AccountID  string `json:"accountId,omitempty"`
	Ready      bool   `json:"ready"`
	Networks   int    `json:"networks,omitempty"`
	Source     string `json:"source,omitempty"`
	LoadedAt   string `json:"loadedAt,omitempty"`
	LastError  string `json:"lastError,omitempty"`
}

// geoIPStatus reports the current state of country data.
func (s *Server) geoIPStatus() GeoIPStatus {
	credentials := s.geoIPCredentials()
	status := GeoIPStatus{
		Configured: credentials.LicenseKey != "",
		HasKey:     credentials.LicenseKey != "",
		AccountID:  credentials.AccountID,
	}
	s.mu.Lock()
	db := s.geoIP
	status.LastError = s.geoIPError
	s.mu.Unlock()
	if db != nil && db.Loaded() {
		source, networks, loaded := db.Info()
		status.Ready = true
		status.Source = source
		status.Networks = networks
		status.LoadedAt = loaded.Format(timeLayout)
	}
	return status
}

// geoIPDir is where the database is cached.
func (s *Server) geoIPDir() string {
	if s.opts.GeoIPDir != "" {
		return s.opts.GeoIPDir
	}
	return s.opts.StateDir + "/geoip"
}

// GeoIPLookupForTest exposes the country lookup so tests can assert that a saved
// database is actually consulted (there is no country data on a test machine).
func (s *Server) GeoIPLookupForTest(addr string) string {
	s.mu.Lock()
	db := s.geoIP
	s.mu.Unlock()
	if db == nil {
		return ""
	}
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	return db.Lookup(parsed)
}

// handleGeoIP reads or updates the MaxMind credentials.
func (s *Server) handleGeoIP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"geoip": s.geoIPStatus()})
	case http.MethodPost:
		var body struct {
			LicenseKey string `json:"licenseKey"`
			AccountID  string `json:"accountId"`
			Clear      bool   `json:"clear"`
			Fetch      bool   `json:"fetch"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		cfg := store.GeoIPConfig{LicenseKey: body.LicenseKey, AccountID: body.AccountID}
		if body.Clear {
			cfg = store.GeoIPConfig{}
		} else if strings.TrimSpace(body.LicenseKey) == "" {
			// Leaving the field empty keeps the stored key.
			cfg.LicenseKey = s.store.GeoIP().LicenseKey
		}
		if err := s.store.SetGeoIP(cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		s.recordEvent("geoip", "MaxMind credentials updated")
		if body.Fetch && !body.Clear {
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
			err := s.loadGeoIP(ctx, s.geoIPDir())
			cancel()
			s.broadcastState()
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]any{"geoip": s.geoIPStatus(), "error": err.Error()})
				return
			}
		}
		s.broadcastState()
		writeJSON(w, http.StatusOK, map[string]any{"geoip": s.geoIPStatus()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errBody("use GET or POST"))
	}
}
