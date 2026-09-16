package control

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/geoip"
)

// startGeoIP loads the country database in the background: a slow download must
// not delay the control node coming up, and country rules simply stay inert
// until it is ready.
func (s *Server) startGeoIP(ctx context.Context) {
	dir := s.opts.GeoIPDir
	if dir == "" {
		dir = filepath.Join(s.opts.StateDir, "geoip")
	}
	if _, err := os.Stat(dir); err != nil && s.geoIPCredentials().LicenseKey == "" {
		// Nothing local and no licence key: country rules stay disabled.
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if s.loadGeoIP(ctx, dir) == nil {
			return
		}
		// Without a licence key there is nothing to download; a local database is
		// still useful, so only retry when downloading is possible.
		if s.geoIPCredentials().LicenseKey == "" {
			return
		}
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if s.loadGeoIP(ctx, dir) == nil {
					return
				}
			}
		}
	}()
}

// loadGeoIP loads a cached database or downloads a fresh one.
func (s *Server) loadGeoIP(ctx context.Context, dir string) error {
	db, err := geoip.LoadOrDownload(ctx, geoip.Options{
		// Credentials come from the settings panel when no flags were given.
		AccountID:  s.geoIPCredentials().AccountID,
		LicenseKey: s.geoIPCredentials().LicenseKey,
		Dir:        dir,
	})
	if err != nil {
		s.log.Warn("country rules are disabled", "error", err)
		return err
	}
	s.useGeoIP(db)
	_, blocks, _ := db.Info()
	s.log.Info("country database ready", "networks", blocks, "directory", dir)
	s.mu.Lock()
	s.geoIP = db
	s.mu.Unlock()
	s.broadcastState()
	return nil
}
