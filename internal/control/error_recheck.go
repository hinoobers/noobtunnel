package control

import (
	"context"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	errorRecheckEvery = 30 * time.Second
	errorRetryPause   = time.Second
	errorRetryCount   = 3
)

// errorRecheckLoop revisits actionable errors every thirty seconds. An entry is
// removed only when three independent probes all say the failure is gone; one
// lucky DNS response or backend connection cannot hide an intermittent fault.
func (s *Server) errorRecheckLoop(ctx context.Context) {
	ticker := time.NewTicker(errorRecheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if len(s.errors.recent()) != 0 {
				s.recheckErrors(ctx)
			}
		}
	}
}

func (s *Server) recheckErrors(ctx context.Context) {
	entries := s.errors.recent()
	if len(entries) == 0 {
		return
	}
	resolved := make(map[string]bool, len(entries))
	for _, entry := range entries {
		resolved[errorFingerprint(entry)] = true
	}

	for attempt := 0; attempt < errorRetryCount; attempt++ {
		s.refreshErrorSources(ctx, entries, attempt)
		for _, entry := range entries {
			if s.errorIsActive(entry) {
				resolved[errorFingerprint(entry)] = false
			}
		}
		if attempt+1 < errorRetryCount {
			timer := time.NewTimer(errorRetryPause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}

	s.errors.remove(resolved)
	s.broadcastState()
}

// refreshErrorSources performs real checks for the kinds of error currently in
// the log. It deliberately does not manufacture traffic to published apps;
// resource health is refreshed by the proxy manager and by real requests.
func (s *Server) refreshErrorSources(ctx context.Context, entries []ErrorEntry, attempt int) {
	sources := make(map[string]bool, len(entries))
	for _, entry := range entries {
		sources[entry.Source] = true
	}
	if sources["resource"] || sources["target"] || sources["agent"] || sources["wireguard"] {
		s.proxies.Reconcile(s.ResourceSpecs())
		s.recordResourceErrors()
	}
	if sources["dns"] {
		checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		s.syncDomains(checkCtx)
		cancel()
	}
	if sources["geoip"] {
		s.mu.Lock()
		api := s.geoIP
		s.mu.Unlock()
		if api != nil && api.Configured() {
			// Different stable addresses make each attempt bypass a successful
			// cache entry, so three retries really are three API checks.
			addresses := [...]string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
			checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, _ = api.Lookup(checkCtx, netip.MustParseAddr(addresses[attempt%len(addresses)]))
			cancel()
		}
	}
}

func (s *Server) errorIsActive(entry ErrorEntry) bool {
	switch entry.Source {
	case "dns":
		for _, domain := range s.store.Domains() {
			if domain.LastError != "" && domain.LastError == entry.Detail {
				return true
			}
		}
		return false
	case "geoip":
		return s.geoIPStatus().LastError != ""
	case "certificate":
		name := strings.TrimPrefix(entry.Message, "no managed certificate for ")
		if name == entry.Message || name == "" {
			return true
		}
		published := strings.EqualFold(name, strings.TrimSpace(s.opts.Domain))
		for _, resource := range s.store.Resources() {
			if strings.EqualFold(resource.Domain, name) && resource.Protocol == "https" {
				published = true
				break
			}
		}
		if !published {
			return false
		}
		_, err := os.Stat(filepath.Join(s.opts.StateDir, "certificates", url.PathEscape(name)))
		return err != nil
	case "resource", "target", "agent", "wireguard":
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, detail := range s.reportedErrors {
			if detail == entry.Detail {
				return true
			}
		}
		return false
	default:
		// Unknown errors are retained: without a health source, absence is not
		// evidence that the problem recovered.
		return true
	}
}
