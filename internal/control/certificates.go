package control

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/geoip"
	"github.com/noobtunnel/noobtunnel/internal/proxy"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"golang.org/x/crypto/acme/autocert"
)

// worthReporting keeps the Errors view about the operator's own names.
//
// A handshake with no server name, or one asking for a name that is not published
// here, is a scanner or a misconfigured client. There is nothing to fix, and
// reporting it does two harmful things: it buries the failures the operator can
// act on, and it names domains they do not own - which reasonably makes people
// wonder what happened to their server. The certificate is never requested for
// such a name either: the host policy refuses it before anything is asked of the
// certificate authority.
func worthReporting(name string, err error) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, noise := range []string{"missing server name", "no https resource is published"} {
		if strings.Contains(message, noise) {
			return false
		}
	}
	return true
}

// newProxyManager builds the resource proxy manager, wiring in the certificate
// provider for terminated HTTPS resources and the account check used by identity
// controlled ones.
func newProxyManager(opts Options, st *store.Store, auth *store.Auth, requestEvents *requestLog, errorEvents *errorLog) *proxy.Manager {
	manager := proxy.New(opts.Logger)
	// The name on a published service's error pages follows the operator's brand.
	manager.SetBrandName(st.Settings().BrandName)
	selfSigned := proxy.NewSelfSignedProvider()

	// Managed certificates are the default: an HTTPS resource with a domain gets
	// a certificate issued for it automatically, with a self-signed fallback so a
	// certificate authority outage (or a domain that does not point here yet)
	// never takes the service down.
	{
		email := strings.TrimSpace(opts.ACMEEmail)
		// The control node's own hostname is issued a certificate too, so the UI
		// is reachable on its domain without a browser warning.
		controlName := strings.ToLower(strings.TrimSpace(opts.Domain))
		// Managed certificates: ask Let's Encrypt per domain, and fall back to a
		// self-signed certificate so a certificate authority outage never takes a
		// published service down.
		acmeManager := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(opts.StateDir, "certificates")),
			Email:  email,
			// Only names that are actually published as HTTPS resources may be
			// requested, plus the control node's own name, so a stray SNI cannot
			// burn rate limits.
			HostPolicy: func(_ context.Context, host string) error {
				host = strings.ToLower(strings.TrimSpace(host))
				if controlName != "" && host == controlName {
					return nil
				}
				for _, r := range st.Resources() {
					if r.Domain == host && r.Protocol == store.ProtocolHTTPS {
						return nil
					}
				}
				return fmt.Errorf("no https resource is published for %s", host)
			},
		}
		manager.Certificates = &proxy.FallbackProvider{
			Primary:  acmeManager,
			Fallback: selfSigned,
			OnError: func(name string, err error) {
				if worthReporting(name, err) {
					opts.Logger.Warn("could not obtain a managed certificate, serving a self-signed one",
						"domain", name, "error", err)
					errorEvents.record("certificate", "no managed certificate for "+name, err.Error(),
						"check that the name resolves here and that port 80 is reachable for the ACME challenge")
					return
				}
				// A scanner asking for somebody else's name is worth a debug line,
				// not a warning people will read and worry about.
				opts.Logger.Debug("ignoring a certificate request for a name that is not published here",
					"domain", name, "error", err)
			},
		}
		// HTTP-01 validation is answered on the ports HTTP resources use.
		manager.ACMEChallenge = acmeManager.HTTPHandler(nil)
		// The control node's own UI is published on the shared HTTPS port, so
		// browsers reach it on the domain with the same managed certificate.
		manager.ControlDomain = controlName
		manager.ControlPort = opts.ControlRoutePort
		opts.Logger.Info("managed certificates enabled",
			"email", email, "cache", filepath.Join(opts.StateDir, "certificates"), "default", true)
	}

	manager.IdentityCheck = func(username, password string) error {
		if !auth.HasUsers() {
			return fmt.Errorf("no accounts are configured")
		}
		_, err := auth.Authenticate(username, password)
		return err
	}
	// How long a connection to a published target may take. Tests shorten it so a
	// target that cannot be reached fails quickly.
	if opts.ProxyDialTimeout > 0 {
		manager.DialTimeout = opts.ProxyDialTimeout
	}
	// Every request the proxy handles is recorded for the Logs tab.
	if requestEvents != nil {
		manager.OnRequest = requestEvents.record
	}
	return manager
}

// useGeoIP gives the proxy manager a country lookup, so country rules work. The
// answer comes from the IP API (see geoip.go) with the client's own cache in
// front of it, because this runs while a request is being handled.
func (s *Server) wireCountryLookup(api *geoip.API) {
	if api == nil {
		return
	}
	// A decision waits, briefly, for an answer; the request log never waits, and
	// starts a lookup in the background instead.
	s.proxies.CountryOf = func(addr netip.Addr) string {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return api.CountryForDecision(ctx, addr)
	}
	s.proxies.CountryOfFast = func(addr netip.Addr) string { return api.Country(addr) }
}
