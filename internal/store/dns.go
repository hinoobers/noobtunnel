package store

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// DNSProviderKind is the API a provider talks.
type DNSProviderKind string

const (
	// DNSProviderCloudflare manages records through the Cloudflare API.
	DNSProviderCloudflare DNSProviderKind = "cloudflare"
	// DNSProviderManual means the operator creates records by hand; the control
	// node only shows what to create.
	DNSProviderManual DNSProviderKind = "manual"
)

// ValidDNSProviderKind reports whether k is supported.
func ValidDNSProviderKind(k DNSProviderKind) bool {
	return k == DNSProviderCloudflare || k == DNSProviderManual
}

// DNSProvider is an account the control node can create records with.
type DNSProvider struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Kind    DNSProviderKind `json:"kind"`
	Token   string          `json:"token,omitempty"`
	Enabled bool            `json:"enabled"`
	// Zone optionally pins the zone; otherwise it is discovered from the domain.
	Zone      string    `json:"zone,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// DNSProviderInput is a caller supplied provider description.
type DNSProviderInput struct {
	Name    string
	Kind    string
	Token   string
	Zone    string
	Enabled *bool
}

var (
	// ErrProviderInUse means domains still use the provider.
	ErrProviderInUse = errors.New("store: that provider is still used by a domain")
	// ErrBadProvider means the description is not usable.
	ErrBadProvider = errors.New("store: invalid DNS provider")
)

// DNSProviders lists configured providers.
func (s *Store) DNSProviders() []DNSProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]DNSProvider(nil), s.st.DNSProviders...)
}

// DNSProvider returns one provider.
func (s *Store) DNSProvider(id string) (DNSProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.st.DNSProviders {
		if p.ID == id {
			return p, nil
		}
	}
	return DNSProvider{}, ErrNotFound
}

// AddDNSProvider registers a provider.
func (s *Store) AddDNSProvider(in DNSProviderInput) (DNSProvider, error) {
	var created DNSProvider
	err := s.Update(func(st *State) error {
		provider, err := buildDNSProvider(in)
		if err != nil {
			return err
		}
		for _, existing := range st.DNSProviders {
			if strings.EqualFold(existing.Name, provider.Name) {
				return fmt.Errorf("%w: a provider called %q already exists", ErrBadProvider, provider.Name)
			}
		}
		id, err := randomToken(6)
		if err != nil {
			return err
		}
		provider.ID = id
		provider.CreatedAt = time.Now().UTC()
		st.DNSProviders = append(st.DNSProviders, provider)
		created = provider
		return nil
	})
	return created, err
}

// UpdateDNSProvider changes a provider. An empty token keeps the stored one, so
// the UI never has to show it.
func (s *Store) UpdateDNSProvider(id string, in DNSProviderInput) (DNSProvider, error) {
	var updated DNSProvider
	err := s.Update(func(st *State) error {
		index := -1
		for i := range st.DNSProviders {
			if st.DNSProviders[i].ID == id {
				index = i
				break
			}
		}
		if index < 0 {
			return ErrNotFound
		}
		current := st.DNSProviders[index]
		if strings.TrimSpace(in.Token) == "" {
			in.Token = current.Token
		}
		provider, err := buildDNSProvider(in)
		if err != nil {
			return err
		}
		provider.ID = id
		provider.CreatedAt = current.CreatedAt
		st.DNSProviders[index] = provider
		updated = provider
		return nil
	})
	return updated, err
}

// RemoveDNSProvider deletes a provider that no domain uses.
func (s *Store) RemoveDNSProvider(id string) error {
	return s.Update(func(st *State) error {
		found := false
		for _, p := range st.DNSProviders {
			if p.ID == id {
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
		for _, d := range st.Domains {
			if d.ProviderID == id {
				return fmt.Errorf("%w: %s uses it", ErrProviderInUse, d.Hostname)
			}
		}
		out := st.DNSProviders[:0]
		for _, p := range st.DNSProviders {
			if p.ID == id {
				continue
			}
			out = append(out, p)
		}
		st.DNSProviders = out
		return nil
	})
}

// SetDomainProvider attaches a provider to a domain. An empty id means "manage
// this record by hand".
func (s *Store) SetDomainProvider(hostname, providerID string) (Domain, error) {
	host, err := NormaliseHostname(hostname)
	if err != nil {
		return Domain{}, err
	}
	var updated Domain
	err = s.Update(func(st *State) error {
		if providerID != "" {
			known := false
			for _, p := range st.DNSProviders {
				if p.ID == providerID {
					known = true
					break
				}
			}
			if !known {
				return fmt.Errorf("%w: that provider does not exist", ErrBadProvider)
			}
		}
		for i := range st.Domains {
			if st.Domains[i].Hostname != host {
				continue
			}
			st.Domains[i].ProviderID = providerID
			st.Domains[i].LastError = ""
			updated = st.Domains[i]
			return nil
		}
		return ErrNotFound
	})
	return updated, err
}

// RecordDomainSync stores the outcome of a DNS update.
func (s *Store) RecordDomainSync(hostname, address string, syncErr error) error {
	host, err := NormaliseHostname(hostname)
	if err != nil {
		return err
	}
	return s.Update(func(st *State) error {
		for i := range st.Domains {
			if st.Domains[i].Hostname != host {
				continue
			}
			st.Domains[i].Address = address
			st.Domains[i].LastSync = time.Now().UTC()
			if syncErr == nil {
				st.Domains[i].LastError = ""
			} else {
				st.Domains[i].LastError = syncErr.Error()
			}
			return nil
		}
		return ErrNotFound
	})
}

// buildDNSProvider validates a provider description.
func buildDNSProvider(in DNSProviderInput) (DNSProvider, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return DNSProvider{}, fmt.Errorf("%w: give the provider a name", ErrBadProvider)
	}
	kind := DNSProviderKind(strings.ToLower(strings.TrimSpace(in.Kind)))
	if kind == "" {
		kind = DNSProviderCloudflare
	}
	if !ValidDNSProviderKind(kind) {
		return DNSProvider{}, fmt.Errorf("%w: kind must be cloudflare", ErrBadProvider)
	}
	provider := DNSProvider{Name: name, Kind: kind, Enabled: true, Zone: strings.TrimSpace(in.Zone)}
	if in.Enabled != nil {
		provider.Enabled = *in.Enabled
	}
	if kind == DNSProviderCloudflare {
		if strings.TrimSpace(in.Token) == "" {
			return DNSProvider{}, fmt.Errorf("%w: a Cloudflare API token is required", ErrBadProvider)
		}
		provider.Token = strings.TrimSpace(in.Token)
	}
	return provider, nil
}

// GeoIPConfig holds the MaxMind credentials used for country access rules.
type GeoIPConfig struct {
	// LicenseKey is a secret: it lives in the state file (0600) and is never
	// returned by the API.
	LicenseKey string `json:"licenseKey,omitempty"`
	// AccountID is optional; with it the newer authenticated endpoint is used.
	AccountID string `json:"accountId,omitempty"`
}

// GeoIP returns the stored MaxMind credentials.
func (s *Store) GeoIP() GeoIPConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.GeoIP
}

// SetGeoIP stores MaxMind credentials; an empty licence key clears them.
func (s *Store) SetGeoIP(cfg GeoIPConfig) error {
	return s.Update(func(st *State) error {
		st.GeoIP = GeoIPConfig{
			LicenseKey: strings.TrimSpace(cfg.LicenseKey),
			AccountID:  strings.TrimSpace(cfg.AccountID),
		}
		return nil
	})
}
