// Package store persists control node state: mesh settings, enrolled agents and
// the hub's own WireGuard keys.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/ipam"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// DefaultSettings are applied to a fresh control node.
func DefaultSettings() Settings {
	return Settings{
		MeshName:           "noobtunnel",
		BrandName:          "noobtunnel",
		MeshCIDR:           "10.77.0.0/16",
		MTU:                1420,
		KeepaliveSec:       25,
		DirectPaths:        true,
		Interface:          "noobtun",
		WGListenPort:       51820,
		ControlListenAddr:  ":8443",
		StatsIntervalSec:   5,
		DirectFreshSec:     180,
		DirectProbeSec:     30,
		AgentInactivitySec: 90,
	}
}

// Settings are the control node's tunables.
type Settings struct {
	MeshName string `json:"meshName"`
	// BrandName is what the UI calls this deployment. It is separate from the
	// mesh name so an operator can rename the product without touching the
	// WireGuard configuration.
	BrandName          string `json:"brandName,omitempty"`
	MeshCIDR           string `json:"meshCidr"`
	MTU                int    `json:"mtu"`
	KeepaliveSec       int    `json:"keepaliveSec"`
	DirectPaths        bool   `json:"directPaths"`
	Interface          string `json:"interface"`
	WGListenPort       int    `json:"wgListenPort"`
	ControlListenAddr  string `json:"controlListenAddr"`
	PublicEndpoint     string `json:"publicEndpoint"`
	StatsIntervalSec   int    `json:"statsIntervalSec"`
	DirectFreshSec     int    `json:"directFreshSec"`
	DirectProbeSec     int    `json:"directProbeSec"`
	AgentInactivitySec int    `json:"agentInactivitySec"`
}

// Validate normalises and checks the settings.
func (s *Settings) Validate() error {
	if strings.TrimSpace(s.MeshName) == "" {
		s.MeshName = "noobtunnel"
	}
	if s.BrandName = strings.TrimSpace(s.BrandName); s.BrandName == "" {
		s.BrandName = "noobtunnel"
	}
	// The name is rendered in the header and in the page title: keep it short
	// and free of control characters so a paste cannot break the layout.
	s.BrandName = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s.BrandName)
	if runes := []rune(s.BrandName); len(runes) > 40 {
		s.BrandName = strings.TrimSpace(string(runes[:40]))
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(s.MeshCIDR))
	if err != nil {
		return fmt.Errorf("mesh CIDR %q is invalid: %w", s.MeshCIDR, err)
	}
	s.MeshCIDR = prefix.Masked().String()
	if s.MTU < 1280 || s.MTU > wg.MaxMTU {
		return fmt.Errorf("MTU %d is outside the supported range 1280-%d", s.MTU, wg.MaxMTU)
	}
	if s.KeepaliveSec < 0 || s.KeepaliveSec > 3600 {
		return fmt.Errorf("keepalive %d must be between 0 and 3600 seconds", s.KeepaliveSec)
	}
	if s.WGListenPort < 1 || s.WGListenPort > 65535 {
		return fmt.Errorf("WireGuard listen port %d is invalid", s.WGListenPort)
	}
	if err := wg.ValidateInterfaceName(s.Interface); err != nil {
		return err
	}
	if s.StatsIntervalSec < 1 {
		s.StatsIntervalSec = 5
	}
	if s.DirectFreshSec < 5 {
		s.DirectFreshSec = 180
	}
	if s.DirectProbeSec < 1 {
		s.DirectProbeSec = 30
	}
	if s.AgentInactivitySec < 30 {
		s.AgentInactivitySec = 90
	}
	return nil
}

// HubKeys are the control node's own WireGuard keys.
type HubKeys struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

// Agent is one enrolled mesh member.
type Agent struct {
	ID        uint32   `json:"id"`
	Name      string   `json:"name"`
	Token     string   `json:"token"`
	PublicKey string   `json:"publicKey,omitempty"`
	Address   string   `json:"address"`
	Advertise []string `json:"advertise,omitempty"`
	// HubPresharedKey secures the agent <-> control node WireGuard session.
	HubPresharedKey string `json:"hubPresharedKey"`
	Enabled         bool   `json:"enabled"`
	// AdvertiseAll tells the agent to route every network it can reach, instead
	// of the explicit Advertise list.
	AdvertiseAll bool       `json:"advertiseAll,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	EnrolledAt   *time.Time `json:"enrolledAt,omitempty"`
	LastSeen     time.Time  `json:"lastSeen,omitempty"`
	Version      string     `json:"version,omitempty"`
	Hostname     string     `json:"hostname,omitempty"`
	OS           string     `json:"os,omitempty"`
	Arch         string     `json:"arch,omitempty"`
	Notes        string     `json:"notes,omitempty"`
}

// Expired reports whether the enrollment window has passed.
func (a *Agent) Expired(now time.Time) bool {
	return a.ExpiresAt != nil && now.After(*a.ExpiresAt)
}

// AddressPrefix returns the overlay address as a /32 prefix.
func (a *Agent) AddressPrefix() (netip.Prefix, error) {
	addr, err := netip.ParseAddr(a.Address)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, 32), nil
}

// State is the persisted control node state.
type State struct {
	Version     int               `json:"version"`
	Settings    Settings          `json:"settings"`
	Hub         HubKeys           `json:"hub"`
	Agents      []*Agent          `json:"agents"`
	PairKeys    map[string]string `json:"pairKeys,omitempty"`
	NextAgentID uint32            `json:"nextAgentId"`
	// Resources are services published through the mesh; Domains are the
	// hostnames they can be reached on.
	Resources      []*Resource `json:"resources,omitempty"`
	Domains        []Domain    `json:"domains,omitempty"`
	NextResourceID uint32      `json:"nextResourceId,omitempty"`
	// ExitNodes are the public addresses resources can be published on.
	ExitNodes []ExitNode `json:"exitNodes,omitempty"`
	// DNSProviders are the accounts used to create domain records automatically.
	DNSProviders []DNSProvider `json:"dnsProviders,omitempty"`
	// GeoIP holds the MaxMind credentials for country access rules.
	GeoIP GeoIPConfig `json:"geoip,omitempty"`
}

// ErrNotFound means the requested agent does not exist.
var ErrNotFound = errors.New("store: agent not found")

// Store is a concurrency safe, atomically persisted state holder.
type Store struct {
	path string
	mu   sync.RWMutex
	st   *State
}

// Open loads or creates the state file in dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create state directory: %w", err)
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	raw, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		st := &State{}
		if err := json.Unmarshal(raw, st); err != nil {
			return nil, fmt.Errorf("store: parse %s: %w", s.path, err)
		}
		s.st = st
	case os.IsNotExist(err):
		s.st = &State{Version: 1, Settings: DefaultSettings(), PairKeys: map[string]string{}}
	default:
		return nil, fmt.Errorf("store: read %s: %w", s.path, err)
	}
	if err := s.initialise(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the state file path.
func (s *Store) Path() string { return s.path }

func (s *Store) initialise() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	if s.st.Version == 0 {
		s.st.Version = 1
		changed = true
	}
	if s.st.Settings.MeshCIDR == "" {
		s.st.Settings = DefaultSettings()
		changed = true
	}
	if err := s.st.Settings.Validate(); err != nil {
		return err
	}
	if !wg.ValidKey(s.st.Hub.PrivateKey) {
		kp, err := wg.GenerateKeyPair()
		if err != nil {
			return err
		}
		s.st.Hub = HubKeys{PrivateKey: kp.Private, PublicKey: kp.Public}
		changed = true
	}
	if s.st.PairKeys == nil {
		s.st.PairKeys = map[string]string{}
		changed = true
	}
	if s.st.NextAgentID == 0 {
		s.st.NextAgentID = 1
		changed = true
	}
	if s.st.NextResourceID == 0 {
		s.st.NextResourceID = 1
		changed = true
	}
	if err := s.migrateResourcesLocked(); err != nil {
		return err
	}
	if created, err := s.ensureControlExitNodeLocked(); err != nil {
		return err
	} else if created {
		changed = true
	}
	if repaired, err := s.repairAddressesLocked(); err != nil {
		return err
	} else if repaired {
		changed = true
	}
	if changed {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("store: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("store: replace %s: %w", s.path, err)
	}
	return nil
}

// View returns a deep copy of the state, safe to read without holding the lock.
func (s *Store) View() *State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.copyLocked()
}

func (s *Store) copyLocked() *State {
	cp := &State{
		Version:     s.st.Version,
		Settings:    s.st.Settings,
		Hub:         s.st.Hub,
		NextAgentID: s.st.NextAgentID,
		PairKeys:    map[string]string{},
	}
	for k, v := range s.st.PairKeys {
		cp.PairKeys[k] = v
	}
	for _, a := range s.st.Agents {
		dup := *a
		dup.Advertise = append([]string(nil), a.Advertise...)
		cp.Agents = append(cp.Agents, &dup)
	}
	for _, r := range s.st.Resources {
		dup := *r
		cp.Resources = append(cp.Resources, &dup)
	}
	cp.Domains = append(cp.Domains, s.st.Domains...)
	cp.NextResourceID = s.st.NextResourceID
	cp.ExitNodes = append(cp.ExitNodes, s.st.ExitNodes...)
	cp.DNSProviders = append(cp.DNSProviders, s.st.DNSProviders...)
	cp.GeoIP = s.st.GeoIP
	return cp
}

// migrateResourcesLocked upgrades resources created before a resource could hold
// several targets or choose an exit node.
func (s *Store) migrateResourcesLocked() error {
	changed := false
	for _, r := range s.st.Resources {
		if len(r.Targets) == 0 && r.TargetHost != "" {
			r.Targets = []ResourceTarget{{
				ID: 1, AgentID: r.AgentID, Host: r.TargetHost, Port: r.TargetPort, Enabled: true,
			}}
			r.TargetHost, r.TargetPort, r.AgentID = "", 0, 0
			changed = true
		}
		if r.Strategy == "" {
			r.Strategy = StrategyRoundRobin
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

// Update applies mutate to the state and persists the result.
func (s *Store) Update(mutate func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := mutate(s.st); err != nil {
		return err
	}
	if err := s.st.Settings.Validate(); err != nil {
		return err
	}
	return s.saveLocked()
}

// Settings returns the current settings.
func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.Settings
}

// Hub returns the control node's WireGuard keys.
func (s *Store) Hub() HubKeys {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.Hub
}

// Agents returns the enrolled agents sorted by name.
func (s *Store) Agents() []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Agent, 0, len(s.st.Agents))
	for _, a := range s.st.Agents {
		dup := *a
		out = append(out, &dup)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Agent returns one agent by id.
func (s *Store) Agent(id uint32) (*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a := findAgent(s.st, id)
	if a == nil {
		return nil, ErrNotFound
	}
	dup := *a
	return &dup, nil
}

// AgentByToken returns the agent that owns a token.
func (s *Store) AgentByToken(token string) (*Agent, error) {
	tokenID, ok := TokenID(token)
	if !ok {
		return nil, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.st.Agents {
		if gotID, ok := TokenID(a.Token); ok && gotID == tokenID {
			dup := *a
			return &dup, nil
		}
	}
	return nil, ErrNotFound
}

// AddAgentParams describes a new enrollment.
type AddAgentParams struct {
	Name      string
	Advertise []string
	TTL       time.Duration
	// AdvertiseAll routes everything the agent can reach.
	AdvertiseAll bool
}

// AddAgent creates a new enrollment slot with a fresh token and overlay address.
func (s *Store) AddAgent(p AddAgentParams) (*Agent, error) {
	advertise, err := NormalisePrefixes(p.Advertise)
	if err != nil {
		return nil, err
	}
	token, err := NewToken()
	if err != nil {
		return nil, err
	}
	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		return nil, err
	}
	var created *Agent
	err = s.Update(func(st *State) error {
		pool, err := ipam.New(st.Settings.MeshCIDR)
		if err != nil {
			return err
		}
		taken := map[netip.Addr]bool{}
		for _, a := range st.Agents {
			if addr, err := netip.ParseAddr(a.Address); err == nil {
				taken[addr] = true
			}
		}
		taken[pool.HubAddress()] = true
		addr, err := pool.Allocate(taken)
		if err != nil {
			return err
		}
		if st.NextAgentID == 0 {
			st.NextAgentID = 1
		}
		agent := &Agent{
			ID:              st.NextAgentID,
			Name:            uniqueName(st.Agents, p.Name, st.NextAgentID),
			Token:           token,
			Address:         addr.String(),
			Advertise:       advertise,
			HubPresharedKey: psk,
			Enabled:         true,
			AdvertiseAll:    p.AdvertiseAll,
			CreatedAt:       time.Now().UTC(),
		}
		if p.TTL > 0 {
			exp := time.Now().UTC().Add(p.TTL)
			agent.ExpiresAt = &exp
		}
		st.NextAgentID++
		st.Agents = append(st.Agents, agent)
		dup := *agent
		created = &dup
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func uniqueName(existing []*Agent, want string, id uint32) string {
	name := strings.TrimSpace(want)
	if name == "" {
		name = fmt.Sprintf("agent-%d", id)
	}
	taken := map[string]bool{}
	for _, a := range existing {
		taken[strings.ToLower(a.Name)] = true
	}
	if !taken[strings.ToLower(name)] {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", name, i)
		if !taken[strings.ToLower(candidate)] {
			return candidate
		}
	}
}

// UpdateAgent applies a mutation to one agent.
func (s *Store) UpdateAgent(id uint32, mutate func(*Agent) error) error {
	return s.Update(func(st *State) error {
		a := findAgent(st, id)
		if a == nil {
			return ErrNotFound
		}
		return mutate(a)
	})
}

// RemoveAgent deletes an enrollment slot and its pair keys.
func (s *Store) RemoveAgent(id uint32) error {
	return s.Update(func(st *State) error {
		out := st.Agents[:0]
		found := false
		for _, a := range st.Agents {
			if a.ID == id {
				found = true
				continue
			}
			out = append(out, a)
		}
		if !found {
			return ErrNotFound
		}
		st.Agents = out
		for k := range st.PairKeys {
			if keyHasMember(k, id) {
				delete(st.PairKeys, k)
			}
		}
		return nil
	})
}

func keyHasMember(key string, id uint32) bool {
	var a, b uint32
	if _, err := fmt.Sscanf(key, "%d-%d", &a, &b); err != nil {
		return false
	}
	return a == id || b == id
}

func findAgent(st *State, id uint32) *Agent {
	for _, a := range st.Agents {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// PairKey returns, creating if needed, the preshared key for an agent pair.
func (s *Store) PairKey(a, b uint32) (string, error) {
	if a == b {
		return "", errors.New("store: pair key needs two distinct agents")
	}
	if a > b {
		a, b = b, a
	}
	key := fmt.Sprintf("%d-%d", a, b)
	s.mu.RLock()
	existing, ok := s.st.PairKeys[key]
	s.mu.RUnlock()
	if ok {
		return existing, nil
	}
	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		return "", err
	}
	err = s.Update(func(st *State) error {
		if st.PairKeys == nil {
			st.PairKeys = map[string]string{}
		}
		if cur, ok := st.PairKeys[key]; ok {
			psk = cur
			return nil
		}
		st.PairKeys[key] = psk
		return nil
	})
	if err != nil {
		return "", err
	}
	return psk, nil
}

// repairAddressesLocked reallocates addresses that are missing, duplicated or
// outside the mesh CIDR.
func (s *Store) repairAddressesLocked() (bool, error) {
	pool, err := ipam.New(s.st.Settings.MeshCIDR)
	if err != nil {
		return false, err
	}
	seen := map[netip.Addr]bool{pool.HubAddress(): true}
	changed := false
	for _, a := range s.st.Agents {
		addr, err := netip.ParseAddr(a.Address)
		if err == nil && pool.Contains(addr) && !seen[addr] {
			seen[addr] = true
			continue
		}
		addr, err = pool.Allocate(seen)
		if err != nil {
			return changed, err
		}
		a.Address = addr.String()
		seen[addr] = true
		changed = true
	}
	return changed, nil
}

// NormalisePrefixes validates and canonicalises a list of CIDRs.
func NormalisePrefixes(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return nil, fmt.Errorf("%q is not a CIDR or address", raw)
			}
			prefix = netip.PrefixFrom(addr, 32)
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%s: only IPv4 routes are supported", prefix)
		}
		s := prefix.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}
