package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RuntimeState is the agent's own last known state, written next to the
// identity file so `noobtunnel status` works without talking to the control
// node.
type RuntimeState struct {
	Address     string    `json:"address,omitempty"`
	MeshCIDR    string    `json:"meshCidr,omitempty"`
	Interface   string    `json:"interface,omitempty"`
	HubEndpoint string    `json:"hubEndpoint,omitempty"`
	ControlNode string    `json:"controlNode,omitempty"`
	AgentName   string    `json:"agentName,omitempty"`
	AgentID     uint32    `json:"agentId,omitempty"`
	Connected   bool      `json:"connected"`
	Peers       []PeerRow `json:"peers,omitempty"`
	Routes      []string  `json:"routes,omitempty"`
	MTU         int       `json:"mtu,omitempty"`
	Backend     string    `json:"backend,omitempty"`
	LastError   string    `json:"lastError,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// PeerRow is one mesh peer as this agent sees it.
type PeerRow struct {
	ID        uint32    `json:"id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	Mode      string    `json:"mode"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Handshake time.Time `json:"handshake,omitempty"`
	RxBytes   uint64    `json:"rxBytes,omitempty"`
	TxBytes   uint64    `json:"txBytes,omitempty"`
}

// RuntimePath is where the agent keeps its runtime state.
func RuntimePath(stateDir string) string { return filepath.Join(stateDir, "runtime.json") }

// LoadRuntime reads the agent's runtime state.
func LoadRuntime(stateDir string) (*RuntimeState, error) {
	raw, err := os.ReadFile(RuntimePath(stateDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("agent: no runtime state in %s, is the agent installed here?", stateDir)
		}
		return nil, err
	}
	st := &RuntimeState{}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, err
	}
	return st, nil
}

func writeRuntime(stateDir string, st *RuntimeState) error {
	if stateDir == "" {
		return nil
	}
	st.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := RuntimePath(stateDir)
	tmp := path + ".tmp"
	// World readable on purpose: this file holds the mesh address, peers and
	// counters, not secrets, and `noobtunnel status` should work without sudo.
	// The machine's private key stays in identity.json, root only.
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Describe renders the runtime state for the console.
func (r *RuntimeState) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "control node   %s\n", orDash(r.ControlNode))
	fmt.Fprintf(&b, "agent          %s (id %d)\n", orDash(r.AgentName), r.AgentID)
	fmt.Fprintf(&b, "mesh address   %s\n", orDash(r.Address))
	fmt.Fprintf(&b, "interface      %s (mtu %d, backend %s)\n", orDash(r.Interface), r.MTU, orDash(r.Backend))
	fmt.Fprintf(&b, "hub endpoint   %s\n", orDash(r.HubEndpoint))
	fmt.Fprintf(&b, "control state  %s\n", map[bool]string{true: "connected", false: "disconnected"}[r.Connected])
	fmt.Fprintf(&b, "updated        %s\n", r.UpdatedAt.Local().Format(time.RFC3339))
	if r.LastError != "" {
		fmt.Fprintf(&b, "last error     %s\n", r.LastError)
	}
	if len(r.Routes) > 0 {
		fmt.Fprintf(&b, "routes         %s\n", strings.Join(r.Routes, ", "))
	}
	if len(r.Peers) == 0 {
		b.WriteString("peers          none yet\n")
		return b.String()
	}
	b.WriteString("\npeers\n")
	b.WriteString("  id   name                 address        mode     handshake\n")
	peers := append([]PeerRow(nil), r.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Address < peers[j].Address })
	for _, p := range peers {
		handshake := "never"
		if !p.Handshake.IsZero() {
			handshake = time.Since(p.Handshake).Round(time.Second).String() + " ago"
		}
		fmt.Fprintf(&b, "  %-4d %-20s %-14s %-8s %s\n", p.ID, truncate(p.Name, 20), p.Address, p.Mode, handshake)
	}
	return b.String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
