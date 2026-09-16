package store

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// ControlExitNodeID identifies the built-in exit node: the control node itself.
// It always exists and cannot be removed.
const ControlExitNodeID = "control"

// ExitNodeKind describes how an extra public address reaches this host.
type ExitNodeKind string

const (
	// ExitNodeControl is the control node's own address.
	ExitNodeControl ExitNodeKind = "control"
	// ExitNodeAddress is an address already present on this host, for example a
	// second public IP assigned to the VPS.
	ExitNodeAddress ExitNodeKind = "address"
	// ExitNodeGRE is an address carried over a GRE tunnel from another host.
	ExitNodeGRE ExitNodeKind = "gre"
)

// ValidExitNodeKind reports whether k is supported.
func ValidExitNodeKind(k ExitNodeKind) bool {
	switch k {
	case ExitNodeControl, ExitNodeAddress, ExitNodeGRE:
		return true
	default:
		return false
	}
}

// ExitNode is a public address that resources can be published on.
type ExitNode struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Kind    ExitNodeKind `json:"kind"`
	Address string       `json:"address,omitempty"`
	Enabled bool         `json:"enabled"`
	// Interface is where the address lives, for example "lo" for a secondary
	// address.
	Interface string `json:"interface,omitempty"`

	// GRE tunnel settings.
	LocalEndpoint   string `json:"localEndpoint,omitempty"`
	PeerEndpoint    string `json:"peerEndpoint,omitempty"`
	LocalTunnelAddr string `json:"localTunnelAddress,omitempty"`
	PeerTunnelAddr  string `json:"peerTunnelAddress,omitempty"`
	TunnelInterface string `json:"tunnelInterface,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
}

// Deletable reports whether the node may be removed.
func (n ExitNode) Deletable() bool { return n.Kind != ExitNodeControl }

// BindAddress is the address resources on this node listen on. An empty string
// means every local address, which is what the control node itself uses.
func (n ExitNode) BindAddress() string {
	if n.Kind == ExitNodeControl {
		return ""
	}
	return n.Address
}

// ExitNodeInput is a caller supplied exit node description.
type ExitNodeInput struct {
	Name            string
	Kind            string
	Address         string
	Interface       string
	LocalEndpoint   string
	PeerEndpoint    string
	LocalTunnelAddr string
	PeerTunnelAddr  string
	TunnelInterface string
	Enabled         *bool
}

var (
	// ErrControlExitNode means the built-in node cannot be changed or removed.
	ErrControlExitNode = errors.New("store: the control node exit node cannot be removed")
	// ErrExitNodeInUse means resources still use the node.
	ErrExitNodeInUse = errors.New("store: that exit node is still used by a resource")
)

// ExitNodes lists every exit node, the built-in one first.
func (s *Store) ExitNodes() []ExitNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]ExitNode(nil), s.st.ExitNodes...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == ExitNodeControl
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// ExitNode returns one exit node. The empty id and "control" select the built-in
// node.
func (s *Store) ExitNode(id string) (ExitNode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := findExitNode(s.st, id)
	if !ok {
		return ExitNode{}, ErrNotFound
	}
	return node, nil
}

func findExitNode(st *State, id string) (ExitNode, bool) {
	if id == "" || id == ControlExitNodeID {
		for _, node := range st.ExitNodes {
			if node.Kind == ExitNodeControl {
				return node, true
			}
		}
		return ExitNode{}, false
	}
	for _, node := range st.ExitNodes {
		if node.ID == id {
			return node, true
		}
	}
	return ExitNode{}, false
}

// AddExitNode registers an additional public address.
func (s *Store) AddExitNode(in ExitNodeInput) (ExitNode, error) {
	var created ExitNode
	err := s.Update(func(st *State) error {
		node, err := buildExitNode(in)
		if err != nil {
			return err
		}
		fillExitNodeDefaults(st, &node, "")
		if err := checkExitNodeClashes(st, node, ""); err != nil {
			return err
		}
		id, err := randomToken(6)
		if err != nil {
			return err
		}
		node.ID = id
		node.CreatedAt = time.Now().UTC()
		st.ExitNodes = append(st.ExitNodes, node)
		created = node
		return nil
	})
	return created, err
}

// UpdateExitNode changes an exit node.
func (s *Store) UpdateExitNode(id string, in ExitNodeInput) (ExitNode, error) {
	var updated ExitNode
	err := s.Update(func(st *State) error {
		index := -1
		for i := range st.ExitNodes {
			if st.ExitNodes[i].ID == id {
				index = i
				break
			}
		}
		if index < 0 {
			return ErrNotFound
		}
		if st.ExitNodes[index].Kind == ExitNodeControl {
			// The built-in node cannot be renamed or moved, but it can be
			// switched off so resources have to live on real exit nodes.
			if in.Enabled == nil {
				return ErrControlExitNode
			}
			name := strings.TrimSpace(in.Name)
			if name != "" && !strings.EqualFold(name, st.ExitNodes[index].Name) {
				return ErrControlExitNode
			}
			if strings.TrimSpace(in.Address) != "" {
				return ErrControlExitNode
			}
			control := st.ExitNodes[index]
			control.Enabled = *in.Enabled
			st.ExitNodes[index] = control
			updated = control
			return nil
		}
		node, err := buildExitNode(in)
		if err != nil {
			return err
		}
		node.ID = id
		node.CreatedAt = st.ExitNodes[index].CreatedAt
		fillExitNodeDefaults(st, &node, id)
		if err := checkExitNodeClashes(st, node, id); err != nil {
			return err
		}
		st.ExitNodes[index] = node
		updated = node
		return nil
	})
	return updated, err
}

// checkExitNodeClashes rejects duplicate names and addresses.
func checkExitNodeClashes(st *State, node ExitNode, ignoreID string) error {
	for _, existing := range st.ExitNodes {
		if existing.ID == ignoreID {
			continue
		}
		if node.Address != "" && existing.Address == node.Address {
			return fmt.Errorf("%w: %s is already an exit node", ErrBadResource, node.Address)
		}
		if strings.EqualFold(existing.Name, node.Name) {
			return fmt.Errorf("%w: an exit node called %q already exists", ErrBadResource, node.Name)
		}
	}
	return nil
}

// RemoveExitNode deletes an exit node that nothing uses.
func (s *Store) RemoveExitNode(id string) error {
	return s.Update(func(st *State) error {
		node, ok := findExitNode(st, id)
		if !ok {
			return ErrNotFound
		}
		if !node.Deletable() {
			return ErrControlExitNode
		}
		for _, r := range st.Resources {
			if r.ExitNodeID == node.ID {
				return fmt.Errorf("%w: %s is published on it", ErrExitNodeInUse, r.Name)
			}
		}
		out := st.ExitNodes[:0]
		for _, existing := range st.ExitNodes {
			if existing.ID == node.ID {
				continue
			}
			out = append(out, existing)
		}
		st.ExitNodes = out
		return nil
	})
}

// buildExitNode validates an exit node description.
func buildExitNode(in ExitNodeInput) (ExitNode, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return ExitNode{}, fmt.Errorf("%w: an exit node needs a name", ErrBadResource)
	}
	kind := ExitNodeKind(strings.ToLower(strings.TrimSpace(in.Kind)))
	if kind == "" {
		kind = ExitNodeAddress
	}
	if kind == ExitNodeControl {
		return ExitNode{}, fmt.Errorf("%w: the control node exit node is created automatically", ErrBadResource)
	}
	if !ValidExitNodeKind(kind) {
		return ExitNode{}, fmt.Errorf("%w: the kind must be address or gre", ErrBadResource)
	}
	node := ExitNode{Name: name, Kind: kind, Enabled: true}
	if in.Enabled != nil {
		node.Enabled = *in.Enabled
	}
	address, err := parseIPv4(in.Address, "an address")
	if err != nil {
		return ExitNode{}, err
	}
	node.Address = address
	node.Interface = strings.TrimSpace(in.Interface)

	if kind == ExitNodeGRE {
		if node.LocalEndpoint, err = parseIPv4(in.LocalEndpoint, "the local endpoint"); err != nil {
			return ExitNode{}, err
		}
		if node.PeerEndpoint, err = parseIPv4(in.PeerEndpoint, "the peer endpoint"); err != nil {
			return ExitNode{}, err
		}
		if node.LocalEndpoint == node.PeerEndpoint {
			return ExitNode{}, fmt.Errorf("%w: the tunnel endpoints must differ", ErrBadResource)
		}
		node.TunnelInterface = strings.TrimSpace(in.TunnelInterface)
		// The tunnel addresses are an implementation detail: they are allocated
		// automatically from an internal range unless the operator set them.
		if strings.TrimSpace(in.LocalTunnelAddr) != "" {
			if node.LocalTunnelAddr, err = parseIPv4(in.LocalTunnelAddr, "the local tunnel address"); err != nil {
				return ExitNode{}, err
			}
		}
		if strings.TrimSpace(in.PeerTunnelAddr) != "" {
			if node.PeerTunnelAddr, err = parseIPv4(in.PeerTunnelAddr, "the peer tunnel address"); err != nil {
				return ExitNode{}, err
			}
		}
		if node.LocalTunnelAddr != "" && node.LocalTunnelAddr == node.PeerTunnelAddr {
			return ExitNode{}, fmt.Errorf("%w: the tunnel addresses must differ", ErrBadResource)
		}
	} else if node.Interface == "" {
		node.Interface = "lo"
	}
	return node, nil
}

// fillExitNodeDefaults allocates the values the operator should not have to think
// about: a tunnel interface name and a pair of tunnel addresses per GRE node.
func fillExitNodeDefaults(st *State, node *ExitNode, ignoreID string) {
	if node.Kind != ExitNodeGRE {
		return
	}
	used := 0
	for _, existing := range st.ExitNodes {
		if existing.Kind != ExitNodeGRE || existing.ID == ignoreID {
			continue
		}
		used++
	}
	if strings.TrimSpace(node.TunnelInterface) == "" {
		node.TunnelInterface = fmt.Sprintf("ntgre%d", used)
	}
	// Tunnel addresses come from 10.99.0.0/16, one /30 per node.
	base := 10*1<<24 + 99<<16
	if strings.TrimSpace(node.LocalTunnelAddr) == "" {
		value := uint32(base) + uint32(used)*4 + 1
		node.LocalTunnelAddr = netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}).String()
	}
	if strings.TrimSpace(node.PeerTunnelAddr) == "" {
		value := uint32(base) + uint32(used)*4 + 2
		node.PeerTunnelAddr = netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}).String()
	}
}

// parseIPv4 validates a single IPv4 address.
func parseIPv4(raw, what string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: %s is required", ErrBadResource, what)
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		raw = prefix.Addr().String()
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("%w: %q is not an IPv4 address", ErrBadResource, raw)
	}
	if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return "", fmt.Errorf("%w: %s cannot be %s", ErrBadResource, what, addr)
	}
	return addr.String(), nil
}

// ensureControlExitNodeLocked guarantees the built-in exit node exists.
func (s *Store) ensureControlExitNodeLocked() (bool, error) {
	for _, node := range s.st.ExitNodes {
		if node.Kind == ExitNodeControl {
			return false, nil
		}
	}
	s.st.ExitNodes = append([]ExitNode{{
		ID:        ControlExitNodeID,
		Name:      "Control node",
		Kind:      ExitNodeControl,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}}, s.st.ExitNodes...)
	return true, nil
}
