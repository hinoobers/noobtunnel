package wg

import (
	"context"
	"fmt"
	"time"
)

// PeerStatus is live state read back from a WireGuard device.
type PeerStatus struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          []string
	LatestHandshake     time.Time
	RxBytes             uint64
	TxBytes             uint64
	PersistentKeepalive int
	HasPresharedKey     bool
}

// HandshakeAge returns how long ago the last handshake completed, or -1 if the
// peer has never completed one.
func (p PeerStatus) HandshakeAge(now time.Time) time.Duration {
	if p.LatestHandshake.IsZero() {
		return -1
	}
	return now.Sub(p.LatestHandshake)
}

// InterfaceStatus is live state of a WireGuard interface.
type InterfaceStatus struct {
	Name       string
	Exists     bool
	PublicKey  string
	ListenPort int
	MTU        int
	Addresses  []string
	Peers      []PeerStatus
}

// PeerByKey finds a peer by public key.
func (s InterfaceStatus) PeerByKey(key string) (PeerStatus, bool) {
	for _, p := range s.Peers {
		if p.PublicKey == key {
			return p, true
		}
	}
	return PeerStatus{}, false
}

// Backend programs a WireGuard device. The real implementation shells out to
// wg(8) and ip(8); the fake implementation is used by tests and --demo mode.
type Backend interface {
	// Name identifies the backend in logs and the UI.
	Name() string
	// Sync makes the live device match cfg exactly: it creates the interface if
	// needed, applies keys and peers, assigns addresses and installs routes.
	Sync(ctx context.Context, iface string, cfg Config) error
	// EnsureRoutes re-asserts the kernel routes for an interface without touching
	// the device. It exists so a running node can repair a routing table that
	// changed underneath it, which is otherwise invisible: the tunnel still
	// handshakes while every answer goes out of the default gateway.
	EnsureRoutes(ctx context.Context, iface string, routes []string) error
	// Status reads the live device state.
	Status(ctx context.Context, iface string) (InterfaceStatus, error)
	// Down removes the interface.
	Down(ctx context.Context, iface string) error
}

// ErrNoInterface means the WireGuard device does not exist (yet).
var ErrNoInterface = fmt.Errorf("wg: interface does not exist")
