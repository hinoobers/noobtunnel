package wg

import (
	"fmt"
	"strings"
)

// MTU bounds for the WireGuard interface. 1420 leaves room for the outer IPv4
// and UDP headers inside a standard 1500 byte path MTU.
const (
	DefaultMTU = 1420
	MinMTU     = 1280
	MaxMTU     = 1500
)

// InterfaceConfig describes the [Interface] section of a WireGuard device.
type InterfaceConfig struct {
	PrivateKey string
	Addresses  []string // CIDR addresses assigned to the interface
	ListenPort int
	MTU        int
	FwMark     int
}

// PeerConfig describes one [Peer] section.
type PeerConfig struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

// Config is a complete WireGuard device description.
type Config struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
	// Routes are the kernel routes that must point at the interface. WireGuard's
	// AllowedIPs only decide which peer a packet is encrypted for; the kernel
	// routing table still has to send the packet into the interface.
	Routes []string
}

// Render produces a wg(8) / wg-quick(8) compatible configuration file.
func (c Config) Render() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.Interface.PrivateKey)
	for _, addr := range c.Interface.Addresses {
		fmt.Fprintf(&b, "Address = %s\n", addr)
	}
	if c.Interface.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.Interface.ListenPort)
	}
	if c.Interface.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.Interface.MTU)
	}
	if c.Interface.FwMark != 0 {
		fmt.Fprintf(&b, "FwMark = %#x\n", c.Interface.FwMark)
	}
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}

// Redacted renders the configuration with all key material replaced by
// placeholders, for display in the UI and in logs.
func (c Config) Redacted() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = <hidden>\n")
	for _, addr := range c.Interface.Addresses {
		fmt.Fprintf(&b, "Address = %s\n", addr)
	}
	if c.Interface.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.Interface.ListenPort)
	}
	if c.Interface.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.Interface.MTU)
	}
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			b.WriteString("PresharedKey = <hidden>\n")
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}
