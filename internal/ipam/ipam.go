// Package ipam allocates overlay addresses for mesh members.
package ipam

import (
	"fmt"
	"net/netip"
)

// Pool hands out addresses from the mesh CIDR.
type Pool struct {
	prefix netip.Prefix
}

// New validates a mesh CIDR and returns a pool for it.
func New(cidr string) (*Pool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("ipam: %q is not a valid CIDR: %w", cidr, err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("ipam: only IPv4 overlays are supported, got %s", cidr)
	}
	if prefix.Bits() > 30 {
		return nil, fmt.Errorf("ipam: %s leaves no usable addresses", cidr)
	}
	return &Pool{prefix: prefix}, nil
}

// Prefix returns the masked mesh prefix.
func (p *Pool) Prefix() netip.Prefix { return p.prefix }

// String returns the mesh CIDR.
func (p *Pool) String() string { return p.prefix.String() }

// Contains reports whether addr belongs to the mesh.
func (p *Pool) Contains(addr netip.Addr) bool { return p.prefix.Contains(addr) }

// HubAddress is the address reserved for the control node itself.
func (p *Pool) HubAddress() netip.Addr { return p.prefix.Addr().Next() }

// Capacity is the number of assignable agent addresses.
func (p *Pool) Capacity() int {
	bits := 32 - p.prefix.Bits()
	if bits >= 31 {
		return 1<<31 - 1
	}
	return 1<<bits - 3 // network, broadcast and the hub
}

// Allocate returns the lowest free address that is not in taken, reserving the
// network address, the broadcast address and the hub address.
func (p *Pool) Allocate(taken map[netip.Addr]bool) (netip.Addr, error) {
	addr := p.HubAddress().Next()
	last := p.lastUsable()
	for p.prefix.Contains(addr) && addr.Compare(last) <= 0 {
		if !taken[addr] {
			return addr, nil
		}
		addr = addr.Next()
	}
	return netip.Addr{}, fmt.Errorf("ipam: no free addresses left in %s", p.prefix)
}

// lastUsable returns the last usable host address in the prefix, i.e. the
// broadcast address minus one.
func (p *Pool) lastUsable() netip.Addr {
	base := p.prefix.Addr().As4()
	bits := p.prefix.Bits()
	mask := ^uint32(0)
	if bits > 0 {
		mask = ^(uint32(1<<(32-bits)) - 1)
	}
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	// (v & mask) | ^mask is the broadcast address; step back one for the last host.
	v = ((v & mask) | (^mask)) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Broadcast returns the broadcast address of the pool.
func (p *Pool) Broadcast() netip.Addr {
	base := p.prefix.Addr().As4()
	bits := p.prefix.Bits()
	mask := ^uint32(0)
	if bits > 0 {
		mask = ^(uint32(1<<(32-bits)) - 1)
	}
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v = (v & mask) | (^mask)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// IsPrivate reports whether the prefix is inside one of the RFC1918 ranges.
// Mesh overlays should stay in private space so they never collide with the
// public internet.
func IsPrivate(prefix netip.Prefix) bool {
	addr := prefix.Masked().Addr()
	switch {
	case netip.MustParsePrefix("10.0.0.0/8").Contains(addr):
		return true
	case netip.MustParsePrefix("172.16.0.0/12").Contains(addr):
		return true
	case netip.MustParsePrefix("192.168.0.0/16").Contains(addr):
		return true
	case netip.MustParsePrefix("100.64.0.0/10").Contains(addr):
		return true
	default:
		return false
	}
}

// AddressString formats an address with a /32 suffix.
func AddressString(addr netip.Addr) string {
	return netip.PrefixFrom(addr, 32).String()
}
