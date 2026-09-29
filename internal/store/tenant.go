package store

import (
	"errors"
	"net/netip"
)

// TenantPrefix reserves one /24 per account inside a /16 mesh address range.
func TenantPrefix(meshCIDR string, slot uint16) (netip.Prefix, error) {
	base, err := netip.ParsePrefix(meshCIDR)
	if err != nil || !base.Addr().Is4() || base.Bits() != 16 || slot > 255 {
		return netip.Prefix{}, errors.New("private meshes require an IPv4 /16 mesh address range")
	}
	addr := base.Masked().Addr().As4()
	addr[2] = byte(slot)
	addr[3] = 0
	return netip.PrefixFrom(netip.AddrFrom4(addr), 24), nil
}
