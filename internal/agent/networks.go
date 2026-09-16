package agent

import (
	"net"
	"sort"
)

// advertiseList resolves what this agent offers to route. With AdvertiseAll it
// enumerates the machine's own networks, minus the ones that make no sense to
// share: loopback, link-local, and the WireGuard interface itself. The control
// node also filters anything overlapping the mesh range, so a mistake here
// cannot hijack the overlay.
func advertiseList(opts Options) []string {
	out := append([]string(nil), opts.Advertise...)
	if opts.AdvertiseAll {
		out = append(out, localNetworks(opts.Interface)...)
	}
	// Keep it tidy: de-duplicate and sort so the peer list is stable.
	seen := map[string]bool{}
	unique := make([]string, 0, len(out))
	for _, prefix := range out {
		if prefix == "" || seen[prefix] {
			continue
		}
		seen[prefix] = true
		unique = append(unique, prefix)
	}
	sort.Strings(unique)
	return unique
}

// localNetworks lists the IPv4 subnets of every usable interface.
func localNetworks(wireGuardInterface string) []string {
	var out []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range interfaces {
		if iface.Name == wireGuardInterface || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones == 0 {
				continue
			}
			out = append(out, (&net.IPNet{IP: ip4.Mask(ipNet.Mask), Mask: ipNet.Mask}).String())
		}
	}
	return out
}
