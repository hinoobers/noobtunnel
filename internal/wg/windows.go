//go:build windows

package wg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// WindowsBackend runs WireGuard in this process over the signed Wintun driver.
// It needs only wintun.dll beside noobtunnel.exe, not the WireGuard desktop app.
type WindowsBackend struct {
	Runner    Runner
	mu        sync.Mutex
	dev       *device.Device
	iface     string
	addresses []string
	routes    []string
	mtu       int
}

func (b *WindowsBackend) Name() string { return "windows" }

func (b *WindowsBackend) runner() Runner {
	if b.Runner != nil {
		return b.Runner
	}
	return ExecRunner{}
}

func (b *WindowsBackend) Sync(ctx context.Context, iface string, cfg Config) error {
	if err := ValidateInterfaceName(iface); err != nil {
		return err
	}
	// WireGuard's Windows bind uses AI_NUMERICHOST when parsing endpoints.
	// Resolve hostnames before creating the adapter so DNS still uses the
	// machine's ordinary network route.
	cfg.Peers = append([]PeerConfig(nil), cfg.Peers...)
	for i := range cfg.Peers {
		if cfg.Peers[i].Endpoint == "" {
			continue
		}
		endpoint, err := resolveWindowsEndpoint(ctx, cfg.Peers[i].Endpoint)
		if err != nil {
			return fmt.Errorf("resolve WireGuard endpoint %s: %w", cfg.Peers[i].Endpoint, err)
		}
		cfg.Peers[i].Endpoint = endpoint
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil {
		mtu := cfg.Interface.MTU
		if mtu == 0 {
			mtu = DefaultMTU
		}
		adapter, err := tun.CreateTUN(iface, mtu)
		if err != nil {
			return fmt.Errorf("create Wintun adapter: %w (is wintun.dll beside noobtunnel.exe, and is this process elevated?)", err)
		}
		b.dev = device.NewDevice(adapter, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "noobtunnel: "))
		b.iface = iface
		b.mtu = mtu
	}
	if b.iface != iface {
		return fmt.Errorf("windows backend already uses %s", b.iface)
	}
	ipc, err := windowsIPC(cfg)
	if err != nil {
		return err
	}
	if err := b.dev.IpcSet(ipc); err != nil {
		return fmt.Errorf("configure WireGuard: %w", err)
	}
	if err := b.dev.Up(); err != nil {
		return fmt.Errorf("start WireGuard: %w", err)
	}
	if err := b.syncAddresses(ctx, iface, cfg.Interface.Addresses); err != nil {
		return err
	}
	if err := b.syncRoutes(ctx, iface, cfg.Routes); err != nil {
		return err
	}
	if err := b.ensureFirewall(ctx, iface); err != nil {
		return err
	}
	return nil
}

func resolveWindowsEndpoint(ctx context.Context, endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if address.Is4() {
			return net.JoinHostPort(address.String(), port), nil
		}
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("no IP address for %s", host)
	}
	return net.JoinHostPort(addresses[0].String(), port), nil
}

func (b *WindowsBackend) ensureFirewall(ctx context.Context, iface string) error {
	// Windows stores InterfaceAlias as the adapter GUID. Wintun can assign a new
	// GUID after an agent restart, so an existing rule must be rebound too.
	script := fmt.Sprintf("if (Get-NetFirewallRule -Name 'noobtunnel-mesh' -ErrorAction SilentlyContinue) { Set-NetFirewallRule -Name 'noobtunnel-mesh' -InterfaceAlias '%s' -Enabled True | Out-Null } else { New-NetFirewallRule -Name 'noobtunnel-mesh' -DisplayName 'noobtunnel mesh' -Direction Inbound -Action Allow -InterfaceAlias '%s' | Out-Null }", iface, iface)
	if err := b.ps(ctx, script); err != nil {
		return fmt.Errorf("allow mesh traffic in Windows Firewall: %w", err)
	}
	return nil
}

func windowsIPC(cfg Config) (string, error) {
	key, err := keyHex(cfg.Interface.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	var out strings.Builder
	fmt.Fprintf(&out, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", key, cfg.Interface.ListenPort)
	for _, peer := range cfg.Peers {
		key, err := keyHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer public key: %w", err)
		}
		fmt.Fprintf(&out, "public_key=%s\nreplace_allowed_ips=true\n", key)
		if peer.PresharedKey != "" {
			psk, err := keyHex(peer.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("peer preshared key: %w", err)
			}
			fmt.Fprintf(&out, "preshared_key=%s\n", psk)
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(&out, "endpoint=%s\n", peer.Endpoint)
		}
		for _, ip := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(ip); err != nil {
				return "", err
			}
			fmt.Fprintf(&out, "allowed_ip=%s\n", ip)
		}
		fmt.Fprintf(&out, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
	}
	return out.String(), nil
}

func keyHex(key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid WireGuard key")
	}
	return hex.EncodeToString(raw), nil
}

func hexKey(key string) string {
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func (b *WindowsBackend) ps(ctx context.Context, script string) error {
	_, err := b.runner().Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+script)
	return err
}

func (b *WindowsBackend) syncAddresses(ctx context.Context, iface string, desired []string) error {
	want := make(map[string]bool, len(desired))
	for _, addr := range desired {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("invalid Windows tunnel address %q", addr)
		}
		want[addr] = true
		if !contains(b.addresses, addr) {
			script := fmt.Sprintf("$i=Get-NetAdapter -Name '%s'; if (-not (Get-NetIPAddress -InterfaceIndex $i.ifIndex -IPAddress '%s' -ErrorAction SilentlyContinue)) { New-NetIPAddress -InterfaceIndex $i.ifIndex -IPAddress '%s' -PrefixLength %d -PolicyStore ActiveStore | Out-Null }", iface, prefix.Addr(), prefix.Addr(), prefix.Bits())
			if err := b.ps(ctx, script); err != nil {
				return fmt.Errorf("assign tunnel address %s: %w", addr, err)
			}
		}
	}
	for _, old := range b.addresses {
		if want[old] {
			continue
		}
		prefix, _ := netip.ParsePrefix(old)
		script := fmt.Sprintf("$i=Get-NetAdapter -Name '%s'; Remove-NetIPAddress -InterfaceIndex $i.ifIndex -IPAddress '%s' -Confirm:$false", iface, prefix.Addr())
		if err := b.ps(ctx, script); err != nil {
			return fmt.Errorf("remove old tunnel address %s: %w", old, err)
		}
	}
	b.addresses = append([]string(nil), desired...)
	return nil
}

func (b *WindowsBackend) syncRoutes(ctx context.Context, iface string, desired []string) error {
	want := make(map[string]bool, len(desired))
	for _, route := range desired {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("invalid Windows mesh route %q", route)
		}
		want[route] = true
		if contains(b.routes, route) {
			continue
		}
		script := fmt.Sprintf("$i=Get-NetAdapter -Name '%s'; if (-not (Get-NetRoute -DestinationPrefix '%s' -InterfaceIndex $i.ifIndex -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '%s' -InterfaceIndex $i.ifIndex -NextHop '0.0.0.0' -RouteMetric 1000 -PolicyStore ActiveStore | Out-Null }", iface, route, route)
		if err := b.ps(ctx, script); err != nil {
			return fmt.Errorf("add mesh route %s: %w", route, err)
		}
	}
	for _, old := range b.routes {
		if want[old] {
			continue
		}
		script := fmt.Sprintf("$i=Get-NetAdapter -Name '%s'; Remove-NetRoute -DestinationPrefix '%s' -InterfaceIndex $i.ifIndex -NextHop '0.0.0.0' -Confirm:$false", iface, old)
		if err := b.ps(ctx, script); err != nil {
			return fmt.Errorf("remove old mesh route %s: %w", old, err)
		}
	}
	b.routes = append([]string(nil), desired...)
	return nil
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func (b *WindowsBackend) EnsureRoutes(ctx context.Context, iface string, routes []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// A Windows route can disappear when the network stack reconfigures. Read it
	// back and recreate it without interrupting the tunnel.
	for _, route := range routes {
		if _, err := netip.ParsePrefix(route); err != nil {
			return err
		}
		script := fmt.Sprintf("$i=Get-NetAdapter -Name '%s'; if (-not (Get-NetRoute -DestinationPrefix '%s' -InterfaceIndex $i.ifIndex -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '%s' -InterfaceIndex $i.ifIndex -NextHop '0.0.0.0' -RouteMetric 1000 -PolicyStore ActiveStore | Out-Null }", iface, route, route)
		if err := b.ps(ctx, script); err != nil {
			return err
		}
	}
	return nil
}

func (b *WindowsBackend) Status(_ context.Context, iface string) (InterfaceStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil || b.iface != iface {
		return InterfaceStatus{}, ErrNoInterface
	}
	raw, err := b.dev.IpcGet()
	if err != nil {
		return InterfaceStatus{}, err
	}
	status := InterfaceStatus{Name: iface, Exists: true, Addresses: append([]string(nil), b.addresses...), MTU: b.mtu}
	var peer *PeerStatus
	flush := func() {
		if peer != nil {
			status.Peers = append(status.Peers, *peer)
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "private_key":
			if priv := hexKey(value); priv != "" {
				status.PublicKey, _ = PublicFromPrivate(priv)
			}
		case "listen_port":
			status.ListenPort, _ = strconv.Atoi(value)
		case "public_key":
			flush()
			peer = &PeerStatus{PublicKey: hexKey(value)}
		case "endpoint":
			if peer != nil {
				peer.Endpoint = value
			}
		case "allowed_ip":
			if peer != nil {
				peer.AllowedIPs = append(peer.AllowedIPs, value)
			}
		case "last_handshake_time_sec":
			if peer != nil {
				sec, _ := strconv.ParseInt(value, 10, 64)
				if sec > 0 {
					peer.LatestHandshake = time.Unix(sec, 0)
				}
			}
		case "rx_bytes":
			if peer != nil {
				peer.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "tx_bytes":
			if peer != nil {
				peer.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "persistent_keepalive_interval":
			if peer != nil {
				peer.PersistentKeepalive, _ = strconv.Atoi(value)
			}
		case "preshared_key":
			if peer != nil {
				peer.HasPresharedKey = value != strings.Repeat("0", 64)
			}
		}
	}
	flush()
	return status, nil
}

func (b *WindowsBackend) Down(_ context.Context, iface string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev != nil && b.iface == iface {
		b.dev.Close()
		b.dev = nil
		b.iface = ""
		b.addresses = nil
		b.routes = nil
	}
	return nil
}
