//go:build windows

package agent

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// syncWindowsCarriedForwarding enables forwarding only on the tunnel and the
// interfaces Windows would use to reach the networks this agent carries.
func (a *Agent) syncWindowsCarriedForwarding(ctx context.Context) {
	if !a.opts.SetupSystem {
		return
	}
	carry := a.carriedPrefixes()
	key := strings.Join(carry, ",")
	if key == a.forwardedFor {
		return
	}
	if len(carry) == 0 {
		a.forwardedFor = ""
		return
	}
	iface := a.opts.Interface
	if iface == "" {
		iface = "noobtun"
	}
	quotedTargets := make([]string, 0, len(carry))
	for _, raw := range carry {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() {
			return
		}
		quotedTargets = append(quotedTargets, "'"+prefix.Masked().Addr().String()+"'")
	}
	iface = strings.ReplaceAll(iface, "'", "''")
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$mesh = Get-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction Stop
if ($mesh.Forwarding -ne 'Enabled') { $mesh | Set-NetIPInterface -Forwarding Enabled -ErrorAction Stop }
foreach ($target in @(%s)) {
  $egress = Find-NetRoute -RemoteIPAddress $target -ErrorAction Stop | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } | Select-Object -First 1
  if (-not $egress) { throw "No route to advertised network $target" }
  if ($egress.InterfaceIndex -eq $mesh.InterfaceIndex) { throw "Advertised network $target routes back into the mesh" }
  $networkInterface = Get-NetIPInterface -InterfaceIndex $egress.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
  if ($networkInterface.Forwarding -ne 'Enabled') { $networkInterface | Set-NetIPInterface -Forwarding Enabled -ErrorAction Stop }
}`, iface, strings.Join(quotedTargets, ","))
	if _, err := a.host().Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script); err != nil {
		a.setLastError("Windows network forwarding: " + err.Error())
		a.log.Warn("could not enable Windows network forwarding", "error", err)
		return
	}
	a.forwardedFor = key
	a.log.Info("Windows network forwarding enabled", "networks", key)
}
