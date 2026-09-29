//go:build windows

package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

func TestWindowsCarriedNetworkEnablesForwardingOnItsPath(t *testing.T) {
	host := &fakeHost{}
	a := testAgent(host, false)
	a.session = &sessionState{peers: map[uint32]proto.Peer{}}
	a.setCarry([]string{"192.168.44.0/24"})
	a.syncWindowsCarriedForwarding(context.Background())
	if len(host.calls) != 1 || host.calls[0][0] != "powershell.exe" {
		t.Fatalf("expected one Windows forwarding setup command, got %d", len(host.calls))
	}
	script := host.calls[0][len(host.calls[0])-1]
	for _, want := range []string{"Get-NetIPInterface -InterfaceAlias 'noobtun'", "Find-NetRoute -RemoteIPAddress $target", "'192.168.44.0'", "Set-NetIPInterface -Forwarding Enabled"} {
		if !strings.Contains(script, want) {
			t.Fatalf("Windows forwarding setup is missing %q", want)
		}
	}
	a.syncWindowsCarriedForwarding(context.Background())
	if len(host.calls) != 1 {
		t.Fatal("unchanged carried networks reconfigured Windows forwarding")
	}
}
