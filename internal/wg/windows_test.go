//go:build windows

package wg

import (
	"context"
	"strings"
	"testing"
)

func TestWindowsIPCUsesUAPIKeysAndRoutes(t *testing.T) {
	self, _ := GenerateKeyPair()
	peer, _ := GenerateKeyPair()
	cfg := Config{Interface: InterfaceConfig{PrivateKey: self.Private, Addresses: []string{"10.77.0.2/32"}, ListenPort: 51820}, Peers: []PeerConfig{{PublicKey: peer.Public, AllowedIPs: []string{"10.77.0.1/32"}, Endpoint: "example.com:51820", PersistentKeepalive: 25}}}
	ipc, err := windowsIPC(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=", "listen_port=51820", "replace_peers=true", "public_key=", "allowed_ip=10.77.0.1/32", "endpoint=example.com:51820", "persistent_keepalive_interval=25"} {
		if !strings.Contains(ipc, want) {
			t.Fatalf("missing %q in UAPI config", want)
		}
	}
	if strings.Contains(ipc, "10.77.0.2/32") {
		t.Fatal("interface address must be configured through Windows networking, not WireGuard UAPI")
	}
}

func TestResolveWindowsEndpointToNumericAddress(t *testing.T) {
	got, err := resolveWindowsEndpoint(context.Background(), "localhost:51820")
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:51820" {
		t.Fatalf("got %q, want IPv4 endpoint", got)
	}
	got, err = resolveWindowsEndpoint(context.Background(), "89.144.8.232:51820")
	if err != nil || got != "89.144.8.232:51820" {
		t.Fatalf("numeric endpoint changed: %q, %v", got, err)
	}
}
