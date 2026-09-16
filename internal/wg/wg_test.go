package wg

import (
	"strings"
	"testing"
	"time"
)

func TestKeyPairRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidKey(kp.Private) || !ValidKey(kp.Public) {
		t.Fatalf("generated keys are not valid: %q %q", kp.Private, kp.Public)
	}
	if kp.Private == kp.Public {
		t.Fatal("private and public keys must differ")
	}
	derived, err := PublicFromPrivate(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if derived != kp.Public {
		t.Fatalf("derived public key %s != %s", derived, kp.Public)
	}
	if ValidKey("not-a-key") {
		t.Fatal("junk should not validate as a key")
	}
}

func TestClampingMatchesWireGuardConvention(t *testing.T) {
	priv, err := DecodeKey("uJ9k1c8Z2p7K3sV6Y1nQ4rT5wX8aB0cD2eF4gH6iJ8=")
	if err != nil {
		// Not a fixed vector, just ensure round tripping works with clamping.
		kp, genErr := GenerateKeyPair()
		if genErr != nil {
			t.Fatal(genErr)
		}
		priv, err = DecodeKey(kp.Private)
		if err != nil {
			t.Fatal(err)
		}
	}
	clamped := clamp(priv)
	if clamped[0]&7 != 0 {
		t.Fatalf("low bits not cleared: %d", clamped[0])
	}
	if clamped[31]&128 != 0 || clamped[31]&64 == 0 {
		t.Fatalf("high bits not clamped: %d", clamped[31])
	}
}

func TestConfigRender(t *testing.T) {
	cfg := Config{
		Interface: InterfaceConfig{
			PrivateKey: "PRIV", Addresses: []string{"10.77.0.2/32"}, ListenPort: 51820, MTU: 1420,
		},
		Peers: []PeerConfig{{
			PublicKey: "PUB", PresharedKey: "PSK", Endpoint: "203.0.113.9:51820",
			AllowedIPs: []string{"10.77.0.1/32", "10.77.0.3/32"}, PersistentKeepalive: 25,
		}},
	}
	out := cfg.Render()
	for _, want := range []string{"[Interface]", "PrivateKey = PRIV", "Address = 10.77.0.2/32",
		"ListenPort = 51820", "MTU = 1420", "[Peer]", "PublicKey = PUB", "PresharedKey = PSK",
		"Endpoint = 203.0.113.9:51820", "AllowedIPs = 10.77.0.1/32, 10.77.0.3/32", "PersistentKeepalive = 25"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered config is missing %q:\n%s", want, out)
		}
	}
	redacted := cfg.Redacted()
	if strings.Contains(redacted, "PRIV") || strings.Contains(redacted, "PSK") {
		t.Fatalf("redacted config leaked secrets:\n%s", redacted)
	}
}

func TestParseDump(t *testing.T) {
	out := "privkey\tpubkey\t51820\toff\n" +
		"peerkey1\t(none)\t203.0.113.5:51820\t10.77.0.2/32,10.77.0.3/32\t1700000000\t1024\t2048\t25\n" +
		"peerkey2\tpsksomething\t(none)\t10.77.0.4/32\t0\t0\t0\toff\n"
	dump, err := ParseDump(out)
	if err != nil {
		t.Fatal(err)
	}
	if dump.ListenPort != 51820 || dump.FwMark != 0 {
		t.Fatalf("interface fields parsed wrong: %+v", dump)
	}
	if len(dump.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(dump.Peers))
	}
	first := dump.Peers[0]
	if first.Endpoint != "203.0.113.5:51820" {
		t.Fatalf("endpoint = %q", first.Endpoint)
	}
	if len(first.AllowedIPs) != 2 || first.AllowedIPs[1] != "10.77.0.3/32" {
		t.Fatalf("allowed ips = %v", first.AllowedIPs)
	}
	if first.LatestHandshake.IsZero() {
		t.Fatal("handshake should be parsed")
	}
	if first.RxBytes != 1024 || first.TxBytes != 2048 || first.PersistentKeepalive != 25 {
		t.Fatalf("counters parsed wrong: %+v", first)
	}
	second := dump.Peers[1]
	if !second.LatestHandshake.IsZero() {
		t.Fatal("a zero handshake must stay zero")
	}
	if second.PresharedKey != "psksomething" {
		t.Fatalf("preshared key = %q", second.PresharedKey)
	}
	if second.Endpoint != "" {
		t.Fatalf("(none) endpoint should be empty, got %q", second.Endpoint)
	}
	if _, err := ParseDump(""); err == nil {
		t.Fatal("empty dump should fail")
	}
}

func TestInterfaceNameValidation(t *testing.T) {
	if err := ValidateInterfaceName("noobtun"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "this-name-is-way-too-long", "bad name", "bad/name"} {
		if err := ValidateInterfaceName(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestHandshakeAge(t *testing.T) {
	now := time.Now()
	if got := (PeerStatus{}).HandshakeAge(now); got != -1 {
		t.Fatalf("age without handshake = %v, want -1", got)
	}
	peer := PeerStatus{LatestHandshake: now.Add(-90 * time.Second)}
	if got := peer.HandshakeAge(now); got != 90*time.Second {
		t.Fatalf("age = %v, want 90s", got)
	}
}
