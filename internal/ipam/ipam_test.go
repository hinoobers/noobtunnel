package ipam

import (
	"net/netip"
	"testing"
)

func TestNewRejectsBadCIDR(t *testing.T) {
	for _, cidr := range []string{"", "10.77.0.0", "not-a-cidr", "fd00::/64", "10.77.0.0/31"} {
		if _, err := New(cidr); err == nil {
			t.Fatalf("New(%q) should have failed", cidr)
		}
	}
}

func TestHubAndAllocation(t *testing.T) {
	pool, err := New("10.77.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	hub := pool.HubAddress()
	if hub.String() != "10.77.0.1" {
		t.Fatalf("hub address = %s, want 10.77.0.1", hub)
	}
	taken := map[netip.Addr]bool{hub: true}
	first, err := pool.Allocate(taken)
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "10.77.0.2" {
		t.Fatalf("first agent address = %s, want 10.77.0.2", first)
	}
	taken[first] = true
	second, err := pool.Allocate(taken)
	if err != nil {
		t.Fatal(err)
	}
	if second.String() != "10.77.0.3" {
		t.Fatalf("second agent address = %s, want 10.77.0.3", second)
	}
	if !pool.Contains(second) {
		t.Fatalf("%s should be inside the pool", second)
	}
}

func TestAllocateSkipsTakenAndExhausts(t *testing.T) {
	pool, err := New("10.9.9.0/29") // network, hub, then 4 usable addresses
	if err != nil {
		t.Fatal(err)
	}
	if got := pool.Broadcast().String(); got != "10.9.9.7" {
		t.Fatalf("broadcast = %s, want 10.9.9.7", got)
	}
	taken := map[netip.Addr]bool{}
	var got []string
	for i := 0; i < 5; i++ {
		addr, err := pool.Allocate(taken)
		if err != nil {
			t.Fatalf("allocation %d failed: %v", i, err)
		}
		taken[addr] = true
		got = append(got, addr.String())
	}
	want := []string{"10.9.9.2", "10.9.9.3", "10.9.9.4", "10.9.9.5", "10.9.9.6"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("allocation %d = %s, want %s", i, got[i], want[i])
		}
	}
	if _, err := pool.Allocate(taken); err == nil {
		t.Fatal("expected the pool to be exhausted")
	}
	// The broadcast address must never be handed out.
	for _, addr := range got {
		if addr == pool.Broadcast().String() {
			t.Fatalf("%s is the broadcast address", addr)
		}
	}
}

func TestCapacityAndPrivate(t *testing.T) {
	pool, _ := New("10.77.0.0/16")
	if got := pool.Capacity(); got != 65533 {
		t.Fatalf("capacity = %d, want 65533", got)
	}
	small, _ := New("192.168.99.0/24")
	if got := small.Capacity(); got != 253 {
		t.Fatalf("capacity = %d, want 253", got)
	}
	if !IsPrivate(netip.MustParsePrefix("10.77.0.0/16")) {
		t.Fatal("10.77.0.0/16 should be private")
	}
	if IsPrivate(netip.MustParsePrefix("8.8.8.0/24")) {
		t.Fatal("8.8.8.0/24 should not be private")
	}
}
