package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/proto"
)

// fakeHost records the host commands and answers the questions the firewall
// setup asks.
type fakeHost struct {
	ufw        bool
	iptables   bool
	failOn     string
	calls      [][]string
	existingIP map[string]bool
	// forwarding is what `sysctl -n net.ipv4.ip_forward` answers.
	forwarding string
	// saved is what `iptables-save -c` prints.
	saved string
}

func (f *fakeHost) LookPath(name string) (string, error) {
	switch {
	case name == "ufw" && f.ufw:
		return "ufw", nil
	case name == "iptables" && f.iptables:
		return "iptables", nil
	case name == "iptables-save" && f.iptables:
		return "iptables-save", nil
	}
	return "", errors.New("not found")
}

func (f *fakeHost) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.failOn != "" && strings.Contains(strings.Join(args, " "), f.failOn) {
		return "boom", errors.New("command failed")
	}
	if name == "ufw" && len(args) > 0 && args[0] == "status" {
		return "Status: active\n", nil
	}
	if name == "sysctl" && len(args) > 0 && args[0] == "-n" {
		if f.forwarding == "" {
			return "0\n", nil
		}
		return f.forwarding + "\n", nil
	}
	if name == "iptables-save" {
		return f.saved, nil
	}
	if name == "iptables" {
		// The table may come first ("-t mangle"), so look for the check flag.
		for i, arg := range args {
			if arg != "-C" {
				continue
			}
			if f.existingIP[strings.Join(args[i+1:], " ")] {
				return "", nil
			}
			return "no such rule", errors.New("exit status 1")
		}
		return "", nil
	}
	return "", nil
}

func (f *fakeHost) ran(parts ...string) bool {
	want := strings.Join(parts, " ")
	for _, call := range f.calls {
		if strings.Join(call, " ") == want {
			return true
		}
	}
	return false
}

func testAgent(host *fakeHost, advertiseAll bool) *Agent {
	return &Agent{
		opts:       Options{Interface: "noobtun", SetupSystem: true, AdvertiseAll: advertiseAll},
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		hostRunner: host,
	}
}

// TestMeshTrafficIsAcceptedThroughUfw covers the case behind "connect: no route
// to host" with a healthy tunnel: ufw's default deny answered every packet from
// the mesh with ICMP host-prohibited.
func TestMeshTrafficIsAcceptedThroughUfw(t *testing.T) {
	host := &fakeHost{ufw: true, existingIP: map[string]bool{}}
	testAgent(host, false).allowMeshTraffic(context.Background())

	if !host.ran("ufw", "allow", "in", "on", "noobtun") {
		t.Fatalf("the mesh interface was not allowed through ufw: %v", host.calls)
	}
	// Forwarding is opened whether or not this agent advertises anything: the
	// control node can pin a published target's address to it at any moment, and a
	// packet that arrives on the mesh interface and is not forwarded is dropped in
	// silence, which reads as a dead service.
	for _, want := range [][]string{
		{"ufw", "route", "allow", "in", "on", "noobtun"},
		{"ufw", "route", "allow", "out", "on", "noobtun"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
	} {
		if !host.ran(want...) {
			t.Fatalf("expected %q to run, calls: %v", strings.Join(want, " "), host.calls)
		}
	}
}

// TestAdvertisedNetworksGetRoutingRules covers what "advertise all" needs: the
// mesh traffic has to be forwarded to those networks, and the host has to forward.
func TestAdvertisedNetworksGetRoutingRules(t *testing.T) {
	host := &fakeHost{ufw: true, existingIP: map[string]bool{}}
	testAgent(host, true).allowMeshTraffic(context.Background())

	for _, want := range [][]string{
		{"ufw", "allow", "in", "on", "noobtun"},
		{"ufw", "route", "allow", "in", "on", "noobtun"},
		{"ufw", "route", "allow", "out", "on", "noobtun"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
	} {
		if !host.ran(want...) {
			t.Fatalf("expected %q to run, calls: %v", strings.Join(want, " "), host.calls)
		}
	}
}

// TestIptablesRulesAreInsertedOnce checks the mesh rules are re-asserted at the
// head of the chain. Deleting and re-inserting is deliberate: Docker puts its own
// jumps back at the top whenever a container or network is created, and a packet
// its chains drop never reaches a rule of ours further down.
func TestIptablesRulesAreInsertedOnce(t *testing.T) {
	host := &fakeHost{iptables: true, existingIP: map[string]bool{
		"INPUT -i noobtun -j ACCEPT": true,
	}}
	testAgent(host, true).allowMeshTraffic(context.Background())

	for _, want := range [][]string{
		{"iptables", "-D", "INPUT", "-i", "noobtun", "-j", "ACCEPT"},
		{"iptables", "-I", "INPUT", "-i", "noobtun", "-j", "ACCEPT"},
		{"iptables", "-I", "FORWARD", "-i", "noobtun", "-j", "ACCEPT"},
		{"iptables", "-I", "FORWARD", "-o", "noobtun", "-j", "ACCEPT"},
		// Traffic between the mesh and a 1500 byte LAN needs its segment size
		// clamped, or the tunnel drops the large packets and the link crawls.
		{"iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	} {
		if !host.ran(want...) {
			t.Fatalf("expected %q to run, calls: %v", strings.Join(want, " "), host.calls)
		}
	}
}

// TestFirewallFailureIsReported keeps a silent failure from hiding the problem:
// the control node's Errors view shows the agent's last error.
func TestFirewallFailureIsReported(t *testing.T) {
	host := &fakeHost{ufw: true, failOn: "allow in on"}
	a := testAgent(host, false)
	a.allowMeshTraffic(context.Background())
	if !strings.Contains(a.lastError(), "host firewall") {
		t.Fatalf("the failure should be reported, last error: %q", a.lastError())
	}
}

// TestSetupSystemCanBeTurnedOff leaves complete control to the operator who
// manages their own firewall.
func TestSetupSystemCanBeTurnedOff(t *testing.T) {
	host := &fakeHost{ufw: true}
	a := testAgent(host, true)
	a.opts.SetupSystem = false
	a.setupHost(context.Background())
	if len(host.calls) != 0 {
		t.Fatalf("nothing should be run with --setup-system=false: %v", host.calls)
	}
}

// TestMeshTrafficIsKeptOutOfHostNAT covers the "curl on the agent works, the
// proxy times out" case: Docker masquerades a container's answer to traffic
// leaving its bridge, so the control node - which opened the connection to the
// container's own address - sees the answer arrive from somewhere else and
// drops it.
func TestMeshTrafficIsKeptOutOfHostNAT(t *testing.T) {
	host := &fakeHost{iptables: true, existingIP: map[string]bool{}}
	a := testAgent(host, true)
	a.meshNATExempt(context.Background(), "10.77.0.0/16")

	rule := []string{"iptables", "-t", "nat", "-I", "POSTROUTING", "-d", "10.77.0.0/16", "-j", "RETURN"}
	if !host.ran(rule...) {
		t.Fatalf("the mesh range should be returned from POSTROUTING before Docker's rules: %v", host.calls)
	}
	// The rule has to be re-inserted rather than checked, because it only works
	// while it sits ahead of the rules Docker adds.
	if !host.ran("iptables", "-t", "nat", "-D", "POSTROUTING", "-d", "10.77.0.0/16", "-j", "RETURN") {
		t.Fatalf("the rule should be removed before it is inserted again: %v", host.calls)
	}
}

// TestNATExemptionFailureIsReported keeps the same silence out of this path: if
// the rule cannot be installed, the control node's Errors view says so.
func TestNATExemptionFailureIsReported(t *testing.T) {
	host := &fakeHost{iptables: true, existingIP: map[string]bool{}, failOn: "nat"}
	a := testAgent(host, true)
	a.meshNATExempt(context.Background(), "10.77.0.0/16")
	if !strings.Contains(a.lastError(), "masquerade") {
		t.Fatalf("the failure should be reported, last error: %q", a.lastError())
	}
}

// TestNATExemptionIgnoresWhatItCannotUse leaves hosts without iptables and
// agents that were told not to touch the system alone.
func TestNATExemptionIgnoresWhatItCannotUse(t *testing.T) {
	noIptables := &fakeHost{}
	testAgent(noIptables, true).meshNATExempt(context.Background(), "10.77.0.0/16")
	if len(noIptables.calls) != 0 {
		t.Fatalf("nothing should run without iptables: %v", noIptables.calls)
	}

	off := &fakeHost{iptables: true}
	a := testAgent(off, true)
	a.opts.SetupSystem = false
	a.meshNATExempt(context.Background(), "10.77.0.0/16")
	if len(off.calls) != 0 {
		t.Fatalf("nothing should run with --setup-system=false: %v", off.calls)
	}

	// A mesh range that is not an IPv4 prefix is nothing to act on either.
	junk := &fakeHost{iptables: true}
	testAgent(junk, true).meshNATExempt(context.Background(), "")
	if len(junk.calls) != 0 {
		t.Fatalf("nothing should run without a mesh range: %v", junk.calls)
	}
}

// TestCarriedAddressesAreExemptedFromTheRawTable covers the rule that hid behind
// every other check: Pterodactyl blocks container addresses in the raw table,
// which runs before conntrack, routing and FORWARD, so a packet from the mesh is
// dropped with no counter in any of the places that were being inspected.
func TestCarriedAddressesAreExemptedFromTheRawTable(t *testing.T) {
	host := &fakeHost{iptables: true, existingIP: map[string]bool{}}
	a := testAgent(host, true)
	a.opts.Interface = "noobtun"
	a.meshRawExempt(context.Background(), "noobtun", []string{"172.18.0.3/32"})

	rule := []string{"iptables", "-t", "raw", "-I", "PREROUTING", "-i", "noobtun", "-d", "172.18.0.3/32", "-j", "ACCEPT"}
	if !host.ran(rule...) {
		t.Fatalf("the address has to be exempted from the raw table: %v", host.calls)
	}
	if !host.ran("iptables", "-t", "raw", "-D", "PREROUTING", "-i", "noobtun", "-d", "172.18.0.3/32", "-j", "ACCEPT") {
		t.Fatalf("it should be removed first so it ends up above the other program's rules: %v", host.calls)
	}

	// Nothing carried means nothing to exempt; an operator who manages their own
	// firewall is left alone.
	quiet := &fakeHost{iptables: true}
	testAgent(quiet, true).meshRawExempt(context.Background(), "noobtun", nil)
	if len(quiet.calls) != 0 {
		t.Fatalf("nothing to exempt: %v", quiet.calls)
	}
	off := &fakeHost{iptables: true}
	managed := testAgent(off, true)
	managed.opts.SetupSystem = false
	managed.meshRawExempt(context.Background(), "noobtun", []string{"172.18.0.3/32"})
	if len(off.calls) != 0 {
		t.Fatalf("nothing should run with --setup-system=false: %v", off.calls)
	}
}

// TestCountersSnapshotIsDiffable covers what the control node needs from an
// agent: one line per rule with its packet count, so two snapshots can be
// compared and the rule that consumed a packet named.
func TestCountersSnapshotIsDiffable(t *testing.T) {
	host := &fakeHost{iptables: true, saved: strings.Join([]string{
		"# Generated by iptables-save",
		"*filter",
		":FORWARD ACCEPT [0:0]",
		"[5:380] -A FORWARD -i noobtun -j ACCEPT",
		"[0:0] -A FORWARD -j DOCKER-USER",
		"COMMIT",
		"*nat",
		":POSTROUTING ACCEPT [0:0]",
		"[2:128] -A POSTROUTING -d 10.77.0.0/16 -j RETURN",
		"COMMIT",
	}, "\n")}
	a := testAgent(host, true)
	snapshot := a.netfilterSnapshot(context.Background())
	want := []string{
		"0 filter -A FORWARD -j DOCKER-USER",
		"2 nat -A POSTROUTING -d 10.77.0.0/16 -j RETURN",
		"5 filter -A FORWARD -i noobtun -j ACCEPT",
	}
	if len(snapshot) != len(want) {
		t.Fatalf("snapshot = %v, want %v", snapshot, want)
	}
	for i := range want {
		if snapshot[i] != want[i] {
			t.Fatalf("snapshot[%d] = %q, want %q", i, snapshot[i], want[i])
		}
	}
	// Without the tool the control node is told nothing rather than something
	// wrong.
	if got := testAgent(&fakeHost{}, true).netfilterSnapshot(context.Background()); got != nil {
		t.Fatalf("no iptables-save means no snapshot, got %v", got)
	}
}

// TestForwardingAlreadyOnIsNotAProblem covers a docker agent: /proc/sys is
// read-only in a container, so the write fails while the machine forwards
// perfectly well, and the agent reported that as a firewall failure on every
// start.
func TestForwardingAlreadyOnIsNotAProblem(t *testing.T) {
	host := &fakeHost{iptables: true, forwarding: "1"}
	a := testAgent(host, true)
	a.allowMeshTraffic(context.Background())
	if !host.ran("sysctl", "-n", "net.ipv4.ip_forward") {
		t.Fatalf("the current value should be read first: %v", host.calls)
	}
	if host.ran("sysctl", "-w", "net.ipv4.ip_forward=1") {
		t.Fatalf("nothing to write when it is already on: %v", host.calls)
	}
}

// TestCarriedNetworksOpenForwarding covers the case that looks like a dead
// service: the operator adds a network to an agent in the UI, the hub routes it
// there, and the machine was never told to forward it - so every packet for it is
// dropped by the host and the target times out.
func TestCarriedNetworksOpenForwarding(t *testing.T) {
	host := &fakeHost{iptables: true, existingIP: map[string]bool{}}
	a := testAgent(host, false)
	a.session = &sessionState{peers: map[uint32]proto.Peer{}}
	if !a.setCarry([]string{"172.18.0.0/16"}) {
		t.Fatal("a new carried set counts as a change")
	}
	a.syncCarriedForwarding(context.Background())

	for _, want := range [][]string{
		{"iptables", "-I", "FORWARD", "-i", "noobtun", "-j", "ACCEPT"},
		{"iptables", "-I", "FORWARD", "-o", "noobtun", "-j", "ACCEPT"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
	} {
		if !host.ran(want...) {
			t.Fatalf("expected %q to run, calls: %v", strings.Join(want, " "), host.calls)
		}
	}

	// The same set again is not reapplied: membership messages arrive often.
	before := len(host.calls)
	if a.setCarry([]string{"172.18.0.0/16"}) {
		t.Fatal("the same carried set is not a change")
	}
	a.syncCarriedForwarding(context.Background())
	if len(host.calls) != before {
		t.Fatalf("nothing should run again: %v", host.calls[before:])
	}

	// An agent the mesh routes nothing through is left as it was.
	later := &fakeHost{iptables: true}
	idle := testAgent(later, false)
	idle.session = &sessionState{peers: map[uint32]proto.Peer{}}
	idle.syncCarriedForwarding(context.Background())
	if len(later.calls) != 0 {
		t.Fatalf("nothing to forward means nothing to open: %v", later.calls)
	}
}
