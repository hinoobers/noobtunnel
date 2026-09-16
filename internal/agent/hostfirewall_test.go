package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// fakeHost records the host commands and answers the questions the firewall
// setup asks.
type fakeHost struct {
	ufw        bool
	iptables   bool
	failOn     string
	calls      [][]string
	existingIP map[string]bool
}

func (f *fakeHost) LookPath(name string) (string, error) {
	switch {
	case name == "ufw" && f.ufw:
		return "ufw", nil
	case name == "iptables" && f.iptables:
		return "iptables", nil
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
	for _, call := range host.calls {
		if strings.Contains(strings.Join(call, " "), "route") {
			t.Fatalf("an agent that advertises nothing needs no forwarding rule: %v", call)
		}
		if strings.HasPrefix(strings.Join(call, " "), "sysctl") {
			t.Fatalf("an agent that advertises nothing needs no IP forwarding: %v", call)
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

// TestIptablesRulesAreInsertedOnce checks the fallback path and that an existing
// rule is not added twice.
func TestIptablesRulesAreInsertedOnce(t *testing.T) {
	host := &fakeHost{iptables: true, existingIP: map[string]bool{
		"INPUT -i noobtun -j ACCEPT": true,
	}}
	testAgent(host, true).allowMeshTraffic(context.Background())

	if host.ran("iptables", "-I", "INPUT", "-i", "noobtun", "-j", "ACCEPT") {
		t.Fatalf("a rule that is already there should not be inserted again: %v", host.calls)
	}
	for _, want := range [][]string{
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
