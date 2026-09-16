package agent

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// hostRunner runs the host commands the firewall setup needs, so tests can watch
// what would be executed without touching a real firewall.
type hostRunner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// execHostRunner is the real thing.
type execHostRunner struct{}

// host returns the runner the agent uses for host commands.
func (a *Agent) host() hostRunner {
	if a.hostRunner != nil {
		return a.hostRunner
	}
	return execHostRunner{}
}

func (execHostRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (execHostRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// setupHost applies the host-side setup unless the operator turned it off.
func (a *Agent) setupHost(ctx context.Context) {
	if !a.opts.SetupSystem {
		return
	}
	a.allowMeshTraffic(ctx)
}

// meshNATExempt keeps the host's NAT rules from rewriting traffic that leaves an
// advertised network for the mesh.
//
// Docker masquerades everything that leaves one of its bridges through another
// interface. A service inside a container therefore answers a connection from the
// mesh with the *host's* mesh address as the source, and the control node - which
// opened that connection to the container's own address - drops the answer as
// unrelated. The service is healthy, curl from the agent works, and the proxy
// dials until it times out. Returning from POSTROUTING before any NAT rule runs
// leaves the real address on the packet, which is what a routed network is meant
// to do.
//
// The rule is re-asserted rather than merely checked: it has to sit before the
// rules Docker inserts, and Docker puts its own back at the top whenever the
// daemon or a network is created.
func (a *Agent) meshNATExempt(ctx context.Context, meshCIDR string) {
	if !a.opts.SetupSystem {
		return
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(meshCIDR))
	if err != nil || !prefix.Addr().Is4() {
		return
	}
	host := a.host()
	iptables, err := host.LookPath("iptables")
	if err != nil {
		return // No iptables: nothing to order, nft setups are left alone.
	}
	rule := []string{"-t", "nat", "POSTROUTING", "-d", prefix.Masked().String(), "-j", "RETURN"}
	// Delete first so the insert lands at the head of the chain, ahead of
	// anything that would masquerade the packet.
	remove := append([]string{"-t", "nat", "-D"}, rule[2:]...)
	insert := append([]string{"-t", "nat", "-I"}, rule[2:]...)
	_, _ = host.Run(ctx, iptables, remove...)
	if _, err := host.Run(ctx, iptables, insert...); err != nil {
		message := "host NAT: could not keep mesh traffic out of Docker's masquerade rules, " +
			"so services inside containers may answer from the wrong address: " + err.Error()
		a.setLastError(message)
		a.log.Warn("could not exclude the mesh from host NAT", "error", err)
		return
	}
	a.log.Debug("mesh traffic is excluded from host NAT", "mesh", prefix.Masked().String())
}

// allowMeshTraffic opens the host firewall for the mesh interface, the way the
// control node does for its own hub.
//
// Without it the agent's device is up and the tunnel handshakes, but the host
// still rejects the traffic: a default firewall (ufw's is
// "-A INPUT -j REJECT --reject-with icmp-host-prohibited") answers every packet
// that arrives on the mesh interface with ICMP host-prohibited, which the control
// node's proxy then reports as "connect: no route to host" while the service on
// this machine is perfectly healthy.
//
// Forwarding is opened the same way and unconditionally: the control node dials
// published targets through this machine, and a host that accepts a packet on the
// mesh interface and does not forward it drops it in silence.
func (a *Agent) allowMeshTraffic(ctx context.Context) {
	iface := a.opts.Interface
	if iface == "" {
		iface = "noobtun"
	}
	// Accepting mesh traffic, and forwarding for it, is not conditional on what
	// this machine happened to advertise at enrollment: the control node can pin a
	// published target's address to this agent at any moment, and a network it
	// routes here that the host refuses to forward is a SYN that arrives and is
	// dropped - the one failure that looks identical to a dead service from
	// everywhere else. A host that carries nothing simply never receives anything.
	advertises := a.advertises()
	var problems []string

	switch {
	case a.ufwActive(ctx):
		// ufw keeps its own chains, so its default deny has to be opened for the
		// mesh interface as well.
		if err := a.ufw("allow", "in", "on", iface); err != nil {
			problems = append(problems, "ufw allow in on "+iface+": "+err.Error())
		}
		// ufw route rules are the FORWARD chain: traffic relayed between the mesh
		// and the networks behind this machine.
		if err := a.ufw("route", "allow", "in", "on", iface); err != nil {
			problems = append(problems, "ufw route allow in on "+iface+": "+err.Error())
		}
		if err := a.ufw("route", "allow", "out", "on", iface); err != nil {
			problems = append(problems, "ufw route allow out on "+iface+": "+err.Error())
		}
	default:
		problems = append(problems, a.iptablesAllow(ctx, iface, true)...)
	}

	if err := a.enableForwarding(ctx); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		// Not fatal: the agent itself is fine, but the mesh traffic may be. Say so
		// loudly, and the control node's Errors view shows it too.
		a.setLastError("host firewall: " + strings.Join(problems, "; "))
		a.log.Warn("could not open the host firewall for the mesh", "problems", strings.Join(problems, "; "))
		return
	}
	a.log.Info("host firewall allows mesh traffic", "interface", iface, "forwarding", advertises)
}

// ufwActive reports whether ufw is managing this host's firewall.
func (a *Agent) ufwActive(ctx context.Context) bool {
	host := a.host()
	if _, err := host.LookPath("ufw"); err != nil {
		return false
	}
	out, err := host.Run(ctx, "ufw", "status")
	return err == nil && strings.Contains(out, "Status: active")
}

func (a *Agent) ufw(args ...string) error {
	out, err := a.host().Run(context.Background(), "ufw", args...)
	if err == nil {
		return nil
	}
	// Repeating a rule ufw already has is not an error for us.
	if strings.Contains(out, "Skipping") {
		return nil
	}
	return err
}

// iptablesAllow inserts the accept rules a host firewall needs, once.
func (a *Agent) iptablesAllow(ctx context.Context, iface string, advertises bool) []string {
	host := a.host()
	iptables, err := host.LookPath("iptables")
	if err != nil {
		return nil // No iptables: nothing to open, and nft setups are left alone.
	}
	var problems []string
	ensure := func(args ...string) {
		check := append([]string{"-C"}, args...)
		if _, err := host.Run(ctx, iptables, check...); err == nil {
			return
		}
		insert := append([]string{"-I"}, args...)
		if _, err := host.Run(ctx, iptables, insert...); err != nil {
			problems = append(problems, fmt.Sprintf("iptables %s: %v", strings.Join(args, " "), err))
		}
	}
	ensure("INPUT", "-i", iface, "-j", "ACCEPT")
	if advertises {
		ensure("FORWARD", "-i", iface, "-j", "ACCEPT")
		ensure("FORWARD", "-o", iface, "-j", "ACCEPT")
		// Clamp the TCP segment size for traffic that crosses between the mesh and
		// the advertised networks: hosts on a 1500 byte LAN would otherwise send
		// segments the tunnel silently drops, and the connection crawls.
		clamp := []string{"FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"}
		check := append([]string{"-t", "mangle", "-C"}, clamp...)
		if _, err := host.Run(ctx, iptables, check...); err != nil {
			appendRule := append([]string{"-t", "mangle", "-A"}, clamp...)
			if _, err := host.Run(ctx, iptables, appendRule...); err != nil {
				problems = append(problems, fmt.Sprintf("iptables mangle TCPMSS clamping: %v", err))
			}
		}
	}
	return problems
}

// enableForwarding turns on IPv4 forwarding, which relaying between the mesh and
// an advertised network needs.
func (a *Agent) enableForwarding(ctx context.Context) error {
	if _, err := a.host().Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("ipv4 forwarding: %w", err)
	}
	return nil
}
