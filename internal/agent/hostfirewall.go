package agent

import (
	"context"
	"fmt"
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

// allowMeshTraffic opens the host firewall for the mesh interface, the way the
// control node does for its own hub.
//
// Without it the agent's device is up and the tunnel handshakes, but the host
// still rejects the traffic: a default firewall (ufw's is
// "-A INPUT -j REJECT --reject-with icmp-host-prohibited") answers every packet
// that arrives on the mesh interface with ICMP host-prohibited, which the control
// node's proxy then reports as "connect: no route to host" while the service on
// this machine is perfectly healthy. Forwarding rules are added only when this
// agent advertises networks for other agents to reach.
func (a *Agent) allowMeshTraffic(ctx context.Context) {
	iface := a.opts.Interface
	if iface == "" {
		iface = "noobtun"
	}
	advertises := a.opts.AdvertiseAll || len(a.opts.Advertise) > 0
	var problems []string

	switch {
	case a.ufwActive(ctx):
		if err := a.ufw("allow", "in", "on", iface); err != nil {
			problems = append(problems, "ufw allow in on "+iface+": "+err.Error())
		}
		if advertises {
			// ufw route rules are the FORWARD chain: traffic relayed between the
			// mesh and the networks this agent advertises.
			if err := a.ufw("route", "allow", "in", "on", iface); err != nil {
				problems = append(problems, "ufw route allow in on "+iface+": "+err.Error())
			}
			if err := a.ufw("route", "allow", "out", "on", iface); err != nil {
				problems = append(problems, "ufw route allow out on "+iface+": "+err.Error())
			}
		}
	default:
		problems = append(problems, a.iptablesAllow(ctx, iface, advertises)...)
	}

	if advertises {
		if err := a.enableForwarding(ctx); err != nil {
			problems = append(problems, err.Error())
		}
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
