package control

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/proxy"
)

// Check is one preflight result shown in the UI.
type Check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"` // ok | warn | fail | info
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

const (
	statusOK   = "ok"
	statusWarn = "warn"
	statusFail = "fail"
	statusInfo = "info"
)

// checkLoop keeps the dashboard's checklist current. The checks are read from the
// host (is the hub interface there, is port 443 free, are the firewall rules in
// place), so a result computed once at startup describes the machine as it was
// then: an interface that appeared later, or a port that was busy during a
// restart, would keep showing the old answer until someone hit refresh.
// routeLoop re-asserts the hub's kernel routes.
//
// A device can be up with the right peers and still have no route for the mesh,
// and then every answer to an agent leaves through this machine's default
// gateway instead of the tunnel - the tunnel looks healthy while nothing that
// arrives through it is ever answered. Re-asserting the routes is idempotent, so
// it is done on a timer rather than trusted once.
func (s *Server) routeLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reassertRoutes(ctx)
		}
	}
}

// reassertRoutes re-applies the mesh routes to the live hub device.
func (s *Server) reassertRoutes(ctx context.Context) {
	if s.opts.DisableWGHub {
		return
	}
	settings := s.store.Settings()
	cfg, err := s.hubConfig()
	if err != nil || len(cfg.Routes) == 0 {
		return
	}
	if err := s.backend.EnsureRoutes(ctx, settings.Interface, cfg.Routes); err != nil {
		s.log.Warn("could not re-assert the mesh routes", "error", err)
	}
}

func (s *Server) checkLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next := s.RunChecks(ctx)
			s.mu.Lock()
			changed := !sameChecks(s.checks, next)
			s.checks = next
			s.mu.Unlock()
			if changed {
				s.broadcastState()
			}
		}
	}
}

// sameChecks reports whether two checklist results say the same thing.
func sameChecks(a, b []Check) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RunChecks inspects the host and reports what still needs doing before agents
// can reach each other.
func (s *Server) RunChecks(ctx context.Context) []Check {
	settings := s.store.Settings()
	var checks []Check

	checks = append(checks, Check{
		ID: "platform", Title: "Host platform", Status: statusInfo,
		Detail: fmt.Sprintf("%s/%s, wireguard backend %s", runtime.GOOS, runtime.GOARCH, s.backend.Name()),
	})

	status, err := s.backend.Status(ctx, settings.Interface)
	switch {
	case err != nil:
		checks = append(checks, Check{
			ID: "wireguard", Title: "WireGuard device", Status: statusFail,
			Detail: err.Error(),
			Fix:    "modprobe wireguard && apt-get install -y wireguard-tools iproute2",
		})
	case !status.Exists:
		checks = append(checks, Check{
			ID: "wireguard", Title: "WireGuard device", Status: statusFail,
			Detail: fmt.Sprintf("interface %s is not up yet", settings.Interface),
			Fix:    "journalctl -u noobtunnel-server -n 50",
		})
	default:
		checks = append(checks, Check{
			ID: "wireguard", Title: "WireGuard device", Status: statusOK,
			Detail: fmt.Sprintf("%s is up, listening on udp/%d with %d peer(s)",
				status.Name, status.ListenPort, len(status.Peers)),
		})
	}

	if runtime.GOOS == "linux" {
		checks = append(checks, forwardingCheck())
		checks = append(checks, s.inboundCheck(ctx, settings.Interface))
		checks = append(checks, s.firewallCheck(ctx, settings.Interface))
	}

	checks = append(checks, s.endpointCheck())

	checks = append(checks, s.domainCheck())

	if !s.auth.HasPassword() {
		checks = append(checks, Check{
			ID: "password", Title: "User accounts", Status: statusWarn,
			Detail: "no accounts exist, so nobody can sign in to the web UI yet",
			Fix:    "restart the control node with --admin-password 'a long passphrase'",
		})
	} else {
		checks = append(checks, Check{
			ID: "password", Title: "User accounts", Status: statusOK,
			Detail: fmt.Sprintf("%d account(s), %d admin(s)", len(s.auth.Users()), s.auth.AdminCount()),
		})
	}

	binaries := s.AvailableBinaries()
	if len(binaries) == 0 {
		checks = append(checks, Check{
			ID: "binaries", Title: "Agent installer downloads", Status: statusWarn,
			Detail: "no release binaries are available, so the one line install command has nothing to download",
			Fix:    "copy dist/noobtunnel_linux_* to the server and restart it with --binary-dir PATH",
		})
	} else {
		var names []string
		for _, b := range binaries {
			names = append(names, b.Name)
		}
		checks = append(checks, Check{
			ID: "binaries", Title: "Agent installer downloads", Status: statusOK,
			Detail: "serving " + strings.Join(names, ", "),
		})
	}

	if settings.DirectPaths {
		checks = append(checks, Check{
			ID: "direct", Title: "Direct paths", Status: statusOK,
			Detail: "agents try direct connections first and fall back to the hub automatically",
		})
	} else {
		checks = append(checks, Check{
			ID: "direct", Title: "Direct paths", Status: statusInfo,
			Detail: "disabled, all mesh traffic is relayed by the control node",
		})
	}

	checks = append(checks, Check{ID: "state", Title: "State directory", Status: statusInfo, Detail: s.store.Path()})

	if resources := s.store.Resources(); len(resources) > 0 {
		if !s.proxies.Started() {
			// Nothing has tried to bind yet: this is a report or a one-off
			// command, not the process that serves the resources.
			checks = append(checks, Check{
				ID: "resources", Title: "Published services", Status: statusInfo,
				Detail: fmt.Sprintf("%d configured; the running control node serves them, and this report does not bind their ports", len(resources)),
			})
		} else {
			stats := s.proxies.Stats()
			var listening, failed []string
			for _, r := range resources {
				if !r.Enabled {
					continue
				}
				if stat, ok := stats[r.ID]; ok && stat.Listening {
					listening = append(listening, r.Name)
					continue
				}
				detail := "not listening"
				if stat, ok := stats[r.ID]; ok && stat.LastError != "" {
					detail = stat.LastError
					if holder := portHolder(context.Background(), r.EffectiveListenPort()); holder != "" {
						detail += " (port " + itoa(r.EffectiveListenPort()) + " is held by " + holder + ")"
					}
				}
				failed = append(failed, r.Name+": "+detail)
			}
			switch {
			case len(failed) > 0:
				checks = append(checks, Check{
					ID: "resources", Title: "Published services", Status: statusFail,
					Detail: strings.Join(failed, "; "),
					Fix:    "free the port or change the listen port in the Resources tab",
				})
			case len(listening) > 0:
				checks = append(checks, Check{
					ID: "resources", Title: "Published services", Status: statusOK,
					Detail: fmt.Sprintf("%d listening (%s)", len(listening), strings.Join(listening, ", ")),
				})
			}
		}
	}
	return checks
}

func forwardingCheck() Check {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return Check{ID: "forwarding", Title: "IP forwarding", Status: statusWarn, Detail: err.Error()}
	}
	if strings.TrimSpace(string(raw)) == "1" {
		return Check{
			ID: "forwarding", Title: "IP forwarding", Status: statusOK,
			Detail: "enabled, the control node can relay traffic between agents",
		}
	}
	return Check{
		ID: "forwarding", Title: "IP forwarding", Status: statusFail,
		Detail: "disabled, so relayed traffic cannot pass through the control node",
		Fix:    "sysctl -w net.ipv4.ip_forward=1; echo net.ipv4.ip_forward=1 > /etc/sysctl.d/99-noobtunnel.conf",
	}
}

func (s *Server) endpointCheck() Check {
	endpoint := s.hubEndpoint("")
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified()) {
		return Check{
			ID: "endpoint", Title: "Advertised WireGuard endpoint", Status: statusWarn,
			Detail: fmt.Sprintf("advertising %s, which is not publicly routable", endpoint),
			Fix:    "restart the control node with --public-endpoint YOUR.PUBLIC.IP:51820",
		}
	}
	return Check{
		ID: "endpoint", Title: "Advertised WireGuard endpoint", Status: statusOK,
		Detail: "agents are told to dial " + endpoint,
	}
}

// domainCheck reports whether the control node's own hostname is actually
// reachable on the shared HTTPS port, which is where a busy web server shows up.
func (s *Server) domainCheck() Check {
	domain := strings.TrimSpace(s.opts.Domain)
	if domain == "" {
		return Check{
			ID: "domain", Title: "Public hostname", Status: statusInfo,
			Detail: "none configured; the UI is served on the TLS listener only",
			Fix:    "restart the control node with --domain YOUR.HOSTNAME to serve it on https://YOUR.HOSTNAME with a managed certificate",
		}
	}
	stat, ok := s.proxies.Stats()[proxy.ControlResourceID]
	switch {
	case !s.proxies.Started():
		// The port is bound by the running service, not by this process: a
		// report that says "could not bind" here is describing a bind it never
		// attempted.
		return Check{
			ID: "domain", Title: "Public hostname", Status: statusInfo,
			Detail: domain + " is served by the running control node; this report does not bind its ports, so it cannot see them",
		}
	case !ok || !stat.Listening:
		detail := "the control node could not bind port 443"
		if ok && stat.LastError != "" {
			detail = stat.LastError
		}
		// Naming the process that holds the port turns "could not bind" into
		// something an operator can act on in one step.
		if holder := portHolder(context.Background(), 443); holder != "" {
			detail += " (port 443 is held by " + holder + ")"
		}
		return Check{
			ID: "domain", Title: "Public hostname", Status: statusFail,
			Detail: domain + ": " + detail,
			Fix:    domainFix(detail),
		}
	default:
		return Check{
			ID: "domain", Title: "Public hostname", Status: statusOK,
			Detail: "https://" + domain + " serves the UI and API; the certificate is managed automatically",
		}
	}
}

// domainFix turns the port 443 bind failure into the thing to do about it. The
// three cases look identical in the UI otherwise, and only one of them is about
// another service holding the port.
func domainFix(detail string) string {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "permission denied"):
		return "binding port 443 needs root: run the control node as root, or grant it CAP_NET_BIND_SERVICE"
	case strings.Contains(lower, "address already in use") || strings.Contains(lower, "in use"):
		return "something else holds port 443: stop it (for example systemctl disable --now nginx) and restart the control node"
	case strings.Contains(lower, "cannot assign requested address"):
		return "the address port 443 is bound to does not exist on this host; check the exit node or listen address"
	default:
		return "check journalctl -u noobtunnel-server for the reason port 443 could not be bound, then restart the control node"
	}
}

// inboundCheck verifies the one rule that is easy to miss and impossible to
// guess: this control node dials published targets itself, so the answers come
// back addressed to it and arrive on the input chain. A host firewall that
// rejects traffic on the mesh interface drops them, the agent side looks
// perfect, and every target times out.
func (s *Server) inboundCheck(ctx context.Context, iface string) Check {
	if _, err := exec.LookPath("iptables"); err == nil {
		if runQuiet(ctx, "iptables", "-C", "INPUT", "-i", iface, "-j", "ACCEPT") {
			return Check{ID: "inbound", Title: "Inbound mesh traffic", Status: statusOK,
				Detail: "iptables accepts traffic arriving on " + iface}
		}
		return Check{
			ID: "inbound", Title: "Inbound mesh traffic", Status: statusFail,
			Detail: "iptables does not accept traffic arriving on " + iface +
				", so answers to the connections this control node makes are dropped",
			Fix: "iptables -I INPUT -i " + iface + " -j ACCEPT (restart the control node to have this applied)",
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		out, err := exec.CommandContext(ctx, "nft", "list", "ruleset").Output()
		if err == nil && strings.Contains(string(out), iface) && strings.Contains(string(out), "input") {
			return Check{ID: "inbound", Title: "Inbound mesh traffic", Status: statusOK,
				Detail: "nftables accepts traffic arriving on " + iface}
		}
		return Check{
			ID: "inbound", Title: "Inbound mesh traffic", Status: statusFail,
			Detail: "no nftables rule accepts traffic arriving on " + iface,
			Fix:    "nft add rule inet noobtunnel input iifname \"" + iface + "\" accept",
		}
	}
	return Check{
		ID: "inbound", Title: "Inbound mesh traffic", Status: statusWarn,
		Detail: "neither iptables nor nft is installed, inbound traffic could not be verified",
		Fix:    "apt-get install -y iptables",
	}
}

func (s *Server) firewallCheck(ctx context.Context, iface string) Check {
	if _, err := exec.LookPath("iptables"); err == nil {
		in := runQuiet(ctx, "iptables", "-C", "FORWARD", "-i", iface, "-j", "ACCEPT")
		out := runQuiet(ctx, "iptables", "-C", "FORWARD", "-o", iface, "-j", "ACCEPT")
		if in && out {
			return Check{ID: "firewall", Title: "Forwarding firewall rules", Status: statusOK,
				Detail: "iptables accepts forwarded traffic on " + iface}
		}
		return Check{
			ID: "firewall", Title: "Forwarding firewall rules", Status: statusFail,
			Detail: "iptables does not accept forwarded traffic on " + iface,
			Fix:    "iptables -I FORWARD -i " + iface + " -j ACCEPT; iptables -I FORWARD -o " + iface + " -j ACCEPT",
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		out, err := exec.CommandContext(ctx, "nft", "list", "ruleset").Output()
		if err == nil && strings.Contains(string(out), iface) {
			return Check{ID: "firewall", Title: "Forwarding firewall rules", Status: statusOK,
				Detail: "nftables accepts traffic on " + iface}
		}
		return Check{
			ID: "firewall", Title: "Forwarding firewall rules", Status: statusFail,
			Detail: "no nftables rule accepts forwarded traffic on " + iface,
			Fix:    "nft add rule inet noobtunnel forward iifname \"" + iface + "\" accept",
		}
	}
	return Check{
		ID: "firewall", Title: "Forwarding firewall rules", Status: statusWarn,
		Detail: "neither iptables nor nft is installed, forwarding could not be verified",
		Fix:    "apt-get install -y iptables",
	}
}

func runQuiet(ctx context.Context, name string, args ...string) bool {
	return exec.CommandContext(ctx, name, args...).Run() == nil
}

// portHolder names the process listening on a TCP port, so a bind failure says
// who to stop instead of leaving the operator to look it up. Empty when it
// cannot be determined, which is always better than a wrong name.
func portHolder(ctx context.Context, port int) string {
	if port <= 0 {
		return ""
	}
	ss, err := exec.LookPath("ss")
	if err != nil {
		return ""
	}
	out, err := exec.CommandContext(ctx, ss, "-H", "-ltnp").Output()
	if err != nil {
		return ""
	}
	suffix := ":" + itoa(port) + " "
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, suffix) {
			continue
		}
		// ss prints the owner as: users:(("nginx",pid=812,fd=6))
		marker := "((\""
		start := strings.Index(line, marker)
		if start < 0 {
			continue
		}
		rest := line[start+len(marker):]
		end := strings.IndexByte(rest, '"')
		if end <= 0 {
			continue
		}
		return rest[:end]
	}
	return ""
}
