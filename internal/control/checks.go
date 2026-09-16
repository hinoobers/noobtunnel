package control

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

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
	case !ok || !stat.Listening:
		detail := "not listening on port 443 yet"
		if ok && stat.LastError != "" {
			detail = stat.LastError
		}
		return Check{
			ID: "domain", Title: "Public hostname", Status: statusFail,
			Detail: domain + ": " + detail,
			Fix:    "free port 443 (for example systemctl disable --now nginx) and restart the control node",
		}
	default:
		return Check{
			ID: "domain", Title: "Public hostname", Status: statusOK,
			Detail: "https://" + domain + " serves the UI and API; the certificate is managed automatically",
		}
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
