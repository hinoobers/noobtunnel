package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// sysctlFile persists IPv4 forwarding across reboots.
const sysctlFile = "/etc/sysctl.d/99-noobtunnel.conf"

// ApplySystemSetup enables IP forwarding and accepts forwarded mesh traffic. It
// is idempotent and safe to run on every start.
func (s *Server) ApplySystemSetup(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic system setup is only implemented for Linux (running %s)", runtime.GOOS)
	}
	settings := s.store.Settings()
	var problems []string

	const content = "net.ipv4.ip_forward = 1\n"
	if raw, err := os.ReadFile(sysctlFile); err != nil || string(raw) != content {
		if err := os.WriteFile(sysctlFile, []byte(content), 0o644); err != nil {
			problems = append(problems, "write "+sysctlFile+": "+err.Error())
		} else {
			s.log.Info("persisted IPv4 forwarding", "file", sysctlFile)
		}
	}
	if _, err := exec.CommandContext(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1").Output(); err != nil {
		problems = append(problems, "sysctl -w net.ipv4.ip_forward=1: "+err.Error())
	}

	if path, err := exec.LookPath("iptables"); err == nil {
		problems = append(problems, enableIptablesForwarding(ctx, path, settings.Interface, settings.MeshCIDR)...)
	} else if path, nftErr := exec.LookPath("nft"); nftErr == nil {
		if err := ensureNftForwarding(ctx, path, settings.Interface); err != nil {
			problems = append(problems, err.Error())
		} else {
			s.log.Info("nftables accepts forwarded mesh traffic", "interface", settings.Interface)
		}
	} else {
		problems = append(problems, "neither iptables nor nft was found, relayed traffic may be blocked")
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func enableIptablesForwarding(ctx context.Context, iptables, iface, meshCIDR string) []string {
	var problems []string
	for _, direction := range []string{"-i", "-o"} {
		if runQuiet(ctx, iptables, "-C", "FORWARD", direction, iface, "-j", "ACCEPT") {
			continue
		}
		if !runQuiet(ctx, iptables, "-I", "FORWARD", direction, iface, "-j", "ACCEPT") {
			problems = append(problems, "iptables "+direction+" "+iface+" -j ACCEPT failed")
		}
	}
	// Clamp the TCP segment size to the path MTU. Without it, endpoints negotiate
	// a size for their own link, the tunnel silently drops the packets that are
	// too large for it, and the connection still works - slowly, through
	// retransmissions. It is the usual reason a mesh tunnel feels slow.
	clamp := []string{"FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu"}
	check := append([]string{"-t", "mangle", "-C"}, clamp...)
	if !runQuiet(ctx, iptables, check...) {
		insert := append([]string{"-t", "mangle", "-A"}, clamp...)
		if !runQuiet(ctx, iptables, insert...) {
			problems = append(problems, "iptables mangle FORWARD TCPMSS clamping failed")
		}
	}
	// A container answer must keep its own address when it comes back through
	// the tunnel, or the peer that opened the connection drops it as unrelated
	// and reports an i/o timeout against a service that is perfectly healthy.
	// Docker masquerades traffic leaving its bridges for any other interface, so
	// the mesh range is returned from the NAT table before any of that runs.
	if mesh, err := netip.ParsePrefix(strings.TrimSpace(meshCIDR)); err == nil && mesh.Addr().Is4() {
		nat := []string{"-d", mesh.Masked().String(), "-j", "RETURN"}
		// Delete and re-insert so the rule keeps the head of the chain.
		_, _ = exec.CommandContext(ctx, iptables, append([]string{"-t", "nat", "-D", "POSTROUTING"}, nat...)...).Output()
		if _, err := exec.CommandContext(ctx, iptables, append([]string{"-t", "nat", "-I", "POSTROUTING"}, nat...)...).Output(); err != nil {
			problems = append(problems, "iptables -t nat POSTROUTING for "+mesh.Masked().String()+" failed: "+err.Error())
		}
	}
	return problems
}

func ensureNftForwarding(ctx context.Context, nft, iface string) error {
	steps := [][]string{
		{"add", "table", "inet", "noobtunnel"},
		{"add", "chain", "inet", "noobtunnel", "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}"},
		{"add", "rule", "inet", "noobtunnel", "forward", "iifname", `"` + iface + `"`, "accept"},
		{"add", "rule", "inet", "noobtunnel", "forward", "oifname", `"` + iface + `"`, "accept"},
	}
	for _, step := range steps {
		out, err := exec.CommandContext(ctx, nft, step...).CombinedOutput()
		if err == nil {
			continue
		}
		message := strings.TrimSpace(string(out))
		if strings.Contains(message, "File exists") || strings.Contains(message, "already exists") {
			continue
		}
		return fmt.Errorf("nft %s: %w: %s", strings.Join(step, " "), err, message)
	}
	return nil
}

// BinaryInfo describes a downloadable agent binary.
type BinaryInfo struct {
	Name string `json:"name"`
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Size int64  `json:"size"`
}

// AvailableBinaries lists release binaries that enrolling agents can download.
func (s *Server) AvailableBinaries() []BinaryInfo {
	dir := s.opts.BinaryDir
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []BinaryInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "noobtunnel_") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())), "_")
		if len(parts) < 3 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, BinaryInfo{
			Name: entry.Name(),
			OS:   parts[1],
			Arch: parts[2],
			Size: info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
