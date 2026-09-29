package control

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func (s *Server) hasPrivateMeshes() bool {
	for _, user := range s.auth.Users() {
		if user.MeshSlot > 0 {
			return true
		}
	}
	return false
}

// syncTenantFirewall isolates private meshes while allowing each mesh to route
// through networks advertised by its own agents. The allow chain is rebuilt off
// path and then swapped into place, so a live update never leaves forwarding
// temporarily unprotected.
func (s *Server) syncTenantFirewall(ctx context.Context) error {
	s.tenantFirewallMu.Lock()
	defer s.tenantFirewallMu.Unlock()
	if runtime.GOOS != "linux" || !s.opts.SetupSystem {
		return errors.New("private mesh firewall requires Linux system setup")
	}
	path, err := exec.LookPath("iptables")
	if err != nil {
		return errors.New("iptables is required for private mesh isolation")
	}
	run := func(args ...string) error {
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %v: %w: %s", args, err, out)
		}
		return nil
	}
	for _, chain := range []string{"NT_MESH_FWD", "NT_MESH_IN"} {
		if err := run("-S", chain); err != nil {
			if err := run("-N", chain); err != nil {
				return err
			}
		}
	}
	for _, jump := range [][2]string{{"FORWARD", "NT_MESH_FWD"}, {"INPUT", "NT_MESH_IN"}} {
		// System setup may prepend a broad ACCEPT rule on restart. Keep the
		// isolation jump first even when a copy already exists lower down.
		out, err := exec.CommandContext(ctx, path, "-S", jump[0]).Output()
		if err != nil {
			return fmt.Errorf("inspect %s firewall chain: %w", jump[0], err)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		first := "-A " + jump[0] + " -j " + jump[1]
		if len(lines) < 2 || strings.TrimSpace(lines[1]) != first {
			if err := run("-I", jump[0], "1", "-j", jump[1]); err != nil {
				return err
			}
		}
	}
	// Replies to connections opened by the control node arrive through INPUT.
	// Allow those before the tenant source drops below; otherwise resource
	// forwards and diagnosis time out even when the agent listener is healthy.
	inbound, err := exec.CommandContext(ctx, path, "-S", "NT_MESH_IN").Output()
	if err != nil {
		return fmt.Errorf("inspect private mesh inbound rules: %w", err)
	}
	inboundLines := strings.Split(strings.TrimSpace(string(inbound)), "\n")
	const establishedReply = "-A NT_MESH_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
	if len(inboundLines) < 2 || strings.TrimSpace(inboundLines[1]) != establishedReply {
		if err := run("-I", "NT_MESH_IN", "1", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	iface := s.store.Settings().Interface
	const allowA, allowB = "NT_MESH_ALLOW_A", "NT_MESH_ALLOW_B"
	current := ""
	if out, err := exec.CommandContext(ctx, path, "-S", "NT_MESH_FWD").Output(); err != nil {
		return fmt.Errorf("inspect private mesh forwarding rules: %w", err)
	} else {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 1 {
			switch strings.TrimSpace(lines[1]) {
			case "-A NT_MESH_FWD -j " + allowA:
				current = allowA
			case "-A NT_MESH_FWD -j " + allowB:
				current = allowB
			}
		}
	}
	next := allowA
	if current == allowA {
		next = allowB
	}
	if err := run("-S", next); err != nil {
		if err := run("-N", next); err != nil {
			return err
		}
	}
	if err := run("-F", next); err != nil {
		return err
	}
	for _, user := range s.auth.Users() {
		if user.MeshSlot == 0 {
			continue
		}
		prefix, err := store.TenantPrefix(s.store.Settings().MeshCIDR, user.MeshSlot)
		if err != nil {
			return err
		}
		cidr := prefix.String()
		for _, agent := range s.store.Agents() {
			if agent.MeshSlot != user.MeshSlot || agent.OwnerID != user.ID || !agent.Enabled {
				continue
			}
			for _, network := range s.store.CarriedPrefixes(agent.ID) {
				for _, rule := range [][]string{
					{next, "-i", iface, "-o", iface, "-s", cidr, "-d", network, "-j", "ACCEPT"},
					{next, "-i", iface, "-o", iface, "-s", network, "-d", cidr, "-j", "ACCEPT"},
				} {
					if err := run(append([]string{"-A"}, rule...)...); err != nil {
						return err
					}
				}
			}
		}
	}
	if current == "" {
		if err := run("-I", "NT_MESH_FWD", "1", "-j", next); err != nil {
			return err
		}
	} else if err := run("-R", "NT_MESH_FWD", "1", "-j", next); err != nil {
		return err
	}
	for _, user := range s.auth.Users() {
		if user.MeshSlot == 0 {
			continue
		}
		prefix, err := store.TenantPrefix(s.store.Settings().MeshCIDR, user.MeshSlot)
		if err != nil {
			return err
		}
		cidr := prefix.String()
		for _, rule := range [][]string{
			{"NT_MESH_FWD", "-i", iface, "-s", cidr, "!", "-d", cidr, "-j", "DROP"},
			{"NT_MESH_FWD", "-o", iface, "-d", cidr, "!", "-s", cidr, "-j", "DROP"},
			{"NT_MESH_IN", "-i", iface, "-s", cidr, "-j", "DROP"},
		} {
			check := append([]string{"-C"}, rule...)
			if err := run(check...); err != nil {
				add := append([]string{"-A"}, rule...)
				if err := run(add...); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
