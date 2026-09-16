package wg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Runner executes an external command. It exists so tests can intercept calls.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// ExecRunner runs real processes.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// ExecBackend drives the kernel WireGuard implementation through wg(8) and ip(8).
type ExecBackend struct {
	Runner Runner
	// WGDir is where temporary config files are staged before `wg setconf`.
	WGDir string

	mu     sync.Mutex
	routes map[string]map[string]bool
}

// Name implements Backend.
func (b *ExecBackend) Name() string { return "kernel" }

func (b *ExecBackend) runner() Runner {
	if b.Runner != nil {
		return b.Runner
	}
	return ExecRunner{}
}

func (b *ExecBackend) dir() string {
	if b.WGDir != "" {
		return b.WGDir
	}
	return os.TempDir()
}

// Sync implements Backend.
func (b *ExecBackend) Sync(ctx context.Context, iface string, cfg Config) error {
	if err := ValidateInterfaceName(iface); err != nil {
		return err
	}
	if err := b.ensureInterface(ctx, iface, cfg.Interface); err != nil {
		return err
	}
	if err := b.setConf(ctx, iface, cfg); err != nil {
		return err
	}
	return b.syncRoutes(ctx, iface, cfg.Routes)
}

// ValidateInterfaceName rejects names the kernel would refuse anyway.
func ValidateInterfaceName(name string) error {
	if name == "" {
		return errors.New("wg: interface name must not be empty")
	}
	if len(name) > 15 {
		return fmt.Errorf("wg: interface name %q is longer than 15 characters", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
		default:
			return fmt.Errorf("wg: interface name %q contains an invalid character %q", name, r)
		}
	}
	return nil
}

func (b *ExecBackend) ensureInterface(ctx context.Context, iface string, ic InterfaceConfig) error {
	run := b.runner()
	if _, err := run.Run(ctx, "ip", "link", "show", "dev", iface); err != nil {
		if _, err := run.Run(ctx, "ip", "link", "add", "dev", iface, "type", "wireguard"); err != nil {
			return fmt.Errorf("%w (is the wireguard kernel module available, and are you root?)", err)
		}
	}
	for _, addr := range ic.Addresses {
		if _, err := run.Run(ctx, "ip", "-4", "addr", "replace", addr, "dev", iface); err != nil {
			return err
		}
	}
	mtu := ic.MTU
	if mtu == 0 {
		mtu = 1420
	}
	if _, err := run.Run(ctx, "ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	return nil
}

func (b *ExecBackend) setConf(ctx context.Context, iface string, cfg Config) error {
	tmp, err := os.CreateTemp(b.dir(), "noobtunnel-*.conf")
	if err != nil {
		return fmt.Errorf("wg: stage config: %w", err)
	}
	path := tmp.Name()
	defer func() { _ = os.Remove(path) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	// wg(8) only understands the keys it documents: Address and MTU are wg-quick
	// extensions and make setconf fail with "Line unrecognized", so the kernel
	// backend renders them out and applies both with `ip` in ensureInterface.
	if _, err := tmp.WriteString(cfg.RenderSetConf()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := b.runner().Run(ctx, "wg", "setconf", iface, path); err != nil {
		return fmt.Errorf("%w (is wireguard-tools installed?)", err)
	}
	return nil
}

// tunnelRouteMetric is how mesh routes are installed in the main table. A high
// metric means the mesh route is only used when nothing else claims the prefix:
// a host that runs Docker (or any other network) on the same private range keeps
// its own route, and the mesh route never blocks the bridge from being created.
//
// The alternative - installing the mesh route with metric 0 - is what makes
// "install the agent and the machine's other networks break": the kernel then
// prefers the tunnel for a prefix the host itself owns.
const tunnelRouteMetric = "1000"

// syncRoutes installs the desired routes and removes ones we installed before.
func (b *ExecBackend) syncRoutes(ctx context.Context, iface string, desired []string) error {
	run := b.runner()
	want := make(map[string]bool, len(desired))
	for _, r := range desired {
		if r = strings.TrimSpace(r); r != "" {
			want[r] = true
		}
	}

	b.mu.Lock()
	prev := b.routes[iface]
	if b.routes == nil {
		b.routes = map[string]map[string]bool{}
	}
	b.routes[iface] = want
	b.mu.Unlock()

	var problems []string
	for r := range want {
		// Clear anything older for this prefix *before* installing: a route from an
		// older build has no metric, and deleting after adding is how a route gets
		// removed in the same breath as it is added - the install reports success,
		// the table has nothing, and the tunnel answers out of the default
		// gateway. Deleting first is order-safe, and the read-back below confirms
		// the result either way.
		// One `ip route del` removes one route, so clear duplicates left by older
		// builds (they installed the same prefix with no metric) before adding
		// ours, or the lower priority wins and the tunnel is bypassed anyway.
		for attempts := 0; attempts < 3; attempts++ {
			if _, err := run.Run(ctx, "ip", "route", "del", r, "dev", iface); err != nil {
				break
			}
		}
		if _, err := run.Run(ctx, "ip", "route", "replace", r, "dev", iface, "metric", tunnelRouteMetric); err != nil {
			problems = append(problems, "ip route replace "+r+" dev "+iface+" metric "+tunnelRouteMetric+": "+err.Error())
			continue
		}
	}
	for r := range prev {
		if want[r] {
			continue
		}
		// A missing route is fine; the prefix may never have been installed.
		if _, err := run.Run(ctx, "ip", "route", "del", r, "dev", iface, "metric", tunnelRouteMetric); err != nil {
			// A route from an older version has no metric.
			if _, fallback := run.Run(ctx, "ip", "route", "del", r, "dev", iface); fallback != nil {
				continue
			}
		}
	}
	// Read the table back. An install that returned success is not proof the
	// route is there, and a route that never lands is invisible everywhere else:
	// the tunnel still handshakes, the service still answers on its own machine,
	// and every reply goes out of the default gateway. Saying so is the only way
	// this failure gets noticed from the outside.
	if len(want) > 0 {
		if out, err := run.Run(ctx, "ip", "-4", "route", "show"); err == nil {
			for r := range want {
				if !routePresent(out, r, iface) {
					problems = append(problems, "the kernel has no route for "+r+" dev "+iface+
						" after installing it (this process reads: "+tablePeek(out)+")")
				}
			}
		} else {
			problems = append(problems, "could not read the routing table back: "+err.Error())
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("routes for %s: %s", iface, strings.Join(problems, "; "))
	}
	return nil
}

// tablePeek keeps an error message readable: a few lines of the routing table
// are enough to see whether the read happened at all, and what it found.
func tablePeek(table string) string {
	lines := strings.Split(strings.TrimSpace(table), "\n")
	const shown = 4
	if len(lines) > shown {
		lines = append(lines[:shown], "…")
	}
	if len(lines) == 1 && lines[0] == "" {
		return "nothing"
	}
	return strings.Join(lines, " | ")
}

// routePresent reports whether a prefix is in a `ip route show` listing for an
// interface.
func routePresent(table, prefix, iface string) bool {
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != prefix {
			continue
		}
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) && fields[i+1] == iface {
				return true
			}
		}
	}
	return false
}

// EnsureRoutes re-asserts the kernel routes for an interface without touching the
// device itself, so a long-running agent can repair a routing table that changed
// underneath it.
func (b *ExecBackend) EnsureRoutes(ctx context.Context, iface string, routes []string) error {
	if err := ValidateInterfaceName(iface); err != nil {
		return err
	}
	return b.syncRoutes(ctx, iface, routes)
}

// Status implements Backend.
func (b *ExecBackend) Status(ctx context.Context, iface string) (InterfaceStatus, error) {
	run := b.runner()
	status := InterfaceStatus{Name: iface}
	out, err := run.Run(ctx, "wg", "show", iface, "dump")
	if err != nil {
		if isMissingInterface(err) {
			return status, nil
		}
		return status, err
	}
	dump, err := ParseDump(out)
	if err != nil {
		if errors.Is(err, ErrEmptyDump) {
			return status, nil
		}
		return status, err
	}
	status.Exists = true
	status.PublicKey = dump.PublicKey
	status.ListenPort = dump.ListenPort
	for _, p := range dump.Peers {
		status.Peers = append(status.Peers, PeerStatus{
			PublicKey:           p.PublicKey,
			Endpoint:            p.Endpoint,
			AllowedIPs:          p.AllowedIPs,
			LatestHandshake:     p.LatestHandshake,
			RxBytes:             p.RxBytes,
			TxBytes:             p.TxBytes,
			PersistentKeepalive: p.PersistentKeepalive,
			HasPresharedKey:     p.PresharedKey != "",
		})
	}
	if out, err := run.Run(ctx, "ip", "-4", "-o", "addr", "show", "dev", iface); err == nil {
		status.Addresses = parseAddresses(out)
	}
	if out, err := run.Run(ctx, "ip", "-o", "link", "show", "dev", iface); err == nil {
		status.MTU = parseMTU(out)
	}
	return status, nil
}

// Down implements Backend.
func (b *ExecBackend) Down(ctx context.Context, iface string) error {
	b.mu.Lock()
	delete(b.routes, iface)
	b.mu.Unlock()
	if _, err := b.runner().Run(ctx, "ip", "link", "del", "dev", iface); err != nil {
		if isMissingInterface(err) {
			return nil
		}
		return err
	}
	return nil
}

func isMissingInterface(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "Cannot find device") ||
		strings.Contains(msg, "No such device") ||
		strings.Contains(msg, "not found")
}

func parseAddresses(ipOut string) []string {
	var out []string
	for _, line := range strings.Split(ipOut, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				out = append(out, fields[i+1])
			}
		}
	}
	return out
}

func parseMTU(linkOut string) int {
	fields := strings.Fields(linkOut)
	for i, f := range fields {
		if f == "mtu" && i+1 < len(fields) {
			n, err := strconv.Atoi(fields[i+1])
			if err == nil {
				return n
			}
		}
	}
	return 0
}

// ConfPath returns the conventional wg-quick path for an interface.
func ConfPath(iface string) string {
	return filepath.Join("/etc/wireguard", iface+".conf")
}
