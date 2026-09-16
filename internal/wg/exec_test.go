package wg

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// recordingRunner captures the commands the backend runs and the config file it
// hands to `wg setconf`.
type recordingRunner struct {
	calls  [][]string
	staged string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if name == "wg" && len(args) >= 3 && args[0] == "setconf" {
		if raw, err := os.ReadFile(args[2]); err == nil {
			r.staged = string(raw)
		}
	}
	return "", nil
}

// TestSyncFeedsSetConfAConfigItUnderstands covers the failure operators saw as
// "wg setconf … Line unrecognized: Address=10.77.0.2/32": the staged file must
// hold only the keys wg(8) accepts, with the address and MTU applied by `ip`
// instead.
func TestSyncFeedsSetConfAConfigItUnderstands(t *testing.T) {
	runner := &recordingRunner{}
	backend := &ExecBackend{Runner: runner, WGDir: t.TempDir()}
	cfg := Config{
		Interface: InterfaceConfig{
			PrivateKey: "PRIV", Addresses: []string{"10.77.0.2/32"}, ListenPort: 51820, MTU: 1420,
		},
		Peers: []PeerConfig{{
			PublicKey: "PUB", PresharedKey: "PSK", Endpoint: "203.0.113.9:51820",
			AllowedIPs: []string{"10.77.0.1/32"}, PersistentKeepalive: 25,
		}},
		Routes: []string{"10.77.0.1/32"},
	}
	if err := backend.Sync(context.Background(), "noobtun", cfg); err != nil {
		t.Fatal(err)
	}
	if runner.staged == "" {
		t.Fatal("no config was staged for wg setconf")
	}
	// Only keys wg(8) documents may appear.
	for _, banned := range []string{"Address", "MTU", "Table", "DNS", "PostUp", "SaveConfig"} {
		if strings.Contains(runner.staged, banned) {
			t.Errorf("the staged config has the wg-quick key %q, wg setconf rejects it:\n%s", banned, runner.staged)
		}
	}
	for _, want := range []string{"[Interface]", "PrivateKey = PRIV", "ListenPort = 51820", "[Peer]", "PublicKey = PUB", "AllowedIPs = 10.77.0.1/32"} {
		if !strings.Contains(runner.staged, want) {
			t.Errorf("the staged config is missing %q:\n%s", want, runner.staged)
		}
	}
	// The address, the MTU and the route have to be applied with ip(8) instead.
	var joined []string
	for _, call := range runner.calls {
		joined = append(joined, strings.Join(call, " "))
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		"ip -4 addr replace 10.77.0.2/32 dev noobtun",
		"ip link set dev noobtun mtu 1420 up",
		// The metric matters: with priority 0 the mesh route would take the
		// prefix away from a network this host owns (a Docker bridge on the same
		// range, for example).
		"ip route replace 10.77.0.1/32 dev noobtun metric 1000",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("expected the backend to run %q, it ran:\n%s", want, all)
		}
	}
}

// failingRunner refuses one command, which is what an install that failed once
// looks like from the backend's point of view.
type failingRunner struct {
	recordingRunner
	refuse string
}

func (r *failingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if strings.Contains(strings.Join(args, " "), r.refuse) {
		r.calls = append(r.calls, append([]string{name}, args...))
		return "boom", errors.New("command failed")
	}
	return r.recordingRunner.Run(ctx, name, args...)
}

// TestRoutesAreAlwaysReasserted covers the failure that leaves a tunnel which
// looks healthy and never answers: the mesh routes are what carry the answers
// back, and remembering them as installed was enough to leave a machine without
// them for good - a routing table rewritten by another tool, or one install that
// failed, stayed broken while the agent reported being in sync.
func TestRoutesAreAlwaysReasserted(t *testing.T) {
	runner := &recordingRunner{}
	backend := &ExecBackend{Runner: runner, WGDir: t.TempDir()}
	ctx := context.Background()
	routes := []string{"10.77.0.0/16", "10.77.0.1/32"}
	if err := backend.EnsureRoutes(ctx, "noobtun", routes); err != nil {
		t.Fatal(err)
	}
	first := countRouteReplaces(runner.calls)
	if first != 2 {
		t.Fatalf("both routes should be installed, got %d: %v", first, runner.calls)
	}
	// A second pass has to reach the kernel again, not the bookkeeping.
	if err := backend.EnsureRoutes(ctx, "noobtun", routes); err != nil {
		t.Fatal(err)
	}
	if got := countRouteReplaces(runner.calls); got != 2*first {
		t.Fatalf("the routes should be re-asserted, got %d installs: %v", got, runner.calls)
	}
}

// TestAFailedRouteInstallIsReportedAndRetried keeps the silence out: the error
// has to come back, and the next attempt must try again instead of treating the
// route as done.
func TestAFailedRouteInstallIsReportedAndRetried(t *testing.T) {
	runner := &failingRunner{refuse: "route replace 10.77.0.0/16"}
	backend := &ExecBackend{Runner: runner, WGDir: t.TempDir()}
	ctx := context.Background()
	err := backend.EnsureRoutes(ctx, "noobtun", []string{"10.77.0.0/16"})
	if err == nil {
		t.Fatal("a route that could not be installed has to be reported")
	}
	if !strings.Contains(err.Error(), "10.77.0.0/16") {
		t.Fatalf("the error should name the route: %v", err)
	}
	before := countRouteReplaces(runner.calls)
	if err := backend.EnsureRoutes(ctx, "noobtun", []string{"10.77.0.0/16"}); err == nil {
		t.Fatal("the retry should try again and fail again, not report success")
	}
	if got := countRouteReplaces(runner.calls); got != before+1 {
		t.Fatalf("the retry should issue the command again: %v", runner.calls)
	}
}

// countRouteReplaces counts the route installs the backend issued.
func countRouteReplaces(calls [][]string) int {
	n := 0
	for _, call := range calls {
		if len(call) > 3 && call[0] == "ip" && call[1] == "route" && call[2] == "replace" {
			n++
		}
	}
	return n
}

// TestRenderSetConfKeepsPeersAndKeys checks the two renderings differ only in the
// wg-quick keys.
func TestRenderSetConfKeepsPeersAndKeys(t *testing.T) {
	cfg := Config{
		Interface: InterfaceConfig{PrivateKey: "PRIV", Addresses: []string{"10.77.0.2/32"}, MTU: 1420, FwMark: 51820},
		Peers:     []PeerConfig{{PublicKey: "PUB", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	setconf := cfg.RenderSetConf()
	if strings.Contains(setconf, "Address") || strings.Contains(setconf, "MTU") {
		t.Fatalf("wg setconf config must not carry wg-quick keys:\n%s", setconf)
	}
	if !strings.Contains(setconf, "FwMark") {
		t.Fatalf("wg setconf understands FwMark and should keep it:\n%s", setconf)
	}
	wgQuick := cfg.Render()
	if !strings.Contains(wgQuick, "Address = 10.77.0.2/32") || !strings.Contains(wgQuick, "MTU = 1420") {
		t.Fatalf("the wg-quick form should keep Address and MTU:\n%s", wgQuick)
	}
	for _, want := range []string{"PrivateKey = PRIV", "[Peer]", "PublicKey = PUB", "AllowedIPs = 0.0.0.0/0"} {
		if !strings.Contains(setconf, want) || !strings.Contains(wgQuick, want) {
			t.Fatalf("both forms should contain %q (setconf:\n%s\nwg-quick:\n%s)", want, setconf, wgQuick)
		}
	}
}
