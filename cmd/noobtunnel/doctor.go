package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/wg"
)

type doctorResult struct {
	name   string
	status string
	detail string
}

func runDoctor(args []string) error {
	fs := newFlagSet("doctor")
	stateDir := fs.String("state-dir", env("NOOBTUNNEL_STATE_DIR", defaultStateDir()), "directory that will hold the agent identity")
	iface := fs.String("interface", env("NOOBTUNNEL_INTERFACE", "noobtun"), "WireGuard interface name that will be used")
	backendName := fs.String("backend", env("NOOBTUNNEL_BACKEND", "kernel"), "backend to test: kernel or fake")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var results []doctorResult
	results = append(results, doctorResult{
		name: "platform", status: "info",
		detail: runtime.GOOS + "/" + runtime.GOARCH + " with go " + runtime.Version(),
	})
	results = append(results, doctorResult{
		name: "interface name", status: statusFor(wg.ValidateInterfaceName(*iface) == nil),
		detail: *iface + " " + describeErr(wg.ValidateInterfaceName(*iface)),
	})

	if runtime.GOOS == "linux" {
		results = append(results,
			binaryCheck("ip", "netlink tooling used to configure the device"),
			binaryCheck("wg", "wireguard-tools for key and peer management"),
			binaryCheck("modprobe", "kernel module loader"),
			moduleCheck(),
		)
		if os.Geteuid() != 0 {
			results = append(results, doctorResult{name: "privileges", status: "fail",
				detail: "not running as root, creating a WireGuard device needs CAP_NET_ADMIN"})
		} else {
			results = append(results, doctorResult{name: "privileges", status: "ok", detail: "running as root"})
		}
	}

	results = append(results, dirCheck(*stateDir))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if strings.EqualFold(*backendName, "fake") {
		results = append(results, doctorResult{name: "backend", status: "info", detail: "fake backend selected, nothing to program"})
	} else {
		device := &wg.ExecBackend{}
		cfg := wg.Config{Interface: wg.InterfaceConfig{
			PrivateKey: wg.MustGeneratePrivateKey(),
			Addresses:  []string{"10.77.0.254/32"},
			ListenPort: 0,
			MTU:        wg.DefaultMTU,
		}}
		testIface := *iface + "test"
		err := device.Sync(ctx, testIface, cfg)
		if err != nil {
			results = append(results, doctorResult{name: "device smoke test", status: "fail", detail: err.Error()})
		} else {
			status, _ := device.Status(ctx, testIface)
			detail := "created and removed " + testIface
			if status.PublicKey != "" {
				detail += " (public key " + status.PublicKey[:12] + "…)"
			}
			results = append(results, doctorResult{name: "device smoke test", status: "ok", detail: detail})
			_ = device.Down(ctx, testIface)
		}
	}

	fmt.Printf("noobtunnel doctor\n\n")
	worst := "ok"
	for _, r := range results {
		fmt.Printf("  %-8s %-20s %s\n", r.status, r.name, r.detail)
		if r.status == "fail" {
			worst = "fail"
		} else if r.status == "warn" && worst == "ok" {
			worst = "warn"
		}
	}
	fmt.Println()
	switch worst {
	case "fail":
		fmt.Println("This machine cannot run an agent yet, fix the failing checks above.")
		return fmt.Errorf("doctor found problems")
	case "warn":
		fmt.Println("Good to go, with warnings above.")
	default:
		fmt.Println("This machine can run a noobtunnel agent.")
	}
	return nil
}

func statusFor(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

func describeErr(err error) string {
	if err == nil {
		return ""
	}
	return "— " + err.Error()
}

func binaryCheck(name, why string) doctorResult {
	path, err := exec.LookPath(name)
	if err != nil {
		return doctorResult{name: name, status: "fail", detail: "not found, " + why}
	}
	return doctorResult{name: name, status: "ok", detail: path}
}

func moduleCheck() doctorResult {
	if err := exec.Command("modprobe", "-n", "wireguard").Run(); err != nil {
		return doctorResult{name: "wireguard module", status: "warn",
			detail: "modprobe could not resolve wireguard; on some hosts it is built in or needs wireguard-dkms"}
	}
	return doctorResult{name: "wireguard module", status: "ok", detail: "loadable"}
}

func dirCheck(dir string) doctorResult {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return doctorResult{name: "state directory", status: "fail", detail: err.Error()}
	}
	probe := filepath.Join(dir, ".write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return doctorResult{name: "state directory", status: "fail", detail: err.Error()}
	}
	_ = os.Remove(probe)
	return doctorResult{name: "state directory", status: "ok", detail: dir + " is writable"}
}
