package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/noobtunnel/noobtunnel/internal/agent"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

func runAgent(args []string) error {
	fs := newFlagSet("agent")
	var (
		serverAddr   = fs.String("server", env("NOOBTUNNEL_SERVER", ""), "control node address, host:port")
		token        = fs.String("token", env("NOOBTUNNEL_TOKEN", ""), "enrollment token from the control node")
		fingerprint  = fs.String("fingerprint", env("NOOBTUNNEL_FINGERPRINT", ""), "control node certificate fingerprint (sha256, hex)")
		insecure     = fs.Bool("insecure", envBool("NOOBTUNNEL_INSECURE", false), "skip certificate verification (testing only)")
		iface        = fs.String("interface", env("NOOBTUNNEL_INTERFACE", "noobtun"), "WireGuard interface name")
		stateDir     = fs.String("state-dir", env("NOOBTUNNEL_STATE_DIR", defaultStateDir()), "directory for the agent identity")
		name         = fs.String("name", env("NOOBTUNNEL_NAME", ""), "name reported to the control node (defaults to the hostname)")
		advertise    = fs.String("advertise", env("NOOBTUNNEL_ADVERTISE", ""), "comma separated CIDRs this agent routes for the mesh")
		advertiseAll = fs.String("advertise-all", env("NOOBTUNNEL_ADVERTISE_ALL", "false"), "route every network this machine can reach")
		direct       = fs.String("direct", env("NOOBTUNNEL_DIRECT", "true"), "attempt direct paths to other agents (true or false)")
		keep         = fs.String("keep-interface", env("NOOBTUNNEL_KEEP_INTERFACE", "false"), "leave the WireGuard device up when the agent stops")
		backendName  = fs.String("backend", env("NOOBTUNNEL_BACKEND", "kernel"), "WireGuard backend: kernel or fake")
		logLevel     = fs.String("log-level", env("NOOBTUNNEL_LOG_LEVEL", "info"), "debug, info, warn or error")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverAddr == "" {
		return fmt.Errorf("--server is required (for example --server 203.0.113.9:8443)")
	}
	if *token == "" {
		return fmt.Errorf("--token is required, create one with the control node's Add agent button")
	}
	logger := newLogger(*logLevel)
	backend, err := buildAgentBackend(*backendName)
	if err != nil {
		return err
	}
	instance, err := agent.New(agent.Options{
		ControlEndpoint: strings.TrimSpace(*serverAddr),
		Token:           strings.TrimSpace(*token),
		Fingerprint:     strings.TrimSpace(*fingerprint),
		Insecure:        *insecure,
		Interface:       *iface,
		StateDir:        *stateDir,
		Name:            *name,
		Advertise:       parseCommaList([]string{*advertise}),
		AdvertiseAll:    isTrue(*advertiseAll),
		Direct:          isTrue(*direct),
		KeepInterface:   isTrue(*keep),
		Logger:          logger,
		Backend:         backend,
	})
	if err != nil {
		return err
	}
	logger.Info("starting noobtunnel agent",
		"control", *serverAddr,
		"interface", *iface,
		"stateDir", *stateDir,
		"publicKey", instance.Identity().PublicKey,
		"directPaths", isTrue(*direct),
		"backend", backend.Name())
	if !isTrue(*direct) {
		logger.Info("direct paths disabled, all mesh traffic will be relayed by the control node")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return instance.Run(ctx)
}

func runStatus(args []string) error {
	fs := newFlagSet("status")
	stateDir := fs.String("state-dir", env("NOOBTUNNEL_STATE_DIR", defaultStateDir()), "directory holding the agent identity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	state, err := agent.LoadRuntime(*stateDir)
	if err != nil {
		return err
	}
	fmt.Print(state.Describe())
	return nil
}

func isTrue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "":
		return true
	default:
		return false
	}
}

// buildAgentBackend selects the WireGuard implementation for an agent.
func buildAgentBackend(name string) (wg.Backend, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "kernel", "real":
		return newKernelBackend()
	case "fake", "sim", "demo":
		return newFakeAgentBackend(), nil
	default:
		return nil, fmt.Errorf("unknown backend %q (use kernel or fake)", name)
	}
}
