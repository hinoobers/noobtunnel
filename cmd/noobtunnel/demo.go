package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/agent"
	"github.com/noobtunnel/noobtunnel/internal/control"
	"github.com/noobtunnel/noobtunnel/internal/ipam"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// runDemo starts the control node together with a handful of simulated agents,
// so the web UI can be explored on a single machine. It is also the basis of
// the end to end tests.
func runDemo(ctx context.Context, server *control.Server, count int, logger *slog.Logger) error {
	hub, ok := server.BackendValue().(*wg.FakeBackend)
	if !ok {
		return fmt.Errorf("--demo requires --backend fake")
	}
	settings := server.Settings()
	pool, err := ipam.New(settings.MeshCIDR)
	if err != nil {
		return err
	}
	hub.OverlayIP = pool.HubAddress().String()
	hub.PublicEndpoint = "203.0.113.1:51820"

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Run(ctx) }()

	address := waitForListener(ctx, server)
	if address == "" {
		return fmt.Errorf("the control node did not start listening")
	}
	logger.Info("demo mesh ready", "agents", count, "url", "https://"+address)

	// Reuse the agents from a previous run so restarting the demo server keeps the
	// same mesh instead of piling up new enrollments.
	existing := server.Store().Agents()
	if len(existing) > 0 {
		logger.Info("reusing the agents already in the state directory", "agents", len(existing))
	}
	names := []string{"homelab-nas", "raspberry-pi-4", "hetzner-vps", "home-router", "media-server", "backup-box"}
	for i := 0; i < count; i++ {
		var created *store.Agent
		if i < len(existing) {
			created, err = server.Store().Agent(existing[i].ID)
			if err != nil {
				return err
			}
		} else {
			created, err = server.Store().AddAgent(store.AddAgentParams{Name: demoName(names, i)})
		}
		if err != nil {
			return err
		}
		device := &wg.FakeBackend{
			Network:   hub.Network,
			Label:     fmt.Sprintf("agent-%d", created.ID),
			OverlayIP: created.Address,
		}
		device.PublicEndpoint = fmt.Sprintf("203.0.113.%d:51820", 10+created.ID)
		if count > 1 && i == count-1 {
			// Simulate an agent behind a symmetric NAT: it can only be reached
			// through the control node.
			device.PublicEndpoint = ""
			device.NoPublicEndpoint = true
		}
		stateDir, err := os.MkdirTemp("", fmt.Sprintf("noobtunnel-demo-%d-", created.ID))
		if err != nil {
			return err
		}
		instance, err := agent.New(agent.Options{
			ControlEndpoint: address,
			Token:           created.Token,
			Fingerprint:     server.Cert().Fingerprint,
			Interface:       settings.Interface,
			StateDir:        stateDir,
			Name:            created.Name,
			Direct:          settings.DirectPaths,
			KeepInterface:   true,
			Logger:          logger.With("agent", created.Name),
			Backend:         device,
		})
		if err != nil {
			return err
		}
		go func(inst *agent.Agent, dir string) {
			if err := inst.Run(ctx); err != nil && !strings.Contains(err.Error(), "context canceled") {
				logger.Warn("demo agent stopped", "error", err)
			}
			_ = os.RemoveAll(dir)
		}(instance, stateDir)
		go simulateTraffic(ctx, device)
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-serverErr:
		return err
	}
}

func demoName(names []string, index int) string {
	if index < len(names) {
		return names[index]
	}
	return fmt.Sprintf("agent-%d", index+1)
}

// simulateTraffic keeps the UI's counters moving.
func simulateTraffic(ctx context.Context, device *wg.FakeBackend) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			device.SimulateRandomTraffic()
		}
	}
}

// waitForListener waits until the control node accepts connections.
func waitForListener(ctx context.Context, server *control.Server) string {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ""
		}
		address := server.Addr()
		if host, port, err := net.SplitHostPort(address); err == nil && port != "" {
			if host == "" || host == "::" || host == "0.0.0.0" {
				host = "127.0.0.1"
			}
			target := net.JoinHostPort(host, port)
			conn, err := net.DialTimeout("tcp", target, 400*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return target
			}
		}
		time.Sleep(120 * time.Millisecond)
	}
	return ""
}
