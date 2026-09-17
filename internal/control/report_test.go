package control_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/access"
	"github.com/noobtunnel/noobtunnel/internal/control"
	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// TestAReportDoesNotBlameTheListenersItNeverStarted covers the line that sent an
// operator looking for a web server that was not there: `noobtunnel server
// --print-info` builds a second, short-lived copy of the control node, which
// never binds the published ports, and the report then said "not listening" and
// "could not bind port 443" as if they had failed.
func TestAReportDoesNotBlameTheListenersItNeverStarted(t *testing.T) {
	dir := t.TempDir()
	server, err := control.New(control.Options{
		StateDir:      dir,
		Listen:        "127.0.0.1:0",
		Backend:       &wg.FakeBackend{Network: wg.NewFakeNetwork(), Label: "hub"},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminPassword: "correct-horse-battery-staple",
		SetupSystem:   false,
		Domain:        "tunnel.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := server.Store().AddAgent(store.AddAgentParams{Name: "homelab", Advertise: []string{"10.10.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Store().UpdateAgent(agent.ID, func(a *store.Agent) error {
		a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Store().AddResource(store.ResourceInput{
		Name: "portfolio", Protocol: store.ProtocolHTTPS, Domain: "portfolio.example.com",
		Targets: []store.ResourceTargetInput{{AgentID: agent.ID, Host: "10.10.0.5", Port: 80}},
	}); err != nil {
		t.Fatal(err)
	}

	// Run was never called, so no listener was ever started - which is exactly
	// the state a --print-info report is in.
	for _, check := range server.RunChecks(context.Background()) {
		switch check.ID {
		case "resources", "domain":
			if check.Status == "fail" {
				t.Fatalf("%s should not be reported as failed before anything was started: %+v", check.ID, check)
			}
			if !strings.Contains(check.Detail, "report") && !strings.Contains(check.Detail, "running control node") {
				t.Fatalf("%s should say why it cannot tell: %+v", check.ID, check)
			}
		}
	}
}

func TestResourceSpecsCarrySecurityControls(t *testing.T) {
	dir := t.TempDir()
	server, err := control.New(control.Options{
		StateDir: dir, Listen: "127.0.0.1:0",
		Backend:       &wg.FakeBackend{Network: wg.NewFakeNetwork(), Label: "hub"},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminPassword: "correct-horse-battery-staple", SetupSystem: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := server.Store().AddAgent(store.AddAgentParams{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Store().UpdateAgent(agent.ID, func(a *store.Agent) error {
		a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rule := access.Rule{Field: access.FieldPath, Operator: access.OpStartsWith, Values: []string{"/private"}, Action: access.ActionBlock}
	if _, err := server.Store().AddResource(store.ResourceInput{
		Name: "secured", Protocol: store.ProtocolHTTP, Domain: "secured.example.com",
		Targets:       []store.ResourceTargetInput{{AgentID: agent.ID, Host: agent.Address, Port: 8080}},
		BlockExploits: true, Rules: []access.Rule{rule},
	}); err != nil {
		t.Fatal(err)
	}
	specs := server.ResourceSpecs()
	if len(specs) != 1 || !specs[0].BlockExploits || len(specs[0].Rules) != 1 || specs[0].Rules[0].Field != access.FieldPath {
		t.Fatalf("security controls missing from proxy spec: %+v", specs)
	}
}
