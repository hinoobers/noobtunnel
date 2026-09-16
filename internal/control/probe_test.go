package control_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// TestProbeTargetsAsksTheAgent covers the half of a diagnosis the control node
// cannot run on itself: whether the service answers on the machine that hosts it.
// The answer is what separates "the service is down" from "the path to it is".
func TestProbeTargetsAsksTheAgent(t *testing.T) {
	h := newHarness(t, true)
	agent := h.enrolledAgent(t, "homelab")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := h.server.ProbeTargets(ctx, agent.id, []string{ln.Addr().String()})
	if err != nil {
		t.Fatalf("the agent should have answered a probe: %v", err)
	}
	if len(result.Results) == 0 {
		t.Fatal("the probe came back with nothing")
	}
	// The first attempt is the plain one, the one a person would do by hand.
	first := result.Results[0]
	if !first.OK {
		t.Fatalf("the agent should reach a listener on its own machine: %+v", first)
	}
	if first.LocalAddr == "" {
		t.Fatalf("the source address should come back with the result: %+v", first)
	}
	if first.Meshed {
		t.Fatalf("the first attempt is not sourced from the mesh address: %+v", first)
	}
}

// TestProbeTargetsReportsAnUnreachableOne keeps the failure useful: the agent's
// own error is what tells the operator which side of the machine is broken.
func TestProbeTargetsReportsAnUnreachableOne(t *testing.T) {
	h := newHarness(t, true)
	agent := h.enrolledAgent(t, "homelab")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := h.server.ProbeTargets(ctx, agent.id, []string{address})
	if err != nil {
		t.Fatalf("the agent should have answered a probe: %v", err)
	}
	if len(result.Results) == 0 {
		t.Fatal("the probe came back with nothing")
	}
	first := result.Results[0]
	if first.OK || first.Error == "" {
		t.Fatalf("a closed port has to come back as a failure with its reason: %+v", first)
	}
}

// TestProbeNeedsAConnectedAgent is the "old agent" case: an agent that does not
// understand the command never answers, and the diagnosis has to say so instead
// of waiting forever.
func TestProbeNeedsAConnectedAgent(t *testing.T) {
	h := newHarness(t, true)
	created, err := h.server.Store().AddAgent(store.AddAgentParams{Name: "never-enrolled"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := h.server.ProbeTargets(ctx, created.ID, []string{"10.0.0.5:4700"}); err == nil {
		t.Fatal("probing a disconnected agent should fail")
	}
}
