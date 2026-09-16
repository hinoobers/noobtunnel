package control_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// TestConflictingAdvertisementsDoNotBreakAPublishedTarget is the model in one
// test: two machines both have 172.18.0.0/16, one of them ends up advertising it
// mesh-wide, and a target published through the other one still works, because
// the address is pinned to the machine the resource names.
//
// The mesh-wide claim that lost is still reported, so the operator knows the
// range itself is not shared - but the published service is not collateral.
func TestConflictingAdvertisementsDoNotBreakAPublishedTarget(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	cassandra := h.enrolledAgent(t, "cassandra")
	lily := h.enrolledAgent(t, "lily")
	setAdvertise(t, h, cassandra.id, "10.10.0.0/16")
	setAdvertise(t, h, lily.id, "172.18.0.0/16")

	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"ptero", "tcp", lily.id, "172.18.0.1", 4702, freePort(t), nil), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}

	// Now a second machine offers the same network. The mesh keeps one claim for
	// its own routing, and the published target keeps working.
	setAdvertise(t, h, cassandra.id, "172.18.0.0/16")

	deadline := time.Now().Add(15 * time.Second)
	var seen []string
	for time.Now().Before(deadline) {
		_, state, _ := h.api("GET", "/api/state", nil, admin)
		var view struct {
			Errors []struct {
				Source  string `json:"source"`
				Message string `json:"message"`
				Detail  string `json:"detail"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(state, &view); err != nil {
			t.Fatal(err)
		}
		seen = seen[:0]
		droppedClaim := false
		for _, entry := range view.Errors {
			seen = append(seen, entry.Message)
			if strings.Contains(entry.Message, "advertised network 172.18.0.0/16 is not routed") {
				droppedClaim = true
			}
			if entry.Source == "target" && strings.Contains(entry.Message, "ptero") {
				t.Fatalf("a published target must not be blamed for the range conflict: %+v", entry)
			}
		}
		if droppedClaim {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("the dropped mesh-wide claim was never reported, errors: %v", seen)
}

// setAdvertise changes what an agent offers, the way the agent itself would when
// it enrolls with a different list.
func setAdvertise(t *testing.T, h *harness, id uint32, prefixes ...string) {
	t.Helper()
	if err := h.server.Store().UpdateAgent(id, func(a *store.Agent) error {
		a.Advertise = prefixes
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestDiagnoseDoesNotBlameTheRangeAroundAPinnedTarget is the regression guard
// for the case that sent an operator hunting through captures: the range around a
// target belongs to another agent, and the target itself is fine because it is
// pinned to its own machine. The diagnosis must not report it as a routing
// problem.
func TestDiagnoseDoesNotBlameTheRangeAroundAPinnedTarget(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	// The lower id keeps a range when two agents claim it, so the one enrolled
	// first is the one that ends up carrying it.
	lily := h.enrolledAgent(t, "lily")
	cassandra := h.enrolledAgent(t, "cassandra")
	setAdvertise(t, h, lily.id, "10.10.0.0/16")
	setAdvertise(t, h, cassandra.id, "172.18.0.0/16")

	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"cassandra-wings", "tcp", cassandra.id, "172.18.0.3", 4700, freePort(t), nil), admin)
	if status != http.StatusOK {
		t.Fatalf("publishing returned %d: %s", status, body)
	}
	var created struct {
		Resource struct {
			ID      uint32 `json:"id"`
			Targets []struct {
				ID uint32 `json:"id"`
			} `json:"targets"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}

	// Now the other machine offers the same range, and the mesh keeps its claim.
	setAdvertise(t, h, lily.id, "172.18.0.0/16")

	status, body, _ = h.api("POST", "/api/diagnose", map[string]any{
		"resourceId": created.Resource.ID,
		"targetId":   created.Resource.Targets[0].ID,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("diagnose returned %d: %s", status, body)
	}
	var result struct {
		Verdict string `json:"verdict"`
		Steps   []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	sawRouting := false
	for _, step := range result.Steps {
		if step.Name != "Mesh routing" {
			continue
		}
		sawRouting = true
		if step.Status != "ok" {
			t.Fatalf("the target is pinned to its own agent, so the range around it is not a routing problem: %+v", step)
		}
		if !strings.Contains(step.Detail, "cassandra") {
			t.Fatalf("the step should say which machine carries the address: %+v", step)
		}
	}
	if !sawRouting {
		t.Fatalf("the diagnosis should say where the address is delivered: %+v", result.Steps)
	}
	// The address is delivered to the agent the resource names, whatever the
	// range around it resolves to.
	pinned := h.server.Store().PinnedHosts(cassandra.id)
	if len(pinned) != 1 || pinned[0].String() != "172.18.0.3/32" {
		t.Fatalf("the target should be pinned to cassandra, got %v", pinned)
	}
}
