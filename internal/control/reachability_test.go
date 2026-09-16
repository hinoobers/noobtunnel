package control_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

// TestConflictingAdvertisementsReachTheErrorsView covers a resource that was
// published before another agent started advertising the same network: the mesh
// can only route a network to one agent, so the resource quietly stops working.
// The operator has to hear about that in the Errors view.
func TestConflictingAdvertisementsReachTheErrorsView(t *testing.T) {
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

	// Now a second machine offers the same network, and the mesh can only route
	// it to one of them, so the resource above no longer lands on lily.
	setAdvertise(t, h, cassandra.id, "172.18.0.0/16")

	deadline := time.Now().Add(20 * time.Second)
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
		for _, entry := range view.Errors {
			seen = append(seen, entry.Message)
			if !strings.Contains(entry.Detail, "routes to cassandra") {
				continue
			}
			if entry.Source != "target" {
				t.Fatalf("the error should be attributed to the target: %+v", entry)
			}
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("the resource that lost its network was never reported, errors: %v", seen)
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
