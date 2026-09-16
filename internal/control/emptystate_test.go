package control_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// TestStateSnapshotHasNoNullLists guards the bug behind "Cannot read properties
// of null (reading 'reduce')": deleting the last agent left state.agents nil,
// which marshals to null, and the UI reads it as an array. Every list in the
// snapshot must be [] even when it is empty.
func TestStateSnapshotHasNoNullLists(t *testing.T) {
	h := newHarness(t, true)
	cookies := h.login(t)

	// Enroll one agent, then delete it: exactly what an operator does to an
	// inactive machine.
	status, body, _ := h.api("POST", "/api/agents", map[string]any{"name": "last-one"}, cookies)
	if status != http.StatusOK {
		t.Fatalf("adding an agent returned %d: %s", status, body)
	}
	var created struct {
		Agent struct {
			ID uint32 `json:"id"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if status, body, _ := h.api("DELETE", "/api/agents/"+strconv.Itoa(int(created.Agent.ID)), nil, cookies); status != http.StatusOK {
		t.Fatalf("deleting the agent returned %d: %s", status, body)
	}

	status, body, _ = h.api("GET", "/api/state", nil, cookies)
	if status != http.StatusOK {
		t.Fatalf("/api/state returned %d", status)
	}
	page := string(body)
	for _, field := range []string{"agents", "events", "health", "resources", "domains", "exitNodes", "dnsProviders"} {
		if strings.Contains(page, `"`+field+`":null`) {
			t.Errorf("the snapshot has %q null, the UI expects a list:\n%s", field, page)
		}
	}
	if !strings.Contains(page, `"agents":[]`) {
		t.Errorf("a mesh with no agents should report an empty list:\n%s", page)
	}
}
