package control_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

func TestAgentMeshDNSCreateEditAndUniqueness(t *testing.T) {
	h := newHarness(t, true)
	admin := h.login(t)
	status, body, _ := h.api("POST", "/api/agents", map[string]any{"name": "desk", "meshDns": " Test "}, admin)
	if status != http.StatusOK {
		t.Fatalf("create: %d %s", status, body)
	}
	var created struct {
		Agent struct {
			ID      uint32 `json:"id"`
			MeshDNS string `json:"meshDns"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Agent.MeshDNS != "test" {
		t.Fatalf("create name = %q", created.Agent.MeshDNS)
	}
	if status, _, _ := h.api("POST", "/api/agents", map[string]any{"name": "desk2", "meshDns": "TEST"}, admin); status != http.StatusBadRequest {
		t.Fatalf("duplicate mesh DNS returned %d", status)
	}
	path := "/api/agents/" + strconv.FormatUint(uint64(created.Agent.ID), 10)
	if status, body, _ := h.api("PATCH", path, map[string]any{"meshDns": ""}, admin); status != http.StatusOK {
		t.Fatalf("clear name: %d %s", status, body)
	}
	if status, body, _ := h.api("GET", path, nil, admin); status != http.StatusOK || string(body) == "" {
		t.Fatalf("read after clear: %d %s", status, body)
	}
}
