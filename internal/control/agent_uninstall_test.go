package control_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func TestAgentUninstallRequiresItsOwnLocalToken(t *testing.T) {
	h := newHarness(t, true)
	owner := h.login(t)
	type created struct {
		Agent struct {
			ID    uint32 `json:"id"`
			Token string `json:"token"`
		} `json:"agent"`
	}
	add := func(name string) created {
		status, body, _ := h.api("POST", "/api/agents", map[string]string{"name": name}, owner)
		if status != http.StatusOK {
			t.Fatalf("create agent: %d %s", status, body)
		}
		var a created
		if err := json.Unmarshal(body, &a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	a, b := add("remove-me"), add("keep-me")
	path := fmt.Sprintf("/api/agent-uninstall/%d", a.Agent.ID)
	request := func(method, token string) int {
		req, err := http.NewRequest(method, "https://"+h.address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := h.client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if got := request("GET", a.Agent.Token); got != http.StatusMethodNotAllowed {
		t.Fatalf("GET uninstall: %d", got)
	}
	for _, token := range []string{"", b.Agent.Token, a.Agent.Token + "bad"} {
		if got := request("POST", token); got != http.StatusUnauthorized {
			t.Fatalf("wrong token: %d", got)
		}
	}
	status, body, _ := h.api("GET", fmt.Sprintf("/api/agents/%d/uninstall", a.Agent.ID), nil, owner)
	if status != http.StatusOK {
		t.Fatalf("uninstall commands: %d %s", status, body)
	}
	var commands struct {
		Method  string `json:"method"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(body, &commands); err != nil {
		t.Fatal(err)
	}
	if commands.Method != "service" || !strings.Contains(commands.Command, "install.sh") || !strings.Contains(commands.Command, " --service") || strings.Contains(commands.Command, a.Agent.Token) {
		t.Fatalf("wrong or unsafe uninstall command: %+v", commands)
	}
	if got := request("POST", a.Agent.Token); got != http.StatusOK {
		t.Fatalf("valid token: %d", got)
	}
	if got := request("POST", a.Agent.Token); got != http.StatusUnauthorized {
		t.Fatalf("reused token: %d", got)
	}
	if _, err := h.server.Store().Agent(b.Agent.ID); err != nil {
		t.Fatalf("another agent was removed: %v", err)
	}
}

func TestAgentRemovalUsesTheSelectedInstallMethod(t *testing.T) {
	h := newHarness(t, true)
	owner := h.login(t)
	for _, test := range []struct {
		method string
		want   string
	}{
		{"docker", " --docker"},
		{"windows", "install.ps1"},
		{"service", " --service"},
	} {
		status, body, _ := h.api("POST", "/api/agents?method="+test.method, map[string]string{"name": test.method}, owner)
		if status != http.StatusOK {
			t.Fatalf("create %s: %d %s", test.method, status, body)
		}
		var created struct {
			Agent struct {
				ID uint32 `json:"id"`
			} `json:"agent"`
		}
		if err := json.Unmarshal(body, &created); err != nil {
			t.Fatal(err)
		}
		path := fmt.Sprintf("/api/agents/%d/uninstall", created.Agent.ID)
		status, body, _ = h.api("GET", path, nil, owner)
		if status != http.StatusOK {
			t.Fatalf("remove %s: %d %s", test.method, status, body)
		}
		var removal struct {
			Method  string `json:"method"`
			Command string `json:"command"`
		}
		if err := json.Unmarshal(body, &removal); err != nil {
			t.Fatal(err)
		}
		if removal.Method != test.method || !strings.Contains(removal.Command, test.want) {
			t.Fatalf("%s removal: %+v", test.method, removal)
		}
	}
	legacy, err := h.server.Store().AddAgent(store.AddAgentParams{Name: "older-linux-agent"})
	if err != nil {
		t.Fatal(err)
	}
	status, body, _ := h.api("GET", fmt.Sprintf("/api/agents/%d/uninstall", legacy.ID), nil, owner)
	if status != http.StatusOK {
		t.Fatalf("legacy removal: %d %s", status, body)
	}
	var removal struct {
		Method  string `json:"method"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(body, &removal); err != nil {
		t.Fatal(err)
	}
	if removal.Method != "auto" || strings.Contains(removal.Command, " --docker") || strings.Contains(removal.Command, " --service") {
		t.Fatalf("legacy removal should detect its local installation: %+v", removal)
	}
}
