package control_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/control"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// routeRecorder remembers the host commands the control node runs.
type routeRecorder struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *routeRecorder) Run(_ context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{name}, args...))
	if name == "ip" && len(args) > 1 && args[0] == "route" {
		return args[2] + " dev noobtun src 10.77.0.1", nil
	}
	return "", nil
}

func (r *routeRecorder) ran(parts ...string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := strings.Join(parts, " ")
	for _, call := range r.calls {
		if strings.Join(call, " ") == want {
			return true
		}
	}
	return false
}

// TestDiagnoseAsksForTheRouteOfTheAddressNotThePort covers the reported
// "Error: any valid prefix is expected rather than "172.18.0.1:4702"": `ip route
// get` takes an address, and the target is stored as host:port.
func TestDiagnoseAsksForTheRouteOfTheAddressNotThePort(t *testing.T) {
	recorder := &routeRecorder{}
	h := newHarnessOpts(t, true, "", func(opts *control.Options) {
		opts.Runner = wg.Runner(recorder)
	})
	admin := h.login(t)
	agent := h.enrolledAgent(t, "cassandra")
	listenPort := freePort(t)
	status, body, _ := h.api("POST", "/api/resources", resourceBody(
		"gameserver", "tcp", agent.id, h.agentAddress(t, agent.id), 4702, listenPort, nil), admin)
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

	status, body, _ = h.api("POST", "/api/diagnose", map[string]any{
		"resourceId": created.Resource.ID,
		"targetId":   created.Resource.Targets[0].ID,
	}, admin)
	if status != http.StatusOK {
		t.Fatalf("diagnose returned %d: %s", status, body)
	}
	host := h.agentAddress(t, agent.id)
	if !recorder.ran("ip", "route", "get", host) {
		t.Fatalf("the route check should ask for %q, calls: %v", host, recorder.calls)
	}
	if recorder.ran("ip", "route", "get", fmt.Sprintf("%s:4702", host)) {
		t.Fatalf("the route check must not pass a port to ip route get: %v", recorder.calls)
	}
	if strings.Contains(string(body), "valid prefix") {
		t.Fatalf("the route step should not report an iproute2 parse error: %s", body)
	}
}
