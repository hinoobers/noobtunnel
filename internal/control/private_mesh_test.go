package control_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/store"
	"github.com/noobtunnel/noobtunnel/internal/wg"
)

func TestSeparateAccountsCannotSeeOrManageEachOthersAgents(t *testing.T) {
	h := newHarness(t, false)
	admin := h.login(t)
	owner, err := h.server.Auth().AddUserWithEmail("privateowner", "", "private-password-123", store.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	if owner.MeshSlot == 0 {
		t.Fatal("new owner was placed in the existing admin mesh")
	}
	private := h.loginAs(t, owner.Username, "private-password-123")
	rootAgent, err := h.server.Store().AddAgent(store.AddAgentParams{Name: "admin-machine"})
	if err != nil {
		t.Fatal(err)
	}
	privateAgent, err := h.server.Store().AddAgent(store.AddAgentParams{Name: "private-machine", OwnerID: owner.ID, MeshSlot: owner.MeshSlot})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rootAgent.Address, "10.77.0.") || !strings.HasPrefix(privateAgent.Address, "10.77.1.") {
		t.Fatalf("agents share an address range: %s and %s", rootAgent.Address, privateAgent.Address)
	}
	if status, body, _ := h.api("GET", "/api/state", nil, private); status != http.StatusOK || strings.Contains(string(body), "admin-machine") || !strings.Contains(string(body), "private-machine") {
		t.Fatalf("private state leaked another mesh: %d %s", status, body)
	}
	if status, body, _ := h.api("GET", "/api/state", nil, admin); status != http.StatusOK || strings.Contains(string(body), "private-machine") || !strings.Contains(string(body), "admin-machine") {
		t.Fatalf("admin mesh view leaked private owner: %d %s", status, body)
	}
	if err := h.server.Store().UpdateAgent(privateAgent.ID, func(a *store.Agent) error {
		a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if status, body, _ := h.api("PATCH", "/api/exitnodes/control", map[string]any{"publicPool": true}, admin); status != http.StatusOK {
		t.Fatalf("enable public exit: %d %s", status, body)
	}
	privateResource, err := h.server.Store().AddResource(store.ResourceInput{
		OwnerID: owner.ID, MeshSlot: owner.MeshSlot, Name: "private-service",
		Protocol: store.ProtocolTCP, Targets: []store.ResourceTargetInput{{AgentID: privateAgent.ID, Host: privateAgent.Address, Port: 8080}},
		ExitNodeID: "control", ListenPort: 39541,
	})
	if err != nil {
		t.Fatal(err)
	}
	privateResourcePath := "/api/resources/" + strconv.FormatUint(uint64(privateResource.ID), 10)
	if status, body, _ := h.api("GET", "/api/state", nil, admin); status != http.StatusOK || strings.Contains(string(body), "private-service") {
		t.Fatalf("admin state exposed another account's resource: %d %s", status, body)
	}
	if status, body, _ := h.api("GET", "/api/resources", nil, admin); status != http.StatusOK || strings.Contains(string(body), "private-service") {
		t.Fatalf("admin resources exposed another account's resource: %d %s", status, body)
	}
	if status, body, _ := h.api("GET", privateResourcePath, nil, admin); status != http.StatusOK || !strings.Contains(string(body), "private-service") {
		t.Fatalf("admin resource editor lookup: %d %s", status, body)
	}
	resourceEdit := resourceBody("private-service", "tcp", privateAgent.ID, privateAgent.Address, 8080, 39541,
		map[string]any{"exitNodeId": "control", "uncapped": true, "enabled": true})
	if status, body, _ := h.api("PATCH", privateResourcePath, resourceEdit, admin); status != http.StatusOK {
		t.Fatalf("admin grant uncapped limits: %d %s", status, body)
	}
	resourceEdit["uncapped"] = false
	if status, body, _ := h.api("PATCH", privateResourcePath, resourceEdit, private); status != http.StatusOK {
		t.Fatalf("owner edit after admin limit grant: %d %s", status, body)
	}
	if updated, err := h.server.Store().Resource(privateResource.ID); err != nil || !updated.Uncapped {
		t.Fatalf("owner edit removed admin limit grant: %v %+v", err, updated)
	}
	if status, _, _ := h.api("DELETE", privateResourcePath, nil, admin); status != http.StatusNotFound {
		t.Fatalf("admin deleted another account's resource: %d", status)
	}
	if status, _, _ := h.api("GET", "/api/agents/"+strconv.FormatUint(uint64(privateAgent.ID), 10), nil, admin); status != http.StatusNotFound {
		t.Fatalf("admin read another account's agent: %d", status)
	}
	if status, _, _ := h.api("GET", "/api/agents/"+strconv.FormatUint(uint64(rootAgent.ID), 10), nil, private); status != http.StatusNotFound {
		t.Fatalf("foreign agent lookup returned %d", status)
	}
	if status, _, _ := h.api("DELETE", "/api/agents/"+strconv.FormatUint(uint64(rootAgent.ID), 10), nil, private); status != http.StatusNotFound {
		t.Fatalf("foreign agent delete returned %d", status)
	}
	if status, body, _ := h.api("GET", "/api/resources", nil, private); status != http.StatusOK || strings.Contains(string(body), "admin-machine") {
		t.Fatalf("private resource list returned %d: %s", status, body)
	}
	if status, _, _ := h.api("POST", "/api/agents", map[string]any{"name": "unsafe"}, private); status != http.StatusServiceUnavailable {
		t.Fatalf("private agent enrollment without firewall returned %d", status)
	}
	key, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.Store().UpdateAgent(rootAgent.ID, func(a *store.Agent) error { a.PublicKey = rootKey.Public; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.server.Store().UpdateAgent(privateAgent.ID, func(a *store.Agent) error { a.PublicKey = key.Public; return nil }); err != nil {
		t.Fatal(err)
	}
	privatePeer, err := h.server.Store().AddAgent(store.AddAgentParams{Name: "private-peer", OwnerID: owner.ID, MeshSlot: owner.MeshSlot})
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.Store().UpdateAgent(privatePeer.ID, func(a *store.Agent) error { a.PublicKey = peerKey.Public; return nil }); err != nil {
		t.Fatal(err)
	}
	path := "/api/agents/" + strconv.FormatUint(uint64(privateAgent.ID), 10)
	if status, body, _ := h.api("PATCH", path, map[string]any{"advertise": []string{"192.168.44.0/24"}}, private); status != http.StatusOK {
		t.Fatalf("private network advertisement returned %d: %s", status, body)
	}
	if status, _, _ := h.api("PATCH", path, map[string]any{"advertise": []string{"8.8.8.8/32"}}, private); status != http.StatusBadRequest {
		t.Fatalf("private account advertised an internet host: %d", status)
	}
	if status, _, _ := h.api("PATCH", path, map[string]any{"advertise": []string{"192.168.45.0/24"}}, admin); status != http.StatusNotFound {
		t.Fatalf("another account changed private routes: %d", status)
	}
	rootPath := "/api/agents/" + strconv.FormatUint(uint64(rootAgent.ID), 10)
	if status, body, _ := h.api("PATCH", rootPath, map[string]any{"advertise": []string{"192.168.44.0/24"}}, admin); status != http.StatusBadRequest || strings.Contains(string(body), privateAgent.Name) {
		t.Fatalf("cross-mesh route conflict returned %d or leaked the private agent name", status)
	}
	peerPreview, err := h.server.AgentConfigPreview(privatePeer.ID)
	if err != nil || !strings.Contains(peerPreview, "192.168.44.0/24") {
		t.Fatalf("private peer did not receive shared route: %v", err)
	}
	preview, err := h.server.AgentConfigPreview(privateAgent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(preview, rootAgent.Address+"/32") {
		t.Fatal("private agent configuration contains the admin agent")
	}
	if !strings.Contains(preview, "10.77.0.1/32") {
		t.Fatal("private agent has no route to its hub outside the private subnet")
	}
	if status, _, _ := h.api("DELETE", "/api/users/"+owner.ID, nil, admin); status != http.StatusOK {
		t.Fatalf("owner deletion returned %d", status)
	}
	if _, err := h.server.Store().Agent(privateAgent.ID); err == nil {
		t.Fatal("deleted account's agent remains enrolled")
	}
}
