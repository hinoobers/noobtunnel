package store

import (
	"errors"
	"strings"
	"testing"
)

func TestControlExitNodeAlwaysExists(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nodes := st.ExitNodes()
	if len(nodes) != 1 {
		t.Fatalf("a fresh control node should have exactly one exit node, got %d", len(nodes))
	}
	control := nodes[0]
	if control.ID != ControlExitNodeID || control.Kind != ExitNodeControl {
		t.Fatalf("the built-in node should be the control node: %+v", control)
	}
	if control.Deletable() {
		t.Fatal("the control node exit node must not be deletable")
	}
	if control.BindAddress() != "" {
		t.Fatalf("the control node binds every address, got %q", control.BindAddress())
	}
	if err := st.RemoveExitNode(ControlExitNodeID); !errors.Is(err, ErrControlExitNode) {
		t.Fatalf("removing the control node must fail, got %v", err)
	}
	if _, err := st.UpdateExitNode(ControlExitNodeID, ExitNodeInput{Name: "hacked", Address: "203.0.113.1"}); !errors.Is(err, ErrControlExitNode) {
		t.Fatalf("editing the control node must fail, got %v", err)
	}
	// It survives a restart and is not duplicated.
	if _, err := Open(st.Path()[:len(st.Path())-len("state.json")]); err != nil {
		t.Fatal(err)
	}
	if nodes := st.ExitNodes(); len(nodes) != 1 {
		t.Fatalf("the control node exit node was duplicated: %+v", nodes)
	}
}

func TestExitNodeLifecycle(t *testing.T) {
	st, agent := resourceFixture(t)
	node, err := st.AddExitNode(ExitNodeInput{
		Name: "second public ip", Kind: "address", Address: "203.0.113.44", Interface: "lo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.Kind != ExitNodeAddress || node.Address != "203.0.113.44" || !node.Enabled {
		t.Fatalf("exit node = %+v", node)
	}
	if node.BindAddress() != "203.0.113.44" {
		t.Fatalf("bind address = %q", node.BindAddress())
	}
	// Duplicates are refused.
	if _, err := st.AddExitNode(ExitNodeInput{Name: "another", Kind: "address", Address: "203.0.113.44"}); err == nil {
		t.Fatal("duplicate addresses must be rejected")
	}
	if _, err := st.AddExitNode(ExitNodeInput{Name: "second public ip", Kind: "address", Address: "203.0.113.45"}); err == nil {
		t.Fatal("duplicate names must be rejected")
	}
	// Validation.
	for _, bad := range []ExitNodeInput{
		{Name: "", Kind: "address", Address: "203.0.113.9"},
		{Name: "x", Kind: "address", Address: "not-an-ip"},
		{Name: "x", Kind: "gre", Address: "203.0.113.9"},
		{Name: "x", Kind: "control", Address: "203.0.113.9"},
	} {
		if _, err := st.AddExitNode(bad); err == nil {
			t.Fatalf("AddExitNode(%+v) should fail", bad)
		}
	}
	// A resource can be published on it, which then blocks deletion.
	resource, err := st.AddResource(ResourceInput{
		Name: "on the second ip", Protocol: ProtocolTCP, ExitNodeID: node.ID,
		Targets: oneTarget(agent.ID, agent.Address, 22), ListenPort: 2222,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveExitNode(node.ID); !errors.Is(err, ErrExitNodeInUse) {
		t.Fatalf("an exit node in use must not be deleted, got %v", err)
	}
	if err := st.RemoveResource(resource.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveExitNode(node.ID); err != nil {
		t.Fatalf("the exit node should be removable now: %v", err)
	}
}

func TestExitNodeGREValidation(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	node, err := st.AddExitNode(ExitNodeInput{
		Name: "gre carried ip", Kind: "gre",
		Address:         "203.0.113.60",
		LocalEndpoint:   "198.51.100.1",
		PeerEndpoint:    "198.51.100.2",
		LocalTunnelAddr: "10.99.0.1",
		PeerTunnelAddr:  "10.99.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.Kind != ExitNodeGRE {
		t.Fatalf("gre node = %+v", node)
	}
	// The tunnel interface and addresses are derived, not asked for.
	if !strings.HasPrefix(node.TunnelInterface, "ntgre") {
		t.Fatalf("tunnel interface should be generated, got %q", node.TunnelInterface)
	}
	if node.LocalTunnelAddr == "" || node.PeerTunnelAddr == "" {
		t.Fatalf("tunnel addresses should be allocated, got %+v", node)
	}
	if node.LocalTunnelAddr == node.PeerTunnelAddr {
		t.Fatalf("tunnel addresses must differ: %+v", node)
	}

	// A second GRE node gets its own interface and address pair.
	second, err := st.AddExitNode(ExitNodeInput{
		Name: "second gre", Kind: "gre", Address: "203.0.113.70",
		LocalEndpoint: "198.51.100.1", PeerEndpoint: "198.51.100.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.TunnelInterface == node.TunnelInterface {
		t.Fatalf("two GRE nodes must not share an interface name: %q", second.TunnelInterface)
	}
	if second.LocalTunnelAddr == node.LocalTunnelAddr {
		t.Fatalf("two GRE nodes must not share a tunnel address: %q", second.LocalTunnelAddr)
	}

	// Explicit values still win when an operator supplies them.
	custom, err := st.AddExitNode(ExitNodeInput{
		Name: "custom gre", Kind: "gre", Address: "203.0.113.80",
		LocalEndpoint: "198.51.100.1", PeerEndpoint: "198.51.100.4",
		TunnelInterface: "gre-custom", LocalTunnelAddr: "10.200.0.1", PeerTunnelAddr: "10.200.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if custom.TunnelInterface != "gre-custom" || custom.LocalTunnelAddr != "10.200.0.1" {
		t.Fatalf("explicit tunnel settings were overwritten: %+v", custom)
	}
	// Missing pieces are refused.
	_, err = st.AddExitNode(ExitNodeInput{
		Name: "incomplete", Kind: "gre", Address: "203.0.113.61",
		LocalEndpoint: "198.51.100.1",
	})
	if err == nil || !strings.Contains(err.Error(), "peer endpoint") {
		t.Fatalf("expected a peer endpoint error, got %v", err)
	}
	// The two ends must differ.
	_, err = st.AddExitNode(ExitNodeInput{
		Name: "same ends", Kind: "gre", Address: "203.0.113.62",
		LocalEndpoint: "198.51.100.1", PeerEndpoint: "198.51.100.1",
		LocalTunnelAddr: "10.99.0.1", PeerTunnelAddr: "10.99.0.2",
	})
	if err == nil {
		t.Fatal("identical tunnel endpoints must be rejected")
	}
}
