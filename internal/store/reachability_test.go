package store

import (
	"errors"
	"strings"
	"testing"
)

// advertise sets an agent's advertised networks.
func advertise(t *testing.T, st *Store, id uint32, prefixes ...string) {
	t.Helper()
	if err := st.UpdateAgent(id, func(a *Agent) error {
		a.Advertise = prefixes
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// enrolled adds another agent the way enrollment does: with a public key, which
// is what makes the hub give it a peer entry at all.
func enrolled(t *testing.T, st *Store, name string) *Agent {
	t.Helper()
	agent, err := st.AddAgent(AddAgentParams{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	key := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	if name == "cassandra" {
		key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	}
	if err := st.UpdateAgent(agent.ID, func(a *Agent) error {
		a.PublicKey = key
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	agent, _ = st.Agent(agent.ID)
	return agent
}

// TestAdvertisedNetworkGrantsAccessToItsTargets is the model in one test: the
// agent's own address always works, and a network the agent advertises for the
// mesh works for services inside it.
func TestAdvertisedNetworkGrantsAccessToItsTargets(t *testing.T) {
	st, agent := resourceFixture(t)
	advertise(t, st, agent.ID, "192.168.0.0/24")

	if _, err := st.AddResource(ResourceInput{
		Name: "web", Protocol: ProtocolTCP, ListenPort: 8080,
		Targets: oneTarget(agent.ID, "192.168.0.5", 80),
	}); err != nil {
		t.Fatalf("a service inside an advertised network should be allowed: %v", err)
	}
	// The agent's own mesh address needs no advertisement at all.
	if _, err := st.AddResource(ResourceInput{
		Name: "local", Protocol: ProtocolTCP, ListenPort: 8081,
		Targets: oneTarget(agent.ID, agent.Address, 80),
	}); err != nil {
		t.Fatalf("the agent's own address should always be allowed: %v", err)
	}
}

// TestATargetNeedsNoAdvertisement is the other half, and the point of the model:
// the address is reached by the agent that owns it, so it does not have to be
// part of anything the agent advertises. 172.18.0.5 on a machine whose list says
// nothing about 172.18.0.0/16 is still that machine's own 172.18.0.5.
func TestATargetNeedsNoAdvertisement(t *testing.T) {
	st, agent := resourceFixture(t)
	advertise(t, st, agent.ID, "172.16.0.0/16")

	if _, err := st.AddResource(ResourceInput{
		Name: "web", Protocol: ProtocolTCP, ListenPort: 8080,
		Targets: oneTarget(agent.ID, "192.168.0.5", 80),
	}); err != nil {
		t.Fatalf("a service on the agent's own network should be allowed: %v", err)
	}
	pinned := st.PinnedHosts(agent.ID)
	if len(pinned) != 1 || pinned[0].String() != "192.168.0.5/32" {
		t.Fatalf("the target should be pinned to that agent, got %v", pinned)
	}
}

// TestUnreachableAgentsAreStillRefused keeps what is left to refuse: the machine
// has to be on the mesh, and a target cannot be an address of the mesh itself.
func TestUnreachableAgentsAreStillRefused(t *testing.T) {
	st, agent := resourceFixture(t)

	_, err := st.AddResource(ResourceInput{
		Name: "overlay", Protocol: ProtocolTCP, ListenPort: 8080,
		Targets: oneTarget(agent.ID, "10.77.0.9", 80),
	})
	if !errors.Is(err, ErrBadResource) || !strings.Contains(err.Error(), "mesh range") {
		t.Fatalf("an address of the overlay is not a target: %v", err)
	}

	stranger, err := st.AddAgent(AddAgentParams{Name: "not-enrolled"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.AddResource(ResourceInput{
		Name: "early", Protocol: ProtocolTCP, ListenPort: 8081,
		Targets: oneTarget(stranger.ID, "192.168.0.5", 80),
	})
	if !errors.Is(err, ErrBadResource) || !strings.Contains(err.Error(), "has not enrolled") {
		t.Fatalf("a machine that never enrolled cannot carry a target: %v", err)
	}

	if err := st.UpdateAgent(agent.ID, func(a *Agent) error {
		a.Enabled = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = st.AddResource(ResourceInput{
		Name: "disabled", Protocol: ProtocolTCP, ListenPort: 8082,
		Targets: oneTarget(agent.ID, "192.168.0.5", 80),
	})
	if !errors.Is(err, ErrBadResource) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("a disabled agent cannot carry a target: %v", err)
	}
}

// TestTheSameRangeOnTwoMachinesIsTwoDifferentNetworks is the model an operator
// actually has: 172.18.0.1 on one machine is not 172.18.0.1 on another, and a
// target names the machine it means. Both resources have to be publishable, each
// pinned to its own agent, or the second machine's containers are unreachable by
// their own address.
func TestTheSameRangeOnTwoMachinesIsTwoDifferentNetworks(t *testing.T) {
	st, cassandra := resourceFixture(t)
	lily := enrolled(t, st, "lily")
	advertise(t, st, cassandra.ID, "172.18.0.0/16")
	advertise(t, st, lily.ID, "172.18.0.0/16")

	for _, tc := range []struct {
		name   string
		agent  *Agent
		listen int
	}{
		{"cassandra-wings", cassandra, 4700},
		{"lily-wings", lily, 4701},
	} {
		if _, err := st.AddResource(ResourceInput{
			Name: tc.name, Protocol: ProtocolTCP, ListenPort: tc.listen,
			Targets: oneTarget(tc.agent.ID, "172.18.0.1", 4700),
		}); err != nil {
			t.Fatalf("%s should be publishable through its own machine: %v", tc.name, err)
		}
	}

	// Each address is delivered to the agent that owns it, whatever the range
	// around it resolves to.
	for _, tc := range []struct {
		agent *Agent
		want  string
	}{{cassandra, "172.18.0.1/32"}, {lily, "172.18.0.1/32"}} {
		pinned := st.PinnedHosts(tc.agent.ID)
		if len(pinned) != 1 || pinned[0].String() != tc.want {
			t.Fatalf("%s should have %s pinned to it, got %v", tc.agent.Name, tc.want, pinned)
		}
	}
}

// TestANarrowerClaimIsNotNeededForATarget keeps the advertised list out of the
// way of a published target: the address is pinned by the resource, so an agent
// does not have to win a claim over the range around it.
func TestANarrowerClaimIsNotNeededForATarget(t *testing.T) {
	st, cassandra := resourceFixture(t)
	lily := enrolled(t, st, "lily")
	advertise(t, st, cassandra.ID, "172.18.0.0/16")
	advertise(t, st, lily.ID, "172.18.5.0/24")

	// lily's own 172.18.5.9 is its to publish even though cassandra advertises a
	// broader range that contains it.
	if _, err := st.AddResource(ResourceInput{
		Name: "ptero", Protocol: ProtocolTCP, ListenPort: 4703,
		Targets: oneTarget(lily.ID, "172.18.5.9", 4703),
	}); err != nil {
		t.Fatalf("the target should be pinned to the agent it names: %v", err)
	}
	pinned := st.PinnedHosts(lily.ID)
	if len(pinned) != 1 || pinned[0].String() != "172.18.5.9/32" {
		t.Fatalf("the target should be pinned to lily, got %v", pinned)
	}
}

// TestCarriedPrefixesAreWhatTheMeshRoutesThroughAnAgent is the list an agent has
// to forward for. It comes from the control node's resolution, not from what the
// agent offered, because the operator can change the list here after the machine
// enrolled - and a network the mesh routes to an agent that never opened
// forwarding for it looks exactly like a service that is down.
func TestCarriedPrefixesAreWhatTheMeshRoutesThroughAnAgent(t *testing.T) {
	st, cassandra := resourceFixture(t)
	lily := enrolled(t, st, "lily")
	advertise(t, st, cassandra.ID, "172.18.0.0/16")
	advertise(t, st, lily.ID, "172.18.0.0/16")

	if got := st.CarriedPrefixes(cassandra.ID); len(got) != 1 || got[0] != "172.18.0.0/16" {
		t.Fatalf("the agent the mesh routes the range to should carry it, got %v", got)
	}
	if got := st.CarriedPrefixes(lily.ID); len(got) != 0 {
		t.Fatalf("the agent that lost the conflict carries nothing, got %v", got)
	}

	// Once the conflict is gone, both lists are what their agents offer.
	advertise(t, st, lily.ID, "10.10.0.0/16")
	if got := st.CarriedPrefixes(lily.ID); len(got) != 1 || got[0] != "10.10.0.0/16" {
		t.Fatalf("an agent should carry what it advertises, got %v", got)
	}

	// An agent that offers nothing carries nothing.
	quiet := enrolled(t, st, "quiet")
	if got := st.CarriedPrefixes(quiet.ID); len(got) != 0 {
		t.Fatalf("an agent with no advertised networks carries nothing, got %v", got)
	}
}
