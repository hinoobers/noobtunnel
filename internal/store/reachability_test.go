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

// TestUnadvertisedNetworkIsRefused is the other half: if the mesh has no way to
// reach that network through this agent, the target is refused instead of failing
// mysteriously later.
func TestUnadvertisedNetworkIsRefused(t *testing.T) {
	st, agent := resourceFixture(t)
	advertise(t, st, agent.ID, "172.16.0.0/16")

	_, err := st.AddResource(ResourceInput{
		Name: "web", Protocol: ProtocolTCP, ListenPort: 8080,
		Targets: oneTarget(agent.ID, "192.168.0.5", 80),
	})
	if !errors.Is(err, ErrBadResource) {
		t.Fatalf("a service outside the advertised networks must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "advertises 172.16.0.0/16") {
		t.Fatalf("the refusal should say what the agent does advertise: %v", err)
	}
}

// TestOverlappingAdvertisementIsRefused covers two machines that both offer the
// same range. Exactly one of them can carry it, so the target on the other is
// refused and the refusal names the agent the mesh actually routes to.
func TestOverlappingAdvertisementIsRefused(t *testing.T) {
	st, cassandra := resourceFixture(t)
	lily := enrolled(t, st, "lily")
	advertise(t, st, cassandra.ID, "172.18.0.0/16")
	advertise(t, st, lily.ID, "172.18.0.0/16")

	// The range is routed to one of the two, and that one keeps working: a
	// target on the losing agent is what breaks, and it is what gets reported.
	_, err := st.AddResource(ResourceInput{
		Name: "ptero-lily", Protocol: ProtocolTCP, ListenPort: 4702,
		Targets: oneTarget(lily.ID, "172.18.0.1", 4702),
	})
	if !errors.Is(err, ErrBadResource) {
		t.Fatalf("an ambiguous network must be refused, got %v", err)
	}
	for _, want := range []string{cassandra.Name, "one of them"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal should mention %q: %v", want, err)
		}
	}

	// Once only one agent offers the range, both sides stop complaining.
	advertise(t, st, lily.ID, "10.10.0.0/16")
	if _, err := st.AddResource(ResourceInput{
		Name: "ptero", Protocol: ProtocolTCP, ListenPort: 4702,
		Targets: oneTarget(cassandra.ID, "172.18.0.1", 4702),
	}); err != nil {
		t.Fatalf("the target should be allowed once the range is unambiguous: %v", err)
	}
}

// TestANarrowerClaimDoesNotCarveOutSomeoneElsesRange pins the rule that decides
// overlaps. A network is routed to exactly one agent - that is what keeps the
// relay fallback working on every node - so a /24 inside another agent's /16 is
// not a carve out: the range stays with the agent that claimed it first, and the
// other agent's target is refused with an explanation.
func TestANarrowerClaimDoesNotCarveOutSomeoneElsesRange(t *testing.T) {
	st, cassandra := resourceFixture(t)
	lily := enrolled(t, st, "lily")
	advertise(t, st, cassandra.ID, "172.18.0.0/16")
	advertise(t, st, lily.ID, "172.18.5.0/24")
	_, err := st.AddResource(ResourceInput{
		Name: "other", Protocol: ProtocolTCP, ListenPort: 4703,
		Targets: oneTarget(lily.ID, "172.18.5.9", 4703),
	})
	if !errors.Is(err, ErrBadResource) {
		t.Fatalf("a target inside another agent's range must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), cassandra.Name) {
		t.Fatalf("the refusal should name the agent that carries the range: %v", err)
	}
	// The agent that carries the range can still publish a service inside it.
	if _, err := st.AddResource(ResourceInput{
		Name: "ptero", Protocol: ProtocolTCP, ListenPort: 4702,
		Targets: oneTarget(cassandra.ID, "172.18.5.7", 4702),
	}); err != nil {
		t.Fatalf("the carrier should be allowed to publish inside its own range: %v", err)
	}
}
