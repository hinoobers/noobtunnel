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
// same range: the mesh can only send it to one of them, so a target on the other
// would silently go to the wrong place. It is refused, with both sides named.
func TestOverlappingAdvertisementIsRefused(t *testing.T) {
	st, cassandra := resourceFixture(t)
	lily, err := st.AddAgent(AddAgentParams{Name: "lily"})
	if err != nil {
		t.Fatal(err)
	}
	advertise(t, st, cassandra.ID, "172.18.0.0/16")
	advertise(t, st, lily.ID, "172.18.0.0/16")

	_, err = st.AddResource(ResourceInput{
		Name: "ptero", Protocol: ProtocolTCP, ListenPort: 4702,
		Targets: oneTarget(cassandra.ID, "172.18.0.1", 4702),
	})
	if !errors.Is(err, ErrBadResource) {
		t.Fatalf("an ambiguous network must be refused, got %v", err)
	}
	for _, want := range []string{"lily", "drop it from one agent"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal should mention %q: %v", want, err)
		}
	}

	// With one side advertising something else, the same target works.
	advertise(t, st, lily.ID, "10.10.0.0/16")
	if _, err := st.AddResource(ResourceInput{
		Name: "ptero", Protocol: ProtocolTCP, ListenPort: 4702,
		Targets: oneTarget(cassandra.ID, "172.18.0.1", 4702),
	}); err != nil {
		t.Fatalf("the target should be allowed once the range is unambiguous: %v", err)
	}
}

// TestTheMoreSpecificAdvertisementWins matches how the kernel routes: the longest
// matching prefix decides, so a narrow claim is not blocked by a broad one.
func TestTheMoreSpecificAdvertisementWins(t *testing.T) {
	st, cassandra := resourceFixture(t)
	lily, err := st.AddAgent(AddAgentParams{Name: "lily"})
	if err != nil {
		t.Fatal(err)
	}
	advertise(t, st, cassandra.ID, "172.18.5.0/24")
	advertise(t, st, lily.ID, "172.18.0.0/16")

	if _, err := st.AddResource(ResourceInput{
		Name: "ptero", Protocol: ProtocolTCP, ListenPort: 4702,
		Targets: oneTarget(cassandra.ID, "172.18.5.7", 4702),
	}); err != nil {
		t.Fatalf("the narrower claim should win: %v", err)
	}
	// The broad claim on the other side still cannot carry a target of its own
	// inside the narrow one, because that traffic goes to cassandra.
	_, err = st.AddResource(ResourceInput{
		Name: "other", Protocol: ProtocolTCP, ListenPort: 4703,
		Targets: oneTarget(lily.ID, "172.18.5.9", 4703),
	})
	if !errors.Is(err, ErrBadResource) {
		t.Fatalf("a target behind the broader claim must be refused, got %v", err)
	}
}
