package store

import (
	"errors"
	"testing"
)

func TestWildcardPublicPoolKeepsTenantHostnamesSeparate(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.AddAgent(AddAgentParams{Name: "first", OwnerID: "account-a", MeshSlot: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.AddAgent(AddAgentParams{Name: "second", OwnerID: "account-b", MeshSlot: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint32{first.ID, second.ID} {
		if err := st.UpdateAgent(id, func(a *Agent) error { a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	node := st.ExitNodes()[0]
	if _, err := st.UpdateExitNode(node.ID, ExitNodeInput{PublicPool: boolPointer(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddDomainWithOptions("*.test.byenoob.com", "", true); err != nil {
		t.Fatal(err)
	}
	firstResource, err := st.AddResource(ResourceInput{OwnerID: "account-a", MeshSlot: 1, Name: "first", Protocol: ProtocolHTTPS, Targets: oneTarget(first.ID, first.Address, 8080), Domain: "alice.test.byenoob.com", MonthlyQuotaBytes: 1, MonthlyRequestQuota: 1, SustainedBps: 999_000_000, BurstBps: 999_000_000, PeakBps: 999_000_000, OverQuotaBps: 999_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if firstResource.MonthlyQuotaBytes != 100_000_000_000 || firstResource.MonthlyRequestQuota != 3_000_000 || firstResource.SustainedBps != 15_000_000 || firstResource.BurstBps != 30_000_000 || firstResource.PeakBps != 100_000_000 || firstResource.OverQuotaBps != 512_000 {
		t.Fatalf("web defaults: %+v", firstResource)
	}
	if _, err := st.AddResource(ResourceInput{OwnerID: "account-b", MeshSlot: 2, Name: "duplicate", Protocol: ProtocolHTTPS, Targets: oneTarget(second.ID, second.Address, 8080), Domain: "alice.test.byenoob.com"}); !errors.Is(err, ErrDomainInUse) {
		t.Fatalf("duplicate public hostname: %v", err)
	}
	if _, err := st.AddResource(ResourceInput{OwnerID: "account-b", MeshSlot: 2, Name: "other protocol", Protocol: ProtocolHTTP, Targets: oneTarget(second.ID, second.Address, 8080), Domain: "alice.test.byenoob.com"}); !errors.Is(err, ErrDomainInUse) {
		t.Fatalf("another account claimed the same hostname on HTTP: %v", err)
	}
	if _, err := st.AddResource(ResourceInput{OwnerID: "account-b", MeshSlot: 2, Name: "second", Protocol: ProtocolHTTPS, Targets: oneTarget(second.ID, second.Address, 8080), Domain: "bob.test.byenoob.com"}); err != nil {
		t.Fatal(err)
	}
	extra, err := st.AddExitNode(ExitNodeInput{Name: "alternate", Kind: string(ExitNodeAddress), Address: "203.0.113.44", Interface: "eth0", PublicPool: boolPointer(true)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddResource(ResourceInput{OwnerID: "account-b", MeshSlot: 2, Name: "third", Protocol: ProtocolHTTPS, Targets: oneTarget(second.ID, second.Address, 8080), Domain: "charlie.test.byenoob.com", ExitNodeID: extra.ID}); err == nil {
		t.Fatal("one wildcard was split across exit nodes")
	}
	if _, err := st.AddDomainWithOptions("bob.test.byenoob.com", "account-b", false); err == nil {
		t.Fatal("public pool hostname could be claimed as a private domain")
	}
	if _, err := st.SetDomainPublicPool("test.byenoob.com", false); err != nil {
		t.Fatal(err)
	}
	for _, resource := range st.Resources() {
		if resource.Enabled {
			t.Fatalf("withdrawn pool left %s published", resource.Name)
		}
	}
}

func TestRegularRawTransportLimitsCannotBeOverridden(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	agent, err := st.AddAgent(AddAgentParams{Name: "private", OwnerID: "account-a", MeshSlot: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAgent(agent.ID, func(a *Agent) error { a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; return nil }); err != nil {
		t.Fatal(err)
	}
	node := st.ExitNodes()[0]
	if _, err := st.UpdateExitNode(node.ID, ExitNodeInput{PublicPool: boolPointer(true)}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		protocol                      Protocol
		quota, sustained, burst, over uint64
		port                          int
	}{
		{ProtocolTCP, 250_000_000_000, 5_000_000, 30_000_000, 1_000_000, 24001},
		{ProtocolUDP, 100_000_000_000, 3_000_000, 20_000_000, 512_000, 24002},
	} {
		resource, err := st.AddResource(ResourceInput{OwnerID: "account-a", MeshSlot: 1, Name: string(tc.protocol), Protocol: tc.protocol, Targets: oneTarget(agent.ID, agent.Address, 8080), ListenPort: tc.port, MonthlyQuotaBytes: 1, SustainedBps: 999_000_000, BurstBps: 999_000_000, OverQuotaBps: 999_000_000})
		if err != nil {
			t.Fatal(err)
		}
		if resource.MonthlyQuotaBytes != tc.quota || resource.SustainedBps != tc.sustained || resource.BurstBps != tc.burst || resource.OverQuotaBps != tc.over {
			t.Fatalf("%s limits: %+v", tc.protocol, resource)
		}
	}
}

func TestExistingWebResourceGetsMonthlyLimitsOnOpen(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := st.AddAgent(AddAgentParams{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAgent(agent.ID, func(a *Agent) error { a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; return nil }); err != nil {
		t.Fatal(err)
	}
	resource, err := st.AddResource(ResourceInput{Name: "web", Protocol: ProtocolHTTP, Targets: oneTarget(agent.ID, agent.Address, 8080), ListenPort: 80, Domain: "web.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(state *State) error {
		for _, current := range state.Resources {
			if current.ID == resource.ID {
				current.MonthlyQuotaBytes, current.MonthlyRequestQuota = 0, 0
				current.SustainedBps, current.BurstBps, current.PeakBps, current.OverQuotaBps = 0, 0, 0, 0
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := reopened.Resource(resource.ID)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.MonthlyQuotaBytes != 100_000_000_000 || migrated.MonthlyRequestQuota != 3_000_000 || migrated.PeakBps != 100_000_000 {
		t.Fatalf("existing web limits were not applied: %+v", migrated)
	}
}

func TestAdminCanChooseWebLimits(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	agent, err := st.AddAgent(AddAgentParams{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAgent(agent.ID, func(a *Agent) error { a.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; return nil }); err != nil {
		t.Fatal(err)
	}
	resource, err := st.AddResource(ResourceInput{
		Name: "custom", Protocol: ProtocolHTTPS, Targets: oneTarget(agent.ID, agent.Address, 8080), Domain: "custom.example.com",
		MonthlyQuotaBytes: 50_000_000_000, MonthlyRequestQuota: 2_000_000,
		SustainedBps: 10_000_000, BurstBps: 20_000_000, PeakBps: 40_000_000, OverQuotaBps: 256_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resource.MonthlyQuotaBytes != 50_000_000_000 || resource.MonthlyRequestQuota != 2_000_000 || resource.SustainedBps != 10_000_000 || resource.BurstBps != 20_000_000 || resource.PeakBps != 40_000_000 || resource.OverQuotaBps != 256_000 {
		t.Fatalf("admin limits were ignored: %+v", resource)
	}
}

func boolPointer(value bool) *bool { return &value }
