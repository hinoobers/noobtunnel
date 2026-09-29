package store

import "testing"

func TestMeshDNSNameAndMeshScope(t *testing.T) {
	for _, input := range []string{"-nas", "nas-", "nas.local", "localhost", "wpad", "name with spaces"} {
		if _, err := NormaliseMeshDNS(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	if name, err := NormaliseMeshDNS(" NAS "); err != nil || name != "nas" {
		t.Fatalf("normalised name = %q, %v", name, err)
	}
	st := &State{Agents: []*Agent{{ID: 1, OwnerID: "alice", MeshSlot: 1, MeshDNS: "nas"}}}
	if err := ValidateMeshDNSUnique(st, 2, "alice", 1, "NAS"); err == nil {
		t.Fatal("duplicate name in one mesh was accepted")
	}
	if err := ValidateMeshDNSUnique(st, 2, "bob", 2, "nas"); err != nil {
		t.Fatalf("separate mesh cannot reuse name: %v", err)
	}
	if err := ValidateMeshDNSUnique(st, 1, "alice", 1, "nas"); err != nil {
		t.Fatalf("self edit rejected: %v", err)
	}
}
