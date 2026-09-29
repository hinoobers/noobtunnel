package agent

import (
	"strings"
	"testing"
)

func TestMeshDNSHostsUpdatesOnlyItsOwnBlock(t *testing.T) {
	original := "127.0.0.1 localhost\n# custom entry\n10.0.0.4 other\n"
	first := meshDNSHostsContent(original, 5, []meshDNSRecord{{Name: "nas", Address: "10.77.1.2"}})
	if !strings.Contains(first, "10.77.1.2 nas.mesh nas\n") || !strings.Contains(first, "10.0.0.4 other") {
		t.Fatalf("mesh name missing or existing hosts changed: %q", first)
	}
	if again := meshDNSHostsContent(first, 5, []meshDNSRecord{{Name: "nas", Address: "10.77.1.2"}}); again != first {
		t.Fatal("unchanged peer set rewrote hosts")
	}
	changed := meshDNSHostsContent(first, 5, []meshDNSRecord{{Name: "desk", Address: "10.77.1.3"}})
	if strings.Contains(changed, "nas.mesh") || !strings.Contains(changed, "desk.mesh desk") {
		t.Fatalf("rename did not replace old name: %q", changed)
	}
	if cleared := meshDNSHostsContent(changed, 5, nil); cleared != original {
		t.Fatalf("clearing name changed unrelated hosts: %q", cleared)
	}
}
