package agent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

type meshDNSRecord struct {
	Name    string
	Address string
}

var meshDNSHostsMu sync.Mutex

func meshDNSHostsPath() string {
	if path := os.Getenv("NOOBTUNNEL_HOSTS_FILE"); path != "" {
		return path
	}
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	if _, err := os.Stat("/run/noobtunnel/host-hosts"); err == nil {
		return "/run/noobtunnel/host-hosts"
	}
	return "/etc/hosts"
}

func (a *Agent) syncMeshDNS() {
	welcome, peers, _, _, ok := a.snapshot()
	if !ok {
		return
	}
	records := make([]meshDNSRecord, 0, len(peers)+1)
	if welcome.MeshDNS != "" {
		records = append(records, meshDNSRecord{Name: welcome.MeshDNS, Address: welcome.Address})
	}
	for _, peer := range peers {
		if peer.MeshDNS != "" {
			records = append(records, meshDNSRecord{Name: peer.MeshDNS, Address: peer.Address})
		}
	}
	if err := writeMeshDNSHosts(meshDNSHostsPath(), welcome.AgentID, records); err != nil {
		a.log.Warn("could not update mesh DNS hosts", "error", err)
	}
}

func (a *Agent) clearMeshDNS() {
	welcome, _, _, _, ok := a.snapshot()
	if !ok {
		return
	}
	if err := writeMeshDNSHosts(meshDNSHostsPath(), welcome.AgentID, nil); err != nil {
		a.log.Warn("could not remove mesh DNS hosts", "error", err)
	}
}

func writeMeshDNSHosts(path string, agentID uint32, records []meshDNSRecord) error {
	meshDNSHostsMu.Lock()
	defer meshDNSHostsMu.Unlock()
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next := meshDNSHostsContent(string(old), agentID, records)
	if next == string(old) {
		return nil
	}
	return os.WriteFile(path, []byte(next), 0644)
}

func meshDNSHostsContent(old string, agentID uint32, records []meshDNSRecord) string {
	begin := fmt.Sprintf("# noobtunnel mesh DNS %d begin", agentID)
	end := fmt.Sprintf("# noobtunnel mesh DNS %d end", agentID)
	if len(records) == 0 && !strings.Contains(old, begin) {
		return old
	}
	newline := "\n"
	if strings.Contains(old, "\r\n") {
		newline = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(old, "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines))
	inside := false
	beginSeen, endSeen := false, false
	for _, line := range lines {
		switch line {
		case begin:
			inside = true
			beginSeen = true
		case end:
			inside = false
			endSeen = true
		default:
			if !inside {
				kept = append(kept, line)
			}
		}
	}
	if beginSeen != endSeen {
		return old
	}
	text := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	if len(records) > 0 {
		if text != "" {
			text += "\n"
		}
		text += begin + "\n"
		for _, record := range records {
			if !validMeshDNSRecord(record) {
				continue
			}
			text += record.Address + " " + record.Name + ".mesh " + record.Name + "\n"
		}
		text += end
	}
	if text != "" {
		text += "\n"
	}
	return strings.ReplaceAll(text, "\n", newline)
}

func validMeshDNSRecord(record meshDNSRecord) bool {
	if len(record.Name) == 0 || len(record.Name) > 63 || strings.ContainsAny(record.Name, " \t\r\n.#") {
		return false
	}
	for i, char := range record.Name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			continue
		}
		if char != '-' || i == 0 || i == len(record.Name)-1 {
			return false
		}
	}
	address, err := netip.ParseAddr(record.Address)
	return err == nil && address.Is4()
}
