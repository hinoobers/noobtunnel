package control

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func TestWindowsInstallCommandIsCMDPasteable(t *testing.T) {
	fingerprint := strings.TrimSuffix(strings.Repeat("aa:", 32), ":")
	command := windowsInstallCommand(&store.Agent{Token: "nt_test", Name: "O'Brien & sons"}, InstallOptions{ControlEndpoint: "tunnel.byenoob.com:8443", Fingerprint: fingerprint, Pin: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12="})
	if !strings.Contains(command, "--pinnedpubkey") || !strings.Contains(command, "/install.ps1") || !strings.Contains(command, " && powershell.exe ") {
		t.Fatalf("incomplete Windows command: %s", command)
	}
	encoded := command[strings.LastIndex(command, " ")+1:]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	ps := string(utf16.Decode(units))
	if !strings.Contains(ps, "-Token 'nt_test'") || !strings.Contains(ps, "-Name 'O''Brien & sons'") || !strings.Contains(ps, "-Fingerprint '"+fingerprint+"'") {
		t.Fatalf("unsafe or missing encoded arguments: %s", ps)
	}
}
