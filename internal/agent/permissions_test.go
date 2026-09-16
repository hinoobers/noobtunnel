package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestRuntimeStateIsReadableWithoutSudo covers the annoyance of having to run
// `noobtunnel status` as root: the status file holds no secrets, so it is world
// readable and sits in a traversable directory.
func TestRuntimeStateIsReadableWithoutSudo(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadIdentity(dir); err != nil {
		t.Fatal(err)
	}
	state := &RuntimeState{Address: "10.77.0.2/32", Connected: true, Interface: "noobtun"}
	if err := writeRuntime(dir, state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(RuntimePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		// Windows emulates POSIX permission bits, Linux is where this matters.
		if got := info.Mode().Perm(); got != 0o644 {
			t.Fatalf("runtime.json mode = %o, want 644 so any user can read it", got)
		}
	}
	loaded, err := LoadRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Address != state.Address || !loaded.Connected {
		t.Fatalf("runtime state round trip = %+v", loaded)
	}
	// The directory has to be traversable for that to mean anything.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm()&0o055 == 0 {
		t.Fatalf("state directory mode = %o, want others to be able to traverse it", dirInfo.Mode().Perm())
	}
}

// TestIdentityKeepsThePrivateKeyPrivate is the other half of that decision: the
// key material must not become readable just because the status file is.
func TestIdentityKeepsThePrivateKeyPrivate(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadIdentity(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows emulates POSIX permission bits; this is checked on Linux")
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity.json mode = %o, want 600: it holds the machine's private key", got)
	}
}
