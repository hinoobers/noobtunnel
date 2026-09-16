package install

import (
	"bytes"
	"strings"
	"testing"
)

func TestScriptIsPosixShell(t *testing.T) {
	raw, err := Script()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("\r\n")) {
		t.Fatal("the installer must use Unix line endings, or sh will fail on the target machine")
	}
	text := string(raw)
	if !strings.HasPrefix(text, "#!/bin/sh\n") {
		t.Fatal("the installer needs a /bin/sh shebang")
	}
	for _, want := range []string{
		"set -eu",
		"--server", "--token", "--fingerprint", "--pin", "--uninstall", "--purge",
		"wireguard-tools", "iproute2", "modprobe wireguard",
		"noobtunnel_linux_", "manifest.json", "sha256sum",
		"systemctl", "nohup",
		"NOOBTUNNEL_SERVER", "NOOBTUNNEL_TOKEN", "NOOBTUNNEL_FINGERPRINT",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("installer is missing %q", want)
		}
	}
}

func TestCertPEM(t *testing.T) {
	der := []byte{1, 2, 3, 4}
	pem := CertPEM(der)
	if !bytes.Contains(pem, []byte("BEGIN CERTIFICATE")) || !bytes.Contains(pem, []byte("END CERTIFICATE")) {
		t.Fatal("CertPEM should produce a PEM block")
	}
}
