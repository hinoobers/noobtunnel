// Package install embeds the agent installer script that the control node
// serves at /install.sh.
package install

import (
	_ "embed"
	"encoding/pem"
)

//go:embed install.sh
var script []byte

// Script returns the installer script.
func Script() ([]byte, error) { return script, nil }

// CertPEM wraps a DER certificate in PEM, for /cert.pem.
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
