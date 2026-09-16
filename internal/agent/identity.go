package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// Identity is the agent's persistent WireGuard key pair. It lives on the agent
// machine and is never transmitted; only the public half is sent to the control
// node during enrollment.
type Identity struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	// NodeID is a stable random identifier for this install, used in logs.
	NodeID string `json:"nodeId"`
}

// LoadIdentity reads the identity from dir, creating it on first run.
func LoadIdentity(dir string) (*Identity, error) {
	path := filepath.Join(dir, "identity.json")
	raw, err := os.ReadFile(path)
	if err == nil {
		id := &Identity{}
		if err := json.Unmarshal(raw, id); err != nil {
			return nil, fmt.Errorf("agent: parse %s: %w", path, err)
		}
		if !wg.ValidKey(id.PrivateKey) {
			return nil, fmt.Errorf("agent: %s holds an invalid private key", path)
		}
		if id.NodeID == "" {
			if id.NodeID, err = randomID(); err != nil {
				return nil, err
			}
			if err := writeIdentity(path, id); err != nil {
				return nil, err
			}
		}
		return id, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	// 0755 so the machine's status file can be read (and `noobtunnel status` can
	// run) without sudo; the private key itself is written 0600 and stays root
	// only.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("agent: create state directory: %w", err)
	}
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	nodeID, err := randomID()
	if err != nil {
		return nil, err
	}
	id := &Identity{PrivateKey: kp.Private, PublicKey: kp.Public, NodeID: nodeID}
	if err := writeIdentity(path, id); err != nil {
		return nil, err
	}
	return id, nil
}

func writeIdentity(path string, id *Identity) error {
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func randomID() (string, error) {
	var b [9]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
