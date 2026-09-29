package store

import (
	"errors"
	"strings"
)

// NormaliseMeshDNS validates an optional short hostname advertised in one mesh.
func NormaliseMeshDNS(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return "", nil
	}
	if len(name) > 63 || name == "localhost" || name == "wpad" {
		return "", errors.New("mesh DNS must be a hostname of up to 63 letters, numbers or hyphens")
	}
	for i, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			continue
		}
		if char != '-' || i == 0 || i == len(name)-1 {
			return "", errors.New("mesh DNS must be a hostname of up to 63 letters, numbers or hyphens")
		}
	}
	return name, nil
}

// ValidateMeshDNSUnique allows the same short name in separate account meshes.
func ValidateMeshDNSUnique(st *State, selfID uint32, ownerID string, meshSlot uint16, name string) error {
	if name == "" {
		return nil
	}
	for _, agent := range st.Agents {
		if agent.ID != selfID && agent.MeshSlot == meshSlot && agent.OwnerID == ownerID && strings.EqualFold(agent.MeshDNS, name) {
			return errors.New("another agent in this mesh already uses that mesh DNS name")
		}
	}
	return nil
}
