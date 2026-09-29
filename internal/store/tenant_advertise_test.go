package store

import "testing"

func TestPrivateMeshRouteScope(t *testing.T) {
	for _, prefix := range []string{"192.168.44.0/24", "10.20.0.0/16", "172.18.0.0/16", "100.64.1.0/24"} {
		if err := ValidateTenantAdvertise([]string{prefix}); err != nil {
			t.Errorf("private LAN route %s was rejected: %v", prefix, err)
		}
	}
	for _, prefix := range []string{"8.8.8.8/32", "0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12"} {
		if err := ValidateTenantAdvertise([]string{prefix}); err == nil {
			t.Errorf("unsafe private mesh route %s was accepted", prefix)
		}
	}
}
