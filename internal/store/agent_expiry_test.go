package store

import (
	"testing"
	"time"
)

func TestAgentEnrollmentExpiry(t *testing.T) {
	created := time.Now().UTC()
	expires := created.Add(15 * time.Minute)
	agent := &Agent{ExpiresAt: &expires}
	if agent.Expired(expires.Add(-time.Nanosecond)) {
		t.Fatal("unclaimed agent expired before its deadline")
	}
	if !agent.Expired(expires) {
		t.Fatal("unclaimed agent remained valid at its deadline")
	}
	agent.EnrolledAt = &created
	if agent.Expired(expires.Add(time.Hour)) {
		t.Fatal("claimed agent expired after its enrollment deadline")
	}
}
