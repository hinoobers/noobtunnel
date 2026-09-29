package control

import (
	"testing"
	"time"
)

func TestLoginLimiterForgetsExpiredIPs(t *testing.T) {
	l := &loginLimiter{attempts: map[string][]time.Time{}}
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !l.allow("old", now) {
			t.Fatal("old IP was blocked early")
		}
		l.fail("old", now)
	}
	if l.allow("old", now) {
		t.Fatal("ten failed attempts were not blocked")
	}
	if !l.allow("fresh", now) || len(l.attempts) != 1 {
		t.Fatal("an IP with no failures consumed limiter storage")
	}
	if !l.allow("new", now.Add(6*time.Minute)) {
		t.Fatal("new IP was blocked")
	}
	if len(l.attempts) != 0 || !l.allow("old", now.Add(6*time.Minute)) {
		t.Fatal("expired IP was retained or remained blocked")
	}
}
