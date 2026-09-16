package control_test

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// TestDebugTwoAgents is a diagnostic helper: it prints goroutine stacks when
// the second agent fails to enroll.
func TestDebugTwoAgents(t *testing.T) {
	if os.Getenv("NOOBTUNNEL_TEST_STACKS") == "" {
		t.Skip("set NOOBTUNNEL_TEST_STACKS=1 to dump goroutine stacks")
	}
	h := newHarness(t, true)
	h.addAgent("dbg-one", true)
	h.addAgent("dbg-two", true)
	time.Sleep(6 * time.Second)
	t.Logf("online=%d", h.onlineCount())
	buf := make([]byte, 1<<22)
	n := runtime.Stack(buf, true)
	_, _ = os.Stdout.Write(buf[:n])
}
