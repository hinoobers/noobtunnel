package main

import (
	"fmt"
	"runtime"

	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// newKernelBackend returns the real device driver, which shells out to ip(8)
// and wg(8).
func newKernelBackend() (wg.Backend, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("the WireGuard agent needs Linux (this host is %s); use --backend fake to dry run", runtime.GOOS)
	}
	return &wg.ExecBackend{}, nil
}

// newFakeAgentBackend returns an in-memory device for dry runs and demos.
func newFakeAgentBackend() wg.Backend {
	return &wg.FakeBackend{Label: "standalone"}
}
