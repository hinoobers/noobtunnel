package main

import (
	"fmt"
	"runtime"

	"github.com/noobtunnel/noobtunnel/internal/wg"
)

// newKernelBackend returns the real device driver, which shells out to ip(8)
// and wg(8).
func newKernelBackend() (wg.Backend, error) {
	switch runtime.GOOS {
	case "linux":
		return &wg.ExecBackend{}, nil
	case "windows":
		return newWindowsBackend(), nil
	default:
		return nil, fmt.Errorf("the WireGuard agent does not support %s", runtime.GOOS)
	}
}

// newFakeAgentBackend returns an in-memory device for dry runs and demos.
func newFakeAgentBackend() wg.Backend {
	return &wg.FakeBackend{Label: "standalone"}
}
