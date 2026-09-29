package agent

import (
	"testing"

	"github.com/noobtunnel/noobtunnel/internal/wg"
)

func TestConnectionStateIsWrittenWhenAgentConnects(t *testing.T) {
	a := &Agent{opts: Options{StateDir: t.TempDir(), Interface: "noobtun"}, backend: &wg.FakeBackend{}}
	a.setConnected(true)
	runtime, err := LoadRuntime(a.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.Connected {
		t.Fatal("runtime still says disconnected after the control channel connected")
	}
	a.setConnected(false)
	runtime, err = LoadRuntime(a.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Connected {
		t.Fatal("runtime still says connected after the control channel closed")
	}
}
