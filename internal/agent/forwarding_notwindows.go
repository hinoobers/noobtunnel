//go:build !windows

package agent

import "context"

func (a *Agent) syncWindowsCarriedForwarding(context.Context) {}
