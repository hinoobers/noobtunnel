//go:build !windows

package main

import "github.com/noobtunnel/noobtunnel/internal/agent"

func runAgentAsWindowsService(_ *agent.Agent) (bool, error) { return false, nil }
