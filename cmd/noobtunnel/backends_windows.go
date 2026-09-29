//go:build windows

package main

import "github.com/noobtunnel/noobtunnel/internal/wg"

func newWindowsBackend() wg.Backend { return &wg.WindowsBackend{} }
