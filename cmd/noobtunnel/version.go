package main

import (
	"runtime"

	"github.com/noobtunnel/noobtunnel/internal/version"
)

func versionString() string   { return version.Version }
func commitString() string    { return version.Commit }
func buildDateString() string { return version.BuildDate }
func goVersion() string       { return runtime.Version() }
func goos() string            { return runtime.GOOS }
func goarch() string          { return runtime.GOARCH }
