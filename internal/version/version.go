// Package version holds build identification for every noobtunnel binary.
package version

// Version is the semantic version of noobtunnel. It is overridden at build time
// with -ldflags "-X github.com/noobtunnel/noobtunnel/internal/version.Version=x.y.z".
var Version = "0.1.0-dev"

// Commit and BuildDate are optional build metadata injected by the build script.
var (
	Commit    = "unknown"
	BuildDate = "unknown"
)

// UserAgent is used for outbound HTTP requests made by the CLI and agent.
func UserAgent() string { return "noobtunnel/" + Version }
