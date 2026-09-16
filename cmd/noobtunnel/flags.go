package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// env returns an environment variable with a fallback, so systemd can supply
// configuration through EnvironmentFile.
func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

// envInt is env for numeric settings; a value that is not a number is ignored
// so a typo in the environment file cannot silently change a default.
func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "noobtunnel")
		}
		return filepath.Join(os.TempDir(), "noobtunnel")
	}
	return "/var/lib/noobtunnel"
}

func defaultBinaryDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

// newLogger builds a structured logger for the CLI.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// newFlagSet creates a FlagSet that reports errors instead of exiting.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func parseCommaList(values []string) []string {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func fatalIf(err error, format string, args ...any) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, format+": %v\n", append(args, err)...)
	os.Exit(1)
}

// isFlagProvided reports whether the user passed a flag explicitly, so defaults
// can differ from a flag's zero value.
func isFlagProvided(args []string, name string) bool {
	for _, arg := range args {
		trimmed := strings.TrimLeft(arg, "-")
		if trimmed == name || strings.HasPrefix(trimmed, name+"=") {
			return true
		}
	}
	return false
}
