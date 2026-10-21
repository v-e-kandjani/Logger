package version

import (
	"fmt"
	"runtime"
)

const (
	// DefaultAgentVersion represents the standalone semantic version of the native LOGGER Agent daemon.
	// This versioning is intentionally decoupled from the LogSeal platform version.
	DefaultAgentVersion = "v0.1.0"
	DefaultBuildDate    = "2026-10-21"
	DefaultCommitSHA    = "324f698"
)

var (
	// Version is the current version of the logger-agent daemon.
	Version   = DefaultAgentVersion
	BuildDate = DefaultBuildDate
	CommitSHA = DefaultCommitSHA
)

// String returns formatted agent version and runtime architecture.
func String() string {
	return fmt.Sprintf("LOGGER Agent %s (Commit: %s, Built: %s, %s/%s)",
		Version, CommitSHA, BuildDate, runtime.GOOS, runtime.GOARCH)
}

// UserAgent returns the HTTP User-Agent header string.
func UserAgent() string {
	return fmt.Sprintf("LOGGER-Agent/%s (%s; %s)", Version, runtime.GOOS, runtime.GOARCH)
}
