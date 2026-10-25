package version

import (
	"fmt"
	"runtime"
	"strings"
)

const (
	// DefaultAgentVersion represents the standalone semantic version of the native LOGGER Agent daemon.
	// This versioning is intentionally decoupled from the LogSeal platform version.
	DefaultAgentVersion = "v0.1.12"
	DefaultBuildDate    = "2026-10-25"
	DefaultCommitSHA    = "077b73a"
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

// IsNewer returns true if target represents a higher semantic version than current.
func IsNewer(target, current string) bool {
	tNorm := strings.TrimPrefix(strings.TrimSpace(target), "v")
	cNorm := strings.TrimPrefix(strings.TrimSpace(current), "v")
	if tNorm == "" || cNorm == "" || tNorm == cNorm {
		return false
	}
	tParts := strings.Split(tNorm, ".")
	cParts := strings.Split(cNorm, ".")
	maxLen := len(tParts)
	if len(cParts) > maxLen {
		maxLen = len(cParts)
	}
	for i := 0; i < maxLen; i++ {
		var tVal, cVal int
		if i < len(tParts) {
			_, _ = fmt.Sscanf(tParts[i], "%d", &tVal)
		}
		if i < len(cParts) {
			_, _ = fmt.Sscanf(cParts[i], "%d", &cVal)
		}
		if tVal > cVal {
			return true
		}
		if tVal < cVal {
			return false
		}
	}
	return false
}
