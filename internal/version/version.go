package version

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	DefaultVersion     = "v1.9.18"
	DefaultBuildDate   = "2026-10-25"
	DefaultCommitSHA   = "93181e8"
	LatestAgentVersion = "v0.1.12"
)

var (
	Version   = "v1.9.18"
	BuildDate = "2026-10-25"
	CommitSHA = "93181e8"
	Platform  = "Valtrivo LogSeal"
	Company   = "Valtrivo"
	Tagline   = "Her kayıt, zamanıyla kanıt."
	RepoOwner = "v-e-kandjani"
	RepoName  = "Logger"
	Branch    = "main"
)

// IsAgentVersionNewer returns true if target represents a higher semantic version than current.
func IsAgentVersionNewer(target, current string) bool {
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

func init() {
	ReloadRuntimeVersion()
}

// ReloadRuntimeVersion synchronizes the in-memory version, commit SHA, and build date
// from either local git repository or config/.version_info written by CLI / Web updates.
func ReloadRuntimeVersion() {
	// 1. Attempt to load runtime version overrides from .version_info if updated dynamically
	paths := []string{
		"/opt/syslog-platform/config/.version_info",
		"config/.version_info",
		"./config/.version_info",
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
				if len(parts) == 2 {
					k := strings.TrimSpace(parts[0])
					v := strings.TrimSpace(parts[1])
					switch k {
					case "COMMIT_SHA":
						if v != "" && v != "unknown" {
							CommitSHA = v
						}
					case "VERSION":
						if v != "" && v != "unknown" {
							Version = v
						}
					case "BUILD_DATE":
						if v != "" && v != "unknown" {
							BuildDate = v
						}
					}
				}
			}
			break
		}
	}

	// 2. Attempt to detect current Git commit SHA dynamically if running in a repo
	if out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		s := strings.TrimSpace(string(out))
		if s != "" && !strings.Contains(s, "fatal") && !strings.Contains(s, "error") {
			CommitSHA = s
		}
	}

	// 3. Fallbacks to prevent empty strings if compiled without ldflags or overrides
	if Version == "" || Version == "unknown" {
		Version = DefaultVersion
	}
	if BuildDate == "" || BuildDate == "unknown" {
		BuildDate = DefaultBuildDate
	}
	if CommitSHA == "" || CommitSHA == "unknown" {
		CommitSHA = DefaultCommitSHA
	}
}
