package version

import (
	"os"
	"os/exec"
	"strings"
)

const (
	DefaultVersion   = "v1.8.2"
	DefaultBuildDate = "2026-10-22"
	DefaultCommitSHA = "d61a08f"
)

var (
	Version   = "v1.8.2"
	BuildDate = "2026-10-22"
	CommitSHA = "d61a08f"
	Platform  = "Valtrivo LogSeal"
	Company   = "Valtrivo"
	Tagline   = "Her kayıt, zamanıyla kanıt."
	RepoOwner = "v-e-kandjani"
	RepoName  = "Logger"
	Branch    = "main"
)

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
