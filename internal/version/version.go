package version

import (
	"os"
	"os/exec"
	"strings"
)

var (
	Version   = "v1.3.7"
	BuildDate = "2026-10-09"
	CommitSHA = "33f2cfe"
	Platform  = "Valtrivo LogSeal"
	Company   = "Valtrivo"
	Tagline   = "Her kayıt, zamanıyla kanıt."
	RepoOwner = "v-e-kandjani"
	RepoName  = "Logger"
	Branch    = "main"
)

func init() {
	// Attempt to detect current Git commit SHA dynamically if running in a repo
	if out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		s := strings.TrimSpace(string(out))
		if s != "" {
			CommitSHA = s
		}
	}

	// Attempt to load runtime version overrides from .version_info if updated dynamically
	paths := []string{
		"/opt/syslog-platform/config/.version_info",
		"config/.version_info",
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
						if v != "" {
							CommitSHA = v
						}
					case "VERSION":
						if v != "" {
							Version = v
						}
					case "BUILD_DATE":
						if v != "" {
							BuildDate = v
						}
					}
				}
			}
			break
		}
	}
}
