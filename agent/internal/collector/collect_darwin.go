//go:build darwin

package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/syslog-platform/logger/internal/models"
)

func collectPlatformSpecific(req *models.AgentInventoryRequest) {
	req.OSType = "darwin"
	req.OSFamily = "macos"
	req.OSName = "macOS"

	if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
		req.OSVersion = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("sw_vers", "-buildVersion").Output(); err == nil {
		req.OSBuild = strings.TrimSpace(string(out))
	}

	// Scan /Applications
	appDirs := []string{"/Applications", "/System/Applications"}
	for _, appDir := range appDirs {
		entries, err := os.ReadDir(appDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".app") {
				appName := strings.TrimSuffix(entry.Name(), ".app")
				req.Software = append(req.Software, models.AgentSoftwareItem{
					Name:            appName,
					Version:         "1.0",
					Arch:            req.Architecture,
					PackageType:     "app",
					InstallLocation: filepath.Join(appDir, entry.Name()),
				})
			}
		}
	}
}
