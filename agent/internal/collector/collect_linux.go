//go:build linux

package collector

import (
	"bufio"
	"os"
	"os/exec"
	"strings"

	"github.com/syslog-platform/logger/internal/models"
)

func collectPlatformSpecific(req *models.AgentInventoryRequest) {
	req.OSType = "linux"

	// Read /etc/os-release
	if f, err := os.Open("/etc/os-release"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				req.OSName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			} else if strings.HasPrefix(line, "VERSION_ID=") {
				req.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			} else if strings.HasPrefix(line, "ID=") {
				req.OSFamily = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			}
		}
		f.Close()
	}

	if req.OSName == "" {
		req.OSName = "Linux"
	}

	// 1. Try dpkg-query on Debian/Ubuntu
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		cmd := exec.Command("dpkg-query", "-W", "-f=${Package}|${Version}|${Architecture}\n")
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				parts := strings.Split(strings.TrimSpace(line), "|")
				if len(parts) >= 2 && parts[0] != "" {
					arch := req.Architecture
					if len(parts) >= 3 && parts[2] != "" {
						arch = parts[2]
					}
					req.Software = append(req.Software, models.AgentSoftwareItem{
						Name:        parts[0],
						Version:     parts[1],
						Arch:        arch,
						PackageType: "deb",
					})
				}
			}
			return
		}
	}

	// 2. Try rpm on RHEL/CentOS/Rocky
	if _, err := exec.LookPath("rpm"); err == nil {
		cmd := exec.Command("rpm", "-qa", "--qf", "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n")
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				parts := strings.Split(strings.TrimSpace(line), "|")
				if len(parts) >= 2 && parts[0] != "" {
					arch := req.Architecture
					if len(parts) >= 3 && parts[2] != "" {
						arch = parts[2]
					}
					req.Software = append(req.Software, models.AgentSoftwareItem{
						Name:        parts[0],
						Version:     parts[1],
						Arch:        arch,
						PackageType: "rpm",
					})
				}
			}
		}
	}
}
