//go:build windows

package collector

import (
	"bytes"
	"encoding/csv"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
	"github.com/syslog-platform/logger/internal/models"
)

func collectPlatformSpecific(req *models.AgentInventoryRequest) {
	req.OSType = "windows"
	req.OSFamily = "windows"

	// 1. Collect OS metadata from Registry
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if prodName, _, err := k.GetStringValue("ProductName"); err == nil {
			req.OSName = prodName
		}
		if build, _, err := k.GetStringValue("CurrentBuild"); err == nil {
			req.OSBuild = build
		}
		if displayVer, _, err := k.GetStringValue("DisplayVersion"); err == nil {
			req.OSVersion = displayVer
		}
	}

	if req.OSName == "" {
		req.OSName = "Microsoft Windows"
	}

	// 2. Collect Installed Software from Registry (both 64-bit and 32-bit views)
	uninstallPaths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	seenSoftware := make(map[string]bool)

	for _, path := range uninstallPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err != nil {
			continue
		}
		subkeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}

		for _, subkey := range subkeys {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+subkey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			displayName, _, errName := sk.GetStringValue("DisplayName")
			displayVer, _, _ := sk.GetStringValue("DisplayVersion")
			publisher, _, _ := sk.GetStringValue("Publisher")
			installLocation, _, _ := sk.GetStringValue("InstallLocation")
			sk.Close()

			if errName != nil || strings.TrimSpace(displayName) == "" {
				continue
			}

			displayName = strings.TrimSpace(displayName)
			displayVer = strings.TrimSpace(displayVer)
			if displayVer == "" {
				displayVer = "1.0"
			}

			key := strings.ToLower(displayName + "@" + displayVer)
			if seenSoftware[key] {
				continue
			}
			seenSoftware[key] = true

			req.Software = append(req.Software, models.AgentSoftwareItem{
				Name:            displayName,
				Vendor:          strings.TrimSpace(publisher),
				Version:         displayVer,
				Arch:            req.Architecture,
				PackageType:     "win_installed",
				InstallLocation: strings.TrimSpace(installLocation),
			})
		}
	}

	// 3. Collect Installed Patches / HotFixes via WMIC or PowerShell
	collectWindowsPatches(req)
}

func collectWindowsPatches(req *models.AgentInventoryRequest) {
	// Try WMIC first
	cmd := exec.Command("wmic", "qfe", "get", "Description,HotFixID,InstalledOn", "/format:csv")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		r := csv.NewReader(bytes.NewReader(out))
		records, err := r.ReadAll()
		if err == nil && len(records) > 1 {
			header := records[0]
			descIdx := -1
			hotfixIdx := -1
			dateIdx := -1
			for j, h := range header {
				h = strings.TrimSpace(strings.ToLower(h))
				if h == "description" {
					descIdx = j
				} else if h == "hotfixid" {
					hotfixIdx = j
				} else if h == "installedon" {
					dateIdx = j
				}
			}
			for i := 1; i < len(records); i++ {
				rec := records[i]
				var kb, desc, date string
				if hotfixIdx >= 0 && hotfixIdx < len(rec) {
					kb = strings.TrimSpace(rec[hotfixIdx])
				}
				if descIdx >= 0 && descIdx < len(rec) {
					desc = strings.TrimSpace(rec[descIdx])
				}
				if dateIdx >= 0 && dateIdx < len(rec) {
					date = strings.TrimSpace(rec[dateIdx])
				}
				if strings.HasPrefix(strings.ToUpper(kb), "KB") {
					req.Patches = append(req.Patches, models.AgentPatchItem{
						HotFixID:    kb,
						Description: desc,
						InstalledOn: date,
					})
				}
			}
			if len(req.Patches) > 0 {
				return
			}
		}
	}

	// Fallback to PowerShell Get-HotFix if WMIC is unavailable
	psCmd := exec.Command("powershell.exe", "-NoProfile", "-Command", "Get-HotFix | ForEach-Object { \"$($_.HotFixID)|$($_.Description)|$($_.InstalledOn)\" }")
	psOut, err := psCmd.Output()
	if err == nil {
		lines := strings.Split(string(psOut), "\n")
		for _, line := range lines {
			parts := strings.Split(strings.TrimSpace(line), "|")
			if len(parts) >= 1 {
				kb := strings.TrimSpace(parts[0])
				if strings.HasPrefix(strings.ToUpper(kb), "KB") {
					desc := ""
					date := ""
					if len(parts) >= 2 {
						desc = strings.TrimSpace(parts[1])
					}
					if len(parts) >= 3 {
						date = strings.TrimSpace(parts[2])
					}
					req.Patches = append(req.Patches, models.AgentPatchItem{
						HotFixID:    kb,
						Description: desc,
						InstalledOn: date,
					})
				}
			}
		}
	}
}
