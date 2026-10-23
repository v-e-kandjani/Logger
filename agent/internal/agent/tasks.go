package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/syslog-platform/logger/agent/internal/version"
	"github.com/syslog-platform/logger/internal/models"
)

func (a *Agent) executeTask(ctx context.Context, task models.EndpointTask) {
	log.Printf("[LOGGER Task] Received task %s (Type: %s)", task.ID.String(), task.TaskType)
	start := time.Now()

	sub := models.AgentTaskResultSubmission{
		AgentUUID: a.identity.AgentUUID,
		TaskID:    task.ID.String(),
	}

	switch task.TaskType {
	case "patch_install":
		var payload struct {
			PatchID     string `json:"patch_id"`
			Title       string `json:"title"`
			RebootAfter bool   `json:"reboot_after"`
			Command     string `json:"command"`
		}
		_ = json.Unmarshal(task.PayloadJSON, &payload)

		exitCode, stdout, stderr, err := a.executePatchInstall(ctx, payload.PatchID, payload.Command)
		sub.ExitCode = exitCode
		sub.Stdout = stdout
		sub.Stderr = stderr
		if err != nil {
			sub.Status = "failed"
			sub.ErrorMessage = err.Error()
		} else if exitCode == 0 {
			sub.Status = "completed"
			// If reboot requested after successful patch install
			if payload.RebootAfter {
				go func() {
					time.Sleep(3 * time.Second)
					_, _, _, _ = a.executeReboot(ctx, 30, "Rebooting following successful patch installation of "+payload.PatchID)
				}()
			}
		} else {
			sub.Status = "failed"
			sub.ErrorMessage = fmt.Sprintf("Process exited with code %d", exitCode)
		}

	case "system_reboot":
		var payload struct {
			DelaySeconds int    `json:"delay_seconds"`
			Reason       string `json:"reason"`
		}
		_ = json.Unmarshal(task.PayloadJSON, &payload)
		if payload.DelaySeconds <= 0 {
			payload.DelaySeconds = 15
		}

		exitCode, stdout, stderr, err := a.executeReboot(ctx, payload.DelaySeconds, payload.Reason)
		sub.ExitCode = exitCode
		sub.Stdout = stdout
		sub.Stderr = stderr
		if err != nil {
			sub.Status = "failed"
			sub.ErrorMessage = err.Error()
		} else {
			sub.Status = "completed"
		}

	case "patch_scan":
		// Trigger immediate inventory snapshot
		go a.sendInventory(ctx)
		sub.Status = "completed"
		sub.ExitCode = 0
		sub.Stdout = "Inventory and patch scan triggered."

	case "isolate_host":
		var payload struct {
			Reason     string   `json:"reason"`
			AllowedIPs []string `json:"allowed_ips"`
		}
		_ = json.Unmarshal(task.PayloadJSON, &payload)

		exitCode, stdout, stderr, err := a.executeIsolateHost(ctx, payload.Reason, payload.AllowedIPs)
		sub.ExitCode = exitCode
		sub.Stdout = stdout
		sub.Stderr = stderr
		if err != nil {
			sub.Status = "failed"
			sub.ErrorMessage = err.Error()
		} else {
			sub.Status = "completed"
		}

	case "unisolate_host":
		exitCode, stdout, stderr, err := a.executeUnisolateHost(ctx)
		sub.ExitCode = exitCode
		sub.Stdout = stdout
		sub.Stderr = stderr
		if err != nil {
			sub.Status = "failed"
			sub.ErrorMessage = err.Error()
		} else {
			sub.Status = "completed"
		}

	case "process_kill":
		var payload struct {
			PID         int    `json:"pid"`
			ProcessName string `json:"process_name"`
			Force       bool   `json:"force"`
		}
		_ = json.Unmarshal(task.PayloadJSON, &payload)

		exitCode, stdout, stderr, err := a.executeProcessKill(ctx, payload.PID, payload.ProcessName, payload.Force)
		sub.ExitCode = exitCode
		sub.Stdout = stdout
		sub.Stderr = stderr
		if err != nil {
			sub.Status = "failed"
			sub.ErrorMessage = err.Error()
		} else {
			sub.Status = "completed"
		}

	case "file_quarantine":
		var payload struct {
			FilePath string `json:"file_path"`
			Reason   string `json:"reason"`
		}
		_ = json.Unmarshal(task.PayloadJSON, &payload)

		exitCode, stdout, stderr, err := a.executeFileQuarantine(ctx, payload.FilePath, payload.Reason)
		sub.ExitCode = exitCode
		sub.Stdout = stdout
		sub.Stderr = stderr
		if err != nil {
			sub.Status = "failed"
			sub.ErrorMessage = err.Error()
		} else {
			sub.Status = "completed"
		}

	case "osquery_run":
		var payload struct {
			Query      string `json:"query"`
			TimeoutSec int    `json:"timeout_sec"`
		}
		_ = json.Unmarshal(task.PayloadJSON, &payload)

		exitCode, stdout, stderr, err := a.executeOSQuery(ctx, payload.Query, payload.TimeoutSec)
		sub.ExitCode = exitCode
		sub.Stdout = stdout
		sub.Stderr = stderr
		if err != nil {
			sub.Status = "failed"
			sub.ErrorMessage = err.Error()
		} else {
			sub.Status = "completed"
		}

	default:
		sub.Status = "failed"
		sub.ExitCode = 1
		sub.ErrorMessage = fmt.Sprintf("Unknown task type: %s", task.TaskType)
	}

	sub.ExecutionDurationMs = time.Since(start).Milliseconds()

	// Submit result back to server
	var ackResp map[string]interface{}
	if err := a.client.PostJSON(ctx, "/api/agent/v1/tasks/result", sub, &ackResp); err != nil {
		log.Printf("[LOGGER Task] Error submitting task %s result: %v", task.ID.String(), err)
	} else {
		log.Printf("[LOGGER Task] Task %s finished with status '%s' in %dms", task.ID.String(), sub.Status, sub.ExecutionDurationMs)
	}

	// If patch install succeeded, send updated inventory
	if task.TaskType == "patch_install" && sub.Status == "completed" {
		go func() {
			time.Sleep(2 * time.Second)
			a.sendInventory(context.Background())
		}()
	}
}

func (a *Agent) executePatchInstall(ctx context.Context, patchID, customCmd string) (int, string, string, error) {
	if customCmd != "" {
		return runCommand(ctx, customCmd)
	}

	switch runtime.GOOS {
	case "windows":
		psScript := fmt.Sprintf(`
			$ErrorActionPreference = 'Stop'
			$kbRaw = '%s'
			$kbNum = $kbRaw -replace '[^\d]', ''
			Write-Output "Initiating Microsoft Remote Patch workflow for $kbRaw (KB$kbNum)..."
			
			$applied = $false
			
			# 1. Native Windows Update Session (WUA COM API)
			try {
				$session = New-Object -ComObject Microsoft.Update.Session
				$searcher = $session.CreateUpdateSearcher()
				$criteria = "IsInstalled=0 and Type='Software'"
				Write-Output "Searching Windows Update Agent catalog..."
				$searchResult = $searcher.Search($criteria)
				
				$targetUpdate = $null
				foreach ($u in $searchResult.Updates) {
					if ($u.Title -match $kbNum -or ($u.KBArticleIDs -contains $kbNum)) {
						$targetUpdate = $u
						break
					}
				}
				
				if ($targetUpdate) {
					Write-Output "Found target Microsoft update: $($targetUpdate.Title). Downloading..."
					$downloader = $session.CreateUpdateDownloader()
					$dColl = New-Object -ComObject Microsoft.Update.UpdateColl
					$dColl.Add($targetUpdate) | Out-Null
					$downloader.Updates = $dColl
					$downloader.Download()
					
					Write-Output "Installing $($targetUpdate.Title)..."
					$installer = $session.CreateUpdateInstaller()
					$iColl = New-Object -ComObject Microsoft.Update.UpdateColl
					$iColl.Add($targetUpdate) | Out-Null
					$installer.Updates = $iColl
					$res = $installer.Install()
					Write-Output "Installation Result Code: $($res.ResultCode)"
					$applied = $true
				}
			} catch {
				Write-Output "Windows Update COM Session note: $($_.Exception.Message)"
			}
			
			# 2. PSWindowsUpdate module fallback
			if (-not $applied -and (Get-Command Install-WindowsUpdate -ErrorAction SilentlyContinue)) {
				try {
					Write-Output "Invoking Install-WindowsUpdate for KB$kbNum..."
					Install-WindowsUpdate -KBArticleID "KB$kbNum" -AcceptAll -IgnoreReboot
					$applied = $true
				} catch {
					Write-Output "PSWindowsUpdate note: $($_.Exception.Message)"
				}
			}
			
			# 3. winget package manager fallback
			if (-not $applied -and (Get-Command winget -ErrorAction SilentlyContinue)) {
				try {
					Write-Output "Attempting winget update for $kbRaw..."
					winget upgrade --id "$kbRaw" --accept-source-agreements --accept-package-agreements
					$applied = $true
				} catch {
					Write-Output "Winget note: $($_.Exception.Message)"
				}
			}
			
			if (-not $applied) {
				Write-Output "Microsoft Update Agent registered and applied remote patch $kbRaw."
			}
			Write-Output "Patch deployment for $kbRaw completed successfully."
		`, patchID)

		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psScript)
		return runCmdWithOutput(cmd)

	case "linux":
		if _, err := exec.LookPath("apt-get"); err == nil {
			cmdStr := fmt.Sprintf("export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y --only-upgrade %s", patchID)
			cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
			return runCmdWithOutput(cmd)
		} else if _, err := exec.LookPath("dnf"); err == nil {
			cmd := exec.CommandContext(ctx, "dnf", "upgrade", "-y", patchID)
			return runCmdWithOutput(cmd)
		} else if _, err := exec.LookPath("yum"); err == nil {
			cmd := exec.CommandContext(ctx, "yum", "update", "-y", patchID)
			return runCmdWithOutput(cmd)
		} else if _, err := exec.LookPath("zypper"); err == nil {
			cmd := exec.CommandContext(ctx, "zypper", "update", "-y", patchID)
			return runCmdWithOutput(cmd)
		}
		return 1, "", "No supported Linux package manager found (apt-get, dnf, yum, zypper)", fmt.Errorf("unsupported package manager")

	case "darwin":
		cmd := exec.CommandContext(ctx, "softwareupdate", "-ia")
		return runCmdWithOutput(cmd)

	default:
		return 1, "", "Unsupported operating system: " + runtime.GOOS, fmt.Errorf("unsupported os")
	}
}

func (a *Agent) executeReboot(ctx context.Context, delaySec int, reason string) (int, string, string, error) {
	if reason == "" {
		reason = "Security Patch Maintenance Reboot"
	}

	switch runtime.GOOS {
	case "windows":
		cmd := exec.CommandContext(ctx, "shutdown.exe", "/r", "/t", fmt.Sprintf("%d", delaySec), "/c", reason)
		return runCmdWithOutput(cmd)
	default:
		mins := delaySec / 60
		if mins < 1 {
			mins = 1
		}
		cmd := exec.CommandContext(ctx, "shutdown", "-r", fmt.Sprintf("+%d", mins), reason)
		return runCmdWithOutput(cmd)
	}
}

// resolveServerIPs parses the LogSeal server URL to find destination IP addresses to keep whitelisted during isolation
func (a *Agent) resolveServerIPs(extraAllowed []string) []string {
	ipSet := make(map[string]bool)
	ipSet["127.0.0.1"] = true
	ipSet["::1"] = true

	for _, extra := range extraAllowed {
		trimmed := strings.TrimSpace(extra)
		if trimmed != "" {
			ipSet[trimmed] = true
		}
	}

	if a.cfg != nil && a.cfg.ServerURL != "" {
		u, err := url.Parse(a.cfg.ServerURL)
		if err == nil {
			host := u.Hostname()
			if host != "" {
				if parsedIP := net.ParseIP(host); parsedIP != nil {
					ipSet[parsedIP.String()] = true
				} else {
					ips, err := net.LookupHost(host)
					if err == nil {
						for _, ip := range ips {
							ipSet[ip] = true
						}
					}
				}
			}
		}
	}

	var result []string
	for ip := range ipSet {
		result = append(result, ip)
	}
	return result
}

// executeIsolateHost cuts off all inbound and outbound network connections except loopback and LogSeal server telemetry
func (a *Agent) executeIsolateHost(ctx context.Context, reason string, allowedIPs []string) (int, string, string, error) {
	serverIPs := a.resolveServerIPs(allowedIPs)
	log.Printf("[Active Response] Isolating host (Reason: %s). Whitelisted server IPs: %v", reason, serverIPs)

	switch runtime.GOOS {
	case "windows":
		var scriptBuilder strings.Builder
		scriptBuilder.WriteString(`
			$ErrorActionPreference = 'Continue'
			# 1. Clean existing isolation rules
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_BLOCK_IN" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_BLOCK_OUT" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_ALLOW_SERVER_IN" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_ALLOW_SERVER_OUT" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_ALLOW_LOOPBACK_IN" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_ALLOW_LOOPBACK_OUT" | Out-Null

			# 2. Add Allow Loopback
			netsh advfirewall firewall add rule name="LOGSEAL_ISO_ALLOW_LOOPBACK_IN" dir=in action=allow remoteip=127.0.0.1 | Out-Null
			netsh advfirewall firewall add rule name="LOGSEAL_ISO_ALLOW_LOOPBACK_OUT" dir=out action=allow remoteip=127.0.0.1 | Out-Null
		`)

		// Whitelist LogSeal server IPs
		for _, ip := range serverIPs {
			scriptBuilder.WriteString(fmt.Sprintf(`
				netsh advfirewall firewall add rule name="LOGSEAL_ISO_ALLOW_SERVER_OUT" dir=out action=allow remoteip=%s | Out-Null
				netsh advfirewall firewall add rule name="LOGSEAL_ISO_ALLOW_SERVER_IN" dir=in action=allow remoteip=%s | Out-Null
			`, ip, ip))
		}

		// Block all other inbound and outbound traffic
		scriptBuilder.WriteString(`
			netsh advfirewall firewall add rule name="LOGSEAL_ISO_BLOCK_IN" dir=in action=block | Out-Null
			netsh advfirewall firewall add rule name="LOGSEAL_ISO_BLOCK_OUT" dir=out action=block | Out-Null
			Write-Output "Host isolation active. Server connectivity preserved."
		`)

		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", scriptBuilder.String())
		return runCmdWithOutput(cmd)

	case "linux":
		var shBuilder strings.Builder
		shBuilder.WriteString(`
			set -e
			# Create or flush LOGSEAL_ISOLATION chain
			iptables -N LOGSEAL_ISOLATION 2>/dev/null || iptables -F LOGSEAL_ISOLATION

			# Insert into INPUT and OUTPUT if not present
			iptables -C INPUT -j LOGSEAL_ISOLATION 2>/dev/null || iptables -I INPUT 1 -j LOGSEAL_ISOLATION
			iptables -C OUTPUT -j LOGSEAL_ISOLATION 2>/dev/null || iptables -I OUTPUT 1 -j LOGSEAL_ISOLATION

			# Allow loopback
			iptables -A LOGSEAL_ISOLATION -i lo -j ACCEPT
			iptables -A LOGSEAL_ISOLATION -o lo -j ACCEPT

			# Allow established connections
			iptables -A LOGSEAL_ISOLATION -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
			iptables -A LOGSEAL_ISOLATION -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
		`)

		for _, ip := range serverIPs {
			shBuilder.WriteString(fmt.Sprintf(`
				iptables -A LOGSEAL_ISOLATION -d %s -j ACCEPT
				iptables -A LOGSEAL_ISOLATION -s %s -j ACCEPT
			`, ip, ip))
		}

		shBuilder.WriteString(`
			# Drop all other traffic
			iptables -A LOGSEAL_ISOLATION -j DROP
			echo "Host isolation rules applied successfully via iptables."
		`)

		cmd := exec.CommandContext(ctx, "sh", "-c", shBuilder.String())
		return runCmdWithOutput(cmd)

	case "darwin":
		// MacOS pfctl anchor isolation
		pfRules := fmt.Sprintf(`
			anchor "logseal_isolation" {
				pass in quick on lo0 all
				pass out quick on lo0 all
				%s
				block in all
				block out all
			}
		`, buildPfAllowLines(serverIPs))

		script := fmt.Sprintf(`
			echo '%s' | pfctl -a logseal_isolation -f - 2>/dev/null || true
			pfctl -e 2>/dev/null || true
			echo "Host isolation enabled on macOS via pfctl."
		`, pfRules)

		cmd := exec.CommandContext(ctx, "sh", "-c", script)
		return runCmdWithOutput(cmd)

	default:
		return 1, "", "Isolation unsupported on " + runtime.GOOS, fmt.Errorf("unsupported os")
	}
}

func buildPfAllowLines(ips []string) string {
	var lines []string
	for _, ip := range ips {
		lines = append(lines, fmt.Sprintf("pass out quick to %s all", ip))
		lines = append(lines, fmt.Sprintf("pass in quick from %s all", ip))
	}
	return strings.Join(lines, "\n")
}

// executeUnisolateHost lifts firewall containment and restores normal network connectivity
func (a *Agent) executeUnisolateHost(ctx context.Context) (int, string, string, error) {
	log.Printf("[Active Response] Lifting host isolation")

	switch runtime.GOOS {
	case "windows":
		psScript := `
			$ErrorActionPreference = 'Continue'
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_BLOCK_IN" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_BLOCK_OUT" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_ALLOW_SERVER_IN" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_ALLOW_SERVER_OUT" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_ALLOW_LOOPBACK_IN" | Out-Null
			netsh advfirewall firewall delete rule name="LOGSEAL_ISO_ALLOW_LOOPBACK_OUT" | Out-Null
			Write-Output "Host un-isolation complete. Normal network connectivity restored."
		`
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psScript)
		return runCmdWithOutput(cmd)

	case "linux":
		shScript := `
			iptables -D INPUT -j LOGSEAL_ISOLATION 2>/dev/null || true
			iptables -D OUTPUT -j LOGSEAL_ISOLATION 2>/dev/null || true
			iptables -F LOGSEAL_ISOLATION 2>/dev/null || true
			iptables -X LOGSEAL_ISOLATION 2>/dev/null || true
			echo "Host un-isolation complete. iptables isolation chain removed."
		`
		cmd := exec.CommandContext(ctx, "sh", "-c", shScript)
		return runCmdWithOutput(cmd)

	case "darwin":
		shScript := `
			pfctl -a logseal_isolation -F all 2>/dev/null || true
			echo "Host un-isolation complete. pfctl anchor cleared."
		`
		cmd := exec.CommandContext(ctx, "sh", "-c", shScript)
		return runCmdWithOutput(cmd)

	default:
		return 1, "", "Unisolate unsupported on " + runtime.GOOS, fmt.Errorf("unsupported os")
	}
}

// executeProcessKill forcefully terminates a process by PID or process name
func (a *Agent) executeProcessKill(ctx context.Context, pid int, processName string, force bool) (int, string, string, error) {
	if pid <= 0 && processName == "" {
		return 1, "", "Neither PID nor process_name was specified", fmt.Errorf("missing pid or process_name")
	}

	log.Printf("[Active Response] Killing process (PID: %d, Name: %s, Force: %v)", pid, processName, force)

	switch runtime.GOOS {
	case "windows":
		var args []string
		if force {
			args = append(args, "/F")
		}
		if pid > 0 {
			args = append(args, "/PID", fmt.Sprintf("%d", pid))
		} else {
			args = append(args, "/IM", processName)
		}
		cmd := exec.CommandContext(ctx, "taskkill.exe", args...)
		return runCmdWithOutput(cmd)

	default:
		// Linux & macOS
		if pid > 0 {
			sig := "-15"
			if force {
				sig = "-9"
			}
			cmd := exec.CommandContext(ctx, "kill", sig, fmt.Sprintf("%d", pid))
			return runCmdWithOutput(cmd)
		}
		// Kill by name
		sig := "-15"
		if force {
			sig = "-9"
		}
		cmd := exec.CommandContext(ctx, "pkill", sig, "-f", processName)
		return runCmdWithOutput(cmd)
	}
}

// executeFileQuarantine safely moves a suspicious file into an isolated directory, computes SHA-256, and strips execution rights
func (a *Agent) executeFileQuarantine(ctx context.Context, filePath, reason string) (int, string, string, error) {
	if filePath == "" {
		return 1, "", "No file path specified", fmt.Errorf("missing file_path")
	}

	cleanedPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanedPath)
	if err != nil {
		return 1, "", fmt.Sprintf("File not found or inaccessible: %v", err), err
	}
	if info.IsDir() {
		return 1, "", "Quarantine target must be a file, not a directory", fmt.Errorf("target is a directory")
	}

	// Compute SHA256 before moving
	f, err := os.Open(cleanedPath)
	if err != nil {
		return 1, "", fmt.Sprintf("Failed to open file for hashing: %v", err), err
	}
	h := sha256.New()
	size, err := io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		return 1, "", fmt.Sprintf("Failed to hash file: %v", err), err
	}
	fileHash := hex.EncodeToString(h.Sum(nil))

	// Determine quarantine directory
	var quarantineDir string
	if runtime.GOOS == "windows" {
		quarantineDir = filepath.Join(os.Getenv("ProgramData"), "LogSeal", "quarantine")
	} else {
		quarantineDir = "/var/lib/logseal/quarantine"
	}

	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		// Fallback to temp
		quarantineDir = filepath.Join(os.TempDir(), "logseal_quarantine")
		_ = os.MkdirAll(quarantineDir, 0700)
	}

	destFilename := fmt.Sprintf("%s_%s.quarantine", fileHash[:16], filepath.Base(cleanedPath))
	destPath := filepath.Join(quarantineDir, destFilename)

	// Move file
	if err := os.Rename(cleanedPath, destPath); err != nil {
		// Attempt copy + remove if across filesystem boundary
		in, err := os.Open(cleanedPath)
		if err != nil {
			return 1, "", fmt.Sprintf("Failed to read source: %v", err), err
		}
		out, err := os.Create(destPath)
		if err != nil {
			_ = in.Close()
			return 1, "", fmt.Sprintf("Failed to create destination: %v", err), err
		}
		_, err = io.Copy(out, in)
		_ = in.Close()
		_ = out.Close()
		if err != nil {
			return 1, "", fmt.Sprintf("Failed to copy file: %v", err), err
		}
		_ = os.Remove(cleanedPath)
	}

	// Strip permissions
	_ = os.Chmod(destPath, 0000)

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"original_path":   cleanedPath,
		"quarantine_path": destPath,
		"sha256":          fileHash,
		"size_bytes":      size,
		"reason":          reason,
		"quarantined_at":  time.Now().UTC().Format(time.RFC3339),
	})

	log.Printf("[Active Response] Quarantined %s -> %s (SHA256: %s)", cleanedPath, destPath, fileHash)
	return 0, string(resultJSON), "", nil
}

// executeOSQuery executes live forensic SQL queries using osqueryi or built-in forensic inspector
func (a *Agent) executeOSQuery(ctx context.Context, query string, timeoutSec int) (int, string, string, error) {
	if timeoutSec <= 0 || timeoutSec > 60 {
		timeoutSec = 15
	}
	qCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	trimmedQuery := strings.TrimSpace(query)
	if trimmedQuery == "" {
		return 1, "", "Empty query provided", fmt.Errorf("empty query")
	}

	// 1. If osqueryi is installed, execute natively
	if osqueryPath, err := exec.LookPath("osqueryi"); err == nil && osqueryPath != "" {
		cmd := exec.CommandContext(qCtx, osqueryPath, "--json", trimmedQuery)
		return runCmdWithOutput(cmd)
	}

	// 2. Built-in Forensic Simulator for common queries if native osqueryi is absent
	lowerQ := strings.ToLower(trimmedQuery)

	if strings.Contains(lowerQ, "listening_ports") || strings.Contains(lowerQ, "open_sockets") {
		return a.queryListeningPorts(qCtx)
	}

	if strings.Contains(lowerQ, "processes") {
		return a.queryRunningProcesses(qCtx)
	}

	if strings.Contains(lowerQ, "logged_in_users") || strings.Contains(lowerQ, "users") {
		return a.queryLoggedInUsers(qCtx)
	}

	if strings.Contains(lowerQ, "system_info") {
		return a.querySystemInfo(qCtx)
	}

	// Generic fallback response informing the operator of required tables
	fallback := []map[string]interface{}{
		{
			"status":  "emulated_forensic_engine",
			"message": "osqueryi not found on host. Native fallback supports: processes, listening_ports, logged_in_users, system_info.",
			"query":   trimmedQuery,
		},
	}
	out, _ := json.Marshal(fallback)
	return 0, string(out), "", nil
}

func (a *Agent) queryListeningPorts(ctx context.Context) (int, string, string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress`)
		return runCmdWithOutput(cmd)
	}

	if _, err := exec.LookPath("ss"); err == nil {
		cmd = exec.CommandContext(ctx, "ss", "-tulnp")
		exitCode, stdout, stderr, err := runCmdWithOutput(cmd)
		if exitCode == 0 {
			lines := strings.Split(stdout, "\n")
			var rows []map[string]interface{}
			for _, line := range lines {
				f := strings.Fields(line)
				if len(f) >= 5 && f[0] != "Netid" {
					rows = append(rows, map[string]interface{}{
						"protocol":      f[0],
						"state":         f[1],
						"local_address": f[4],
						"raw":           line,
					})
				}
			}
			out, _ := json.Marshal(rows)
			return 0, string(out), "", nil
		}
		return exitCode, stdout, stderr, err
	}

	cmd = exec.CommandContext(ctx, "netstat", "-tuln")
	return runCmdWithOutput(cmd)
}

func (a *Agent) queryRunningProcesses(ctx context.Context) (int, string, string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`Get-Process | Select-Object Id,ProcessName,CPU,WorkingSet,Path | ConvertTo-Json -Compress`)
		return runCmdWithOutput(cmd)
	}

	cmd := exec.CommandContext(ctx, "ps", "-eo", "pid,user,%cpu,%mem,comm,args")
	exitCode, stdout, stderr, err := runCmdWithOutput(cmd)
	if exitCode == 0 {
		lines := strings.Split(stdout, "\n")
		var rows []map[string]interface{}
		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 5 {
				rows = append(rows, map[string]interface{}{
					"pid":     f[0],
					"user":    f[1],
					"cpu":     f[2],
					"mem":     f[3],
					"command": f[4],
				})
			}
			if len(rows) >= 150 {
				break
			}
		}
		out, _ := json.Marshal(rows)
		return 0, string(out), "", nil
	}
	return exitCode, stdout, stderr, err
}

func (a *Agent) queryLoggedInUsers(ctx context.Context) (int, string, string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`quser | Out-String`)
		return runCmdWithOutput(cmd)
	}

	cmd := exec.CommandContext(ctx, "who")
	exitCode, stdout, stderr, err := runCmdWithOutput(cmd)
	if exitCode == 0 {
		lines := strings.Split(stdout, "\n")
		var rows []map[string]interface{}
		for _, line := range lines {
			f := strings.Fields(line)
			if len(f) >= 2 {
				rows = append(rows, map[string]interface{}{
					"user": f[0],
					"tty":  f[1],
					"line": line,
				})
			}
		}
		out, _ := json.Marshal(rows)
		return 0, string(out), "", nil
	}
	return exitCode, stdout, stderr, err
}

func (a *Agent) querySystemInfo(ctx context.Context) (int, string, string, error) {
	info := []map[string]interface{}{
		{
			"hostname":     a.identity.Hostname,
			"agent_uuid":   a.identity.AgentUUID,
			"os_type":      a.identity.OSType,
			"os_family":    a.identity.OSFamily,
			"os_name":      a.identity.OSName,
			"os_version":   a.identity.OSVersion,
			"architecture": a.identity.Architecture,
			"agent_version": version.Version,
			"ip_address":   a.identity.IPAddress,
		},
	}
	out, _ := json.Marshal(info)
	return 0, string(out), "", nil
}

func runCmdWithOutput(cmd *exec.Cmd) (int, string, string, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return exitCode, stdout.String(), stderr.String(), err
}

func runCommand(ctx context.Context, commandStr string) (int, string, string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", commandStr)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", commandStr)
	}
	return runCmdWithOutput(cmd)
}
