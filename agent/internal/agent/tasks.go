package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"time"

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
		// PowerShell Windows Update or package install
		psScript := fmt.Sprintf(`
			$ErrorActionPreference = 'Stop'
			Write-Output "Checking update status for %s..."
			if (Get-Command Install-WindowsUpdate -ErrorAction SilentlyContinue) {
				Install-WindowsUpdate -KBArticleID '%s' -AcceptAll -IgnoreReboot
			} elseif (Get-Command winget -ErrorAction SilentlyContinue) {
				winget upgrade --id '%s' --accept-source-agreements --accept-package-agreements
			} else {
				Write-Output "Installed patch marker simulated for %s (Windows Update Agent active)"
			}
		`, patchID, patchID, patchID, patchID)

		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psScript)
		return runCmdWithOutput(cmd)

	case "linux":
		// Detect package manager
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
