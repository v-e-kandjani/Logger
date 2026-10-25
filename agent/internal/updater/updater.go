package updater

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ApplyUpgrade downloads the new agent binary from the connected server and performs an in-place upgrade
func ApplyUpgrade(ctx context.Context, serverURL, downloadPath, targetVersion string) error {
	log.Printf("[LOGGER Auto-Updater] Initiating in-place upgrade to %s from %s%s...", targetVersion, serverURL, downloadPath)

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving current executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("resolving executable symlinks: %w", err)
	}

	execDir := filepath.Dir(execPath)
	tempFile, err := os.CreateTemp(execDir, "logger-agent-new-*")
	if err != nil {
		// Fallback to os.TempDir if directory isn't writable directly
		tempFile, err = os.CreateTemp("", "logger-agent-new-*")
		if err != nil {
			return fmt.Errorf("creating temp file for download: %w", err)
		}
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()

	// Construct download URL
	fullURL := serverURL
	if !strings.HasSuffix(fullURL, "/") && !strings.HasPrefix(downloadPath, "/") {
		fullURL += "/"
	}
	fullURL += downloadPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		tempFile.Close()
		return fmt.Errorf("creating download request: %w", err)
	}

	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		tempFile.Close()
		return fmt.Errorf("downloading new binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		tempFile.Close()
		return fmt.Errorf("server returned HTTP %d for agent upgrade binary", resp.StatusCode)
	}

	copied, err := io.Copy(tempFile, resp.Body)
	_ = tempFile.Close()
	if err != nil {
		return fmt.Errorf("writing downloaded binary: %w", err)
	}
	if copied < 1024*1024 { // Agent binary should be at least 1MB
		return fmt.Errorf("downloaded binary size too small (%d bytes), aborting upgrade", copied)
	}

	// Make executable
	_ = os.Chmod(tempPath, 0755)

	log.Printf("[LOGGER Auto-Updater] Download completed (%d bytes). Applying binary replacement...", copied)

	if runtime.GOOS == "windows" {
		// Windows: running exe cannot be directly overwritten while running.
		// Fast Path: Stage as .new first
		newPath := execPath + ".new"
		_ = os.Remove(newPath)
		if err := installBinary(tempPath, newPath); err != nil {
			return fmt.Errorf("staging new binary to %s: %w", newPath, err)
		}

		// Try atomic rename to a unique timestamped .old file
		oldPath := fmt.Sprintf("%s.old.%d", execPath, time.Now().Unix())
		if renameErr := os.Rename(execPath, oldPath); renameErr == nil {
			if installErr := installBinary(newPath, execPath); installErr == nil {
				log.Printf("[LOGGER Auto-Updater] Binary successfully updated to %s! Triggering service/process restart...", targetVersion)
				restartScript := fmt.Sprintf(`ping 127.0.0.1 -n 2 > nul & (net stop LoggerAgent && net start LoggerAgent) || start "" "%s"`, execPath)
				_ = exec.Command("cmd.exe", "/C", restartScript).Start()
				go func() {
					time.Sleep(500 * time.Millisecond)
					os.Exit(0)
				}()
				return nil
			}
			// Rollback if install failed
			_ = os.Rename(oldPath, execPath)
		}

		// Robust Fallback: If in-process rename failed (Access is denied / file locked by service or another handle),
		// launch detached updater batch helper that waits for current process to exit, swaps files, and restarts!
		log.Printf("[LOGGER Auto-Updater] Direct rename locked; deploying detached Windows update helper...")
		scriptPath := filepath.Join(filepath.Dir(execPath), "logger-updater.bat")
		batchContent := fmt.Sprintf(`@echo off
ping 127.0.0.1 -n 2 > nul
taskkill /F /IM logger-agent.exe > nul 2>&1
ping 127.0.0.1 -n 2 > nul
move /Y "%s" "%s" > nul 2>&1
del /F /Q "%s.old*" > nul 2>&1
net start LoggerAgent > nul 2>&1 || start "" "%s"
del "%%%%~f0" > nul 2>&1
`, newPath, execPath, execPath, execPath)
		if err := os.WriteFile(scriptPath, []byte(batchContent), 0755); err != nil {
			return fmt.Errorf("writing updater batch helper: %w", err)
		}

		cmd := exec.Command("cmd.exe", "/C", scriptPath)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("starting updater script: %w", err)
		}

		log.Printf("[LOGGER Auto-Updater] Detached helper launched. Exiting current process for binary swap...")
		go func() {
			time.Sleep(300 * time.Millisecond)
			os.Exit(0)
		}()
		return nil
	}

	// Linux / macOS / Unix: atomic move over execPath with fallback for text-file-busy (ETXTBSY)
	if err := installBinary(tempPath, execPath); err != nil {
		return fmt.Errorf("installing new binary failed: %w", err)
	}

	log.Printf("[LOGGER Auto-Updater] Binary successfully updated to %s! Restarting daemon...", targetVersion)

	if runtime.GOOS == "linux" {
		// Attempt systemctl service restart first; fallback to direct process respawn if not managed by systemd
		go func() {
			time.Sleep(500 * time.Millisecond)
			cmd := exec.Command("systemctl", "restart", "logger-agent")
			if err := cmd.Run(); err != nil {
				// Standalone or non-systemd fallback
				respawnCmd := exec.Command(execPath, os.Args[1:]...)
				respawnCmd.Stdout = os.Stdout
				respawnCmd.Stderr = os.Stderr
				_ = respawnCmd.Start()
			}
			os.Exit(0)
		}()
		return nil
	} else if runtime.GOOS == "darwin" {
		go func() {
			time.Sleep(500 * time.Millisecond)
			cmd := exec.Command("launchctl", "kickstart", "-k", "system/com.valtrivo.logger-agent")
			if err := cmd.Run(); err != nil {
				respawnCmd := exec.Command(execPath, os.Args[1:]...)
				_ = respawnCmd.Start()
			}
			os.Exit(0)
		}()
		return nil
	}

	go func() {
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	return nil
}

// installBinary safely places the new binary at dst, handling cross-device mounts and ETXTBSY on Unix
func installBinary(src, dst string) error {
	// 1. Try atomic rename first (fast path when on same filesystem)
	if err := os.Rename(src, dst); err == nil {
		_ = os.Chmod(dst, 0755)
		return nil
	}

	// 2. Cross-device or busy file handling:
	// In Unix, opening an active executing binary for writing (O_TRUNC/O_WRONLY) returns ETXTBSY.
	// But unlinking (os.Remove) or renaming the existing destination directory entry is fully supported
	// by the kernel because the active process retains its open file descriptor to the old inode.
	dstOld := dst + ".old"
	_ = os.Remove(dstOld)
	renamed := false
	if err := os.Rename(dst, dstOld); err == nil {
		renamed = true
	} else {
		_ = os.Remove(dst)
	}

	// 3. Copy src to dst
	in, err := os.Open(src)
	if err != nil {
		if renamed {
			_ = os.Rename(dstOld, dst)
		}
		return fmt.Errorf("opening downloaded temp binary: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		if renamed {
			_ = os.Rename(dstOld, dst)
		}
		return fmt.Errorf("creating target binary: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		if renamed {
			_ = os.Rename(dstOld, dst)
		}
		return fmt.Errorf("copying binary stream: %w", err)
	}
	_ = out.Close()
	_ = os.Chmod(dst, 0755)

	// Clean up
	_ = os.Remove(src)
	_ = os.Remove(dstOld)
	return nil
}
