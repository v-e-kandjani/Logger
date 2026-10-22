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
		// Windows: running exe cannot be directly overwritten, but it CAN be renamed
		oldPath := execPath + ".old"
		_ = os.Remove(oldPath) // remove previous old backup if present

		if err := os.Rename(execPath, oldPath); err != nil {
			return fmt.Errorf("renaming running binary to .old: %w", err)
		}

		// Move temp file to execPath
		if err := copyAndRemove(tempPath, execPath); err != nil {
			// Rollback rename
			_ = os.Rename(oldPath, execPath)
			return fmt.Errorf("installing new binary: %w", err)
		}

		log.Printf("[LOGGER Auto-Updater] Binary successfully updated to %s! Triggering service restart...", targetVersion)

		// Spawn helper to restart service after this process exits
		restartScript := fmt.Sprintf(`ping 127.0.0.1 -n 3 > nul & net stop LoggerAgent & net start LoggerAgent`)
		cmd := exec.Command("cmd.exe", "/C", restartScript)
		_ = cmd.Start()

		go func() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()
		return nil
	}

	// Linux / macOS / Unix: atomic move over execPath
	if err := copyAndRemove(tempPath, execPath); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}
	_ = os.Chmod(execPath, 0755)

	log.Printf("[LOGGER Auto-Updater] Binary successfully updated to %s! Restarting daemon...", targetVersion)

	if runtime.GOOS == "linux" {
		_ = exec.Command("systemctl", "restart", "logger-agent").Start()
	} else if runtime.GOOS == "darwin" {
		_ = exec.Command("launchctl", "kickstart", "-k", "system/com.valtrivo.logger-agent").Start()
	}

	go func() {
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	return nil
}

func copyAndRemove(src, dst string) error {
	// Try rename first
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// Cross-device fallback
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	_ = os.Remove(src)
	return nil
}
