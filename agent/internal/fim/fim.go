package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// Scanner maintains cryptographic integrity baselines for system files
type Scanner struct {
	mu           sync.Mutex
	baseline     map[string]string // path -> sha256
	isInitial    bool
	defaultPaths []string
}

// NewScanner initializes a platform-aware FIM scanner
func NewScanner() *Scanner {
	s := &Scanner{
		baseline:  make(map[string]string),
		isInitial: true,
	}

	switch runtime.GOOS {
	case "windows":
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		s.defaultPaths = []string{
			filepath.Join(systemRoot, `System32\drivers\etc\hosts`),
			filepath.Join(systemRoot, `System32\GroupPolicy\Machine\Scripts`),
			filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\Startup`),
		}
	case "darwin":
		s.defaultPaths = []string{
			"/etc/hosts",
			"/etc/passwd",
			"/etc/sudoers",
			"/etc/ssh/sshd_config",
			"/Library/LaunchDaemons",
		}
	default: // Linux / Unix
		s.defaultPaths = []string{
			"/etc/hosts",
			"/etc/passwd",
			"/etc/shadow",
			"/etc/group",
			"/etc/sudoers",
			"/etc/ssh/sshd_config",
			"/etc/crontab",
			"/etc/cron.d",
			"/etc/resolv.conf",
		}
	}

	return s
}

// Scan checks target files against previous cryptographic baselines
func (s *Scanner) Scan(customPaths []string, excludePaths []string) ([]models.FIMEvent, []models.FIMBaselineItem) {
	s.mu.Lock()
	defer s.mu.Unlock()

	targets := make(map[string]struct{})
	for _, p := range s.defaultPaths {
		targets[p] = struct{}{}
	}
	for _, p := range customPaths {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			targets[trimmed] = struct{}{}
		}
	}

	// Filter excluded paths
	isExcluded := func(path string) bool {
		for _, ex := range excludePaths {
			if strings.TrimSpace(ex) != "" && strings.Contains(path, strings.TrimSpace(ex)) {
				return true
			}
		}
		return false
	}

	var events []models.FIMEvent
	var baselines []models.FIMBaselineItem
	currentScanFiles := make(map[string]struct{})

	for target := range targets {
		if isExcluded(target) {
			continue
		}

		info, err := os.Stat(target)
		if err != nil {
			// Check if file was previously tracked and has now been deleted
			if prevHash, exists := s.baseline[target]; exists {
				if !s.isInitial {
					events = append(events, models.FIMEvent{
						EventType:      "deleted",
						TargetType:     "file",
						TargetPath:     target,
						PreviousHash:   prevHash,
						CurrentHash:    "",
						Severity:       s.computeSeverity(target),
						MITRETactic:    "Defense Evasion",
						MITRETechnique: "T1565.001",
						Details:        "Critical file was deleted or removed from disk",
						Timestamp:      time.Now().UTC(),
					})
				}
				delete(s.baseline, target)
			}
			continue
		}

		if info.IsDir() {
			// Traverse directory up to 50 items
			entries, readErr := os.ReadDir(target)
			if readErr != nil {
				continue
			}
			count := 0
			for _, entry := range entries {
				if count >= 50 {
					break
				}
				if !entry.IsDir() {
					filePath := filepath.Join(target, entry.Name())
					if isExcluded(filePath) {
						continue
					}
					s.checkFile(filePath, &events, &baselines, currentScanFiles)
					count++
				}
			}
		} else {
			s.checkFile(target, &events, &baselines, currentScanFiles)
		}
	}

	// Check if any previously tracked files inside baseline were deleted
	if !s.isInitial {
		for trackedPath, prevHash := range s.baseline {
			if _, stillExists := currentScanFiles[trackedPath]; !stillExists {
				events = append(events, models.FIMEvent{
					EventType:      "deleted",
					TargetType:     "file",
					TargetPath:     trackedPath,
					PreviousHash:   prevHash,
					CurrentHash:    "",
					Severity:       s.computeSeverity(trackedPath),
					MITRETactic:    "Defense Evasion",
					MITRETechnique: "T1565.001",
					Details:        "Monitored file in directory was deleted",
					Timestamp:      time.Now().UTC(),
				})
				delete(s.baseline, trackedPath)
			}
		}
	}

	s.isInitial = false
	return events, baselines
}

func (s *Scanner) checkFile(path string, events *[]models.FIMEvent, baselines *[]models.FIMBaselineItem, currentScanFiles map[string]struct{}) {
	currentScanFiles[path] = struct{}{}

	hash, size, mode, err := hashFile(path)
	if err != nil {
		return
	}

	prevHash, exists := s.baseline[path]

	// Add to current baseline items
	*baselines = append(*baselines, models.FIMBaselineItem{
		TargetPath:    path,
		TargetType:    "file",
		SHA256Hash:    hash,
		FileSizeBytes: size,
		Permissions:   mode.String(),
		LastChecked:   time.Now().UTC(),
	})

	if !exists {
		// New file detected
		s.baseline[path] = hash
		if !s.isInitial {
			*events = append(*events, models.FIMEvent{
				EventType:      "created",
				TargetType:     "file",
				TargetPath:     path,
				PreviousHash:   "",
				CurrentHash:    hash,
				FileSizeBytes:  size,
				Permissions:    mode.String(),
				Severity:       s.computeSeverity(path),
				MITRETactic:    s.computeTactic(path),
				MITRETechnique: s.computeTechnique(path),
				Details:        fmt.Sprintf("New file appeared in monitored path (SHA256: %s)", hash),
				Timestamp:      time.Now().UTC(),
			})
		}
	} else if prevHash != hash {
		// Content hash changed
		s.baseline[path] = hash
		*events = append(*events, models.FIMEvent{
			EventType:      "modified",
			TargetType:     "file",
			TargetPath:     path,
			PreviousHash:   prevHash,
			CurrentHash:    hash,
			FileSizeBytes:  size,
			Permissions:    mode.String(),
			Severity:       s.computeSeverity(path),
			MITRETactic:    s.computeTactic(path),
			MITRETechnique: s.computeTechnique(path),
			Details:        fmt.Sprintf("Cryptographic hash mismatch detected! Previous: %s, Current: %s", prevHash, hash),
			Timestamp:      time.Now().UTC(),
		})
	}
}

func (s *Scanner) computeSeverity(path string) string {
	low := strings.ToLower(path)
	if strings.Contains(low, "shadow") || strings.Contains(low, "passwd") || strings.Contains(low, "sudoers") ||
		strings.Contains(low, "sshd_config") || strings.Contains(low, "hosts") {
		return "CRITICAL"
	}
	if strings.Contains(low, "cron") || strings.Contains(low, "systemd") || strings.Contains(low, "startup") ||
		strings.Contains(low, "launchdaemons") {
		return "HIGH"
	}
	return "MEDIUM"
}

func (s *Scanner) computeTactic(path string) string {
	low := strings.ToLower(path)
	if strings.Contains(low, "cron") || strings.Contains(low, "systemd") || strings.Contains(low, "startup") || strings.Contains(low, "launchdaemons") {
		return "Persistence"
	}
	if strings.Contains(low, "passwd") || strings.Contains(low, "shadow") || strings.Contains(low, "sudoers") {
		return "Privilege Escalation"
	}
	return "Defense Evasion"
}

func (s *Scanner) computeTechnique(path string) string {
	low := strings.ToLower(path)
	if strings.Contains(low, "cron") || strings.Contains(low, "systemd") {
		return "T1053"
	}
	if strings.Contains(low, "startup") || strings.Contains(low, "launchdaemons") {
		return "T1547.001"
	}
	if strings.Contains(low, "sudoers") || strings.Contains(low, "shadow") {
		return "T1548"
	}
	return "T1565.001"
}

func hashFile(filePath string) (string, int64, os.FileMode, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", 0, 0, err
	}

	// Limit hashing to max 50MB to prevent I/O choking on accidental large files
	if stat.Size() > 50*1024*1024 {
		return "", stat.Size(), stat.Mode(), fmt.Errorf("file exceeds 50MB limit")
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", stat.Size(), stat.Mode(), err
	}

	return hex.EncodeToString(h.Sum(nil)), stat.Size(), stat.Mode(), nil
}
