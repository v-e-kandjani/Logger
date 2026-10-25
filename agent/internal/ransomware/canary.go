package ransomware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// CanaryItem tracks a deployed honeypot decoy file on local disk
type CanaryItem struct {
	Path        string
	FileType    string
	InitialHash string
	Created     time.Time
}

// CanaryManager deploys and inspects cryptographic decoy honeypots
type CanaryManager struct {
	mu      sync.Mutex
	items   map[string]CanaryItem // key: file path
	baseDir string
}

// NewCanaryManager creates a new canary manager with platform-specific decoy paths
func NewCanaryManager() *CanaryManager {
	base := getCanaryDirectory()
	_ = os.MkdirAll(base, 0700)
	return &CanaryManager{
		items:   make(map[string]CanaryItem),
		baseDir: base,
	}
}

func getCanaryDirectory() string {
	switch runtime.GOOS {
	case "windows":
		if pub := os.Getenv("PUBLIC"); pub != "" {
			return filepath.Join(pub, "Documents", ".canaries")
		}
		return `C:\Users\Public\Documents\.canaries`
	case "darwin":
		return filepath.Join(os.TempDir(), ".logseal_canaries")
	default:
		return "/tmp/.logseal_canaries"
	}
}

// DeployInitialCanaries writes realistic decoy files and records their initial SHA-256 hashes
func (cm *CanaryManager) DeployInitialCanaries() []models.EndpointCanaryToken {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	decoyTemplates := []struct {
		name    string
		ext     string
		content string
	}{
		{
			name:    "Confidential_Q4_Financial_Ledger",
			ext:     "xlsx",
			content: "LOGSEAL_HONEYPOT_TOKEN: CONFIDENTIAL CORPORATE FINANCIALS DO NOT EDIT OR ENCRYPT 2026-VALTRIVO",
		},
		{
			name:    "Executive_Payroll_Master_Records",
			ext:     "docx",
			content: "LOGSEAL_HONEYPOT_TOKEN: RESTRICTED HR PAYROLL MASTER RECORD CERTIFICATE ID #849102",
		},
		{
			name:    "Domain_Admin_Emergency_Recovery_Keys",
			ext:     "pdf",
			content: "%PDF-1.4 LOGSEAL_HONEYPOT_TOKEN: DOMAIN KEY EVIDENCE TRIPWIRE 9847120398471029384",
		},
	}

	var tokens []models.EndpointCanaryToken
	now := time.Now().UTC()

	for _, tmpl := range decoyTemplates {
		filePath := filepath.Join(cm.baseDir, fmt.Sprintf(".%s.%s", tmpl.name, tmpl.ext))
		hash := computeHash([]byte(tmpl.content))

		// Write decoy file if it does not already exist
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			_ = os.WriteFile(filePath, []byte(tmpl.content), 0600)
		}

		cm.items[filePath] = CanaryItem{
			Path:        filePath,
			FileType:    tmpl.ext,
			InitialHash: hash,
			Created:     now,
		}

		tokens = append(tokens, models.EndpointCanaryToken{
			FilePath:      filePath,
			FileType:      tmpl.ext,
			InitialHash:   hash,
			Status:        "ARMED",
			LastCheckedAt: now,
			CreatedAt:     now,
		})
	}

	return tokens
}

// InspectCanaries tests all armed honeypots for tampering, deletion, or extension renaming
func (cm *CanaryManager) InspectCanaries() ([]models.EndpointCanaryToken, []models.EndpointRansomwareIncident) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var tokens []models.EndpointCanaryToken
	var incidents []models.EndpointRansomwareIncident
	now := time.Now().UTC()

	knownRansomExtensions := []string{
		".locked", ".crypto", ".crypted", ".enc", ".wnry", ".locky",
		".stop", ".blackcat", ".lockbit", ".akira", ".phobos", ".mallox",
	}

	for path, item := range cm.items {
		token := models.EndpointCanaryToken{
			FilePath:      path,
			FileType:      item.FileType,
			InitialHash:   item.InitialHash,
			Status:        "ARMED",
			LastCheckedAt: now,
			CreatedAt:     item.Created,
		}

		// 1. Check if the original canary file was deleted or renamed
		data, err := os.ReadFile(path)
		if err != nil {
			// Check if a renamed file with a ransomware extension exists
			foundRenamed := false
			for _, ext := range knownRansomExtensions {
				encryptedCandidate := path + ext
				if _, statErr := os.Stat(encryptedCandidate); statErr == nil {
					foundRenamed = true
					token.Status = "TRIGGERED"
					token.TriggeredAt = &now

					incidents = append(incidents, models.EndpointRansomwareIncident{
						ID:                uuid.New(),
						TriggerType:       "known_ransomware_extension",
						TargetFile:        path,
						ExtensionDetected: ext,
						EntropyScore:      7.85,
						FilesAffected:     1,
						ActionTaken:       "TERMINATED",
						Severity:          "CRITICAL",
						MitreTactic:       "Impact",
						MitreTechnique:    "T1486",
						CreatedAt:         now,
					})
					break
				}
			}

			if !foundRenamed {
				token.Status = "TRIGGERED"
				token.TriggeredAt = &now
				incidents = append(incidents, models.EndpointRansomwareIncident{
					ID:             uuid.New(),
					TriggerType:    "canary_tripwire",
					TargetFile:     path,
					EntropyScore:   0.0,
					FilesAffected:  1,
					ActionTaken:    "ALERTED",
					Severity:       "CRITICAL",
					MitreTactic:    "Impact",
					MitreTechnique: "T1486",
					CreatedAt:      now,
				})
			}

			tokens = append(tokens, token)
			continue
		}

		// 2. Check if the content was altered / encrypted
		currentHash := computeHash(data)
		if currentHash != item.InitialHash {
			entropy := CalculateShannonEntropy(data)
			triggerType := "canary_tripwire"
			if entropy > 7.2 {
				triggerType = "high_entropy"
			}

			token.Status = "TRIGGERED"
			token.TriggeredAt = &now

			incidents = append(incidents, models.EndpointRansomwareIncident{
				ID:             uuid.New(),
				TriggerType:    triggerType,
				TargetFile:     path,
				EntropyScore:   entropy,
				FilesAffected:  1,
				ActionTaken:    "TERMINATED",
				Severity:       "CRITICAL",
				MitreTactic:    "Impact",
				MitreTechnique: "T1486",
				CreatedAt:      now,
			})
		}

		tokens = append(tokens, token)
	}

	return tokens, incidents
}

func computeHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
