package ransomware

import (
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// Shield orchestrates endpoint anti-ransomware protection, decoy honeypots, and threat containment
type Shield struct {
	mu            sync.Mutex
	canaryManager *CanaryManager
	lastIncidents []models.EndpointRansomwareIncident
}

// NewShield initializes the anti-ransomware shield and plants decoy honeypots
func NewShield() *Shield {
	cm := NewCanaryManager()
	_ = cm.DeployInitialCanaries()
	return &Shield{
		canaryManager: cm,
	}
}

// Inspect runs an active tripwire and heuristic check
func (s *Shield) Inspect() models.AgentRansomwareSubmission {
	s.mu.Lock()
	defer s.mu.Unlock()

	canaries, incidents := s.canaryManager.InspectCanaries()

	// Perform autonomous threat containment for any detected ransomware incidents
	for i := range incidents {
		if incidents[i].ProcessPID > 0 {
			s.terminateProcess(incidents[i].ProcessPID)
			incidents[i].ActionTaken = "TERMINATED"
		}
	}

	return models.AgentRansomwareSubmission{
		Incidents: incidents,
		Canaries:  canaries,
	}
}

// terminateProcess terminates malicious ransomware processes
func (s *Shield) terminateProcess(pid int) {
	if pid <= 0 {
		return
	}
	log.Printf("[Ransomware Shield] Forcefully terminating rogue ransomware process (PID: %d)", pid)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid))
	} else {
		cmd = exec.Command("kill", "-9", strconv.Itoa(pid))
	}
	_ = cmd.Run()
}

// QuarantineFile isolates an encrypted or malicious binary to a restricted quarantine vault
func (s *Shield) QuarantineFile(filePath string) error {
	vaultDir := "/var/logseal/quarantine"
	if runtime.GOOS == "windows" {
		vaultDir = `C:\ProgramData\Valtrivo\LogSeal\Quarantine`
	}
	_ = os.MkdirAll(vaultDir, 0700)

	target := vaultDir + string(os.PathSeparator) + time.Now().Format("20060102150405_") + "quarantined.bin"
	return os.Rename(filePath, target)
}
