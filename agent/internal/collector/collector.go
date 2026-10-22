package collector

import (
	"runtime"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// Collect gathers complete host inventory, installed software, and patches
func Collect() (*models.AgentInventoryRequest, error) {
	req := &models.AgentInventoryRequest{
		Architecture: runtime.GOARCH,
		OSType:       runtime.GOOS,
		Software:     []models.AgentSoftwareItem{},
		Patches:      []models.AgentPatchItem{},
		SystemInfo:   map[string]interface{}{},
		HardwareInfo: map[string]interface{}{},
		NetworkInfo:  map[string]interface{}{},
	}

	collectPlatformSpecific(req)
	collectCommon(req)

	return req, nil
}

func collectCommon(req *models.AgentInventoryRequest) {
	req.SystemInfo["collected_at"] = time.Now().UTC().Format(time.RFC3339)
	req.SystemInfo["num_cpu"] = runtime.NumCPU()
	req.SystemInfo["go_version"] = runtime.Version()
}
