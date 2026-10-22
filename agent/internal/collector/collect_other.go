//go:build !windows && !linux && !darwin

package collector

import (
	"github.com/syslog-platform/logger/internal/models"
)

func collectPlatformSpecific(req *models.AgentInventoryRequest) {
	req.OSName = req.OSType
}
