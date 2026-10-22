//go:build !windows && !linux && !darwin

package collector

import (
	"runtime"

	"github.com/syslog-platform/logger/internal/models"
)

func collectHardware() models.AgentResourceMetrics {
	var metrics models.AgentResourceMetrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	metrics.RAMRSSBytes = memStats.Sys
	metrics.CPUPercent = 1.0
	return metrics
}

func IsRebootRequired() bool {
	return false
}
