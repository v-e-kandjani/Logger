package collector

import "github.com/syslog-platform/logger/internal/models"

// GetHostHardwareStats retrieves live CPU, RAM, Disk, and Reboot-required telemetry
func GetHostHardwareStats() models.AgentResourceMetrics {
	return collectHardware()
}
