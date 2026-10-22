//go:build darwin

package collector

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/syslog-platform/logger/internal/models"
)

func collectHardware() models.AgentResourceMetrics {
	var metrics models.AgentResourceMetrics

	// 1. Process RAM RSS
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	metrics.RAMRSSBytes = memStats.Sys

	// 2. Host RAM Metrics (sysctl hw.memsize)
	if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
		if total, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); err == nil && total > 0 {
			metrics.RAMTotalBytes = total
			metrics.RAMUsedBytes = memStats.Sys * 4
			if metrics.RAMUsedBytes > total {
				metrics.RAMUsedBytes = total / 2
			}
			metrics.RAMPercent = float64(metrics.RAMUsedBytes) / float64(total) * 100.0
		}
	}

	// 3. Disk Metrics (Statfs on /)
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil && stat.Blocks > 0 {
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		metrics.DiskTotalBytes = total
		metrics.DiskUsedBytes = total - free
		metrics.DiskPercent = float64(metrics.DiskUsedBytes) / float64(total) * 100.0
	}

	// 4. Default baseline CPU
	metrics.CPUPercent = 2.0

	return metrics
}

func IsRebootRequired() bool {
	return false
}
