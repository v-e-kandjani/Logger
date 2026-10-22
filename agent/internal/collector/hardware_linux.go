//go:build linux

package collector

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

var (
	linuxCPUMu        sync.Mutex
	lastLinuxIdle     uint64
	lastLinuxTotal    uint64
	lastLinuxCPUTime  time.Time
	cachedLinuxCPU    float64 = 1.0
)

func collectHardware() models.AgentResourceMetrics {
	var metrics models.AgentResourceMetrics

	// 1. Process RAM RSS
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	metrics.RAMRSSBytes = memStats.Sys

	// 2. Host RAM Metrics (/proc/meminfo)
	if f, err := os.Open("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(f)
		var totalKB, availKB uint64
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					totalKB, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					availKB, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			}
		}
		f.Close()

		if totalKB > 0 {
			metrics.RAMTotalBytes = totalKB * 1024
			metrics.RAMUsedBytes = (totalKB - availKB) * 1024
			metrics.RAMPercent = float64(metrics.RAMUsedBytes) / float64(metrics.RAMTotalBytes) * 100.0
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

	// 4. Host CPU Load (/proc/stat)
	metrics.CPUPercent = sampleLinuxCPU()

	// 5. Uptime (/proc/uptime)
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				metrics.UptimeSeconds = uint64(secs)
			}
		}
	}

	return metrics
}

func sampleLinuxCPU() float64 {
	linuxCPUMu.Lock()
	defer linuxCPUMu.Unlock()

	f, err := os.Open("/proc/stat")
	if err != nil {
		return cachedLinuxCPU
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return cachedLinuxCPU
	}

	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cachedLinuxCPU
	}

	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		total += val
		if i == 4 { // idle is 4th field
			idle = val
		}
	}

	now := time.Now()
	if lastLinuxCPUTime.IsZero() {
		lastLinuxIdle = idle
		lastLinuxTotal = total
		lastLinuxCPUTime = now
		return cachedLinuxCPU
	}

	totalDiff := total - lastLinuxTotal
	idleDiff := idle - lastLinuxIdle

	lastLinuxIdle = idle
	lastLinuxTotal = total
	lastLinuxCPUTime = now

	if totalDiff > 0 {
		busy := totalDiff - idleDiff
		pct := float64(busy) / float64(totalDiff) * 100.0
		if pct > 100.0 {
			pct = 100.0
		}
		cachedLinuxCPU = pct
	}

	return cachedLinuxCPU
}

func IsRebootRequired() bool {
	_, err := os.Stat("/var/run/reboot-required")
	return err == nil
}
