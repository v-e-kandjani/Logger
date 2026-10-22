//go:build windows

package collector

import (
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
	"github.com/syslog-platform/logger/internal/models"
)

var (
	kernel32DLL               = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatusEx  = kernel32DLL.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceExW   = kernel32DLL.NewProc("GetDiskFreeSpaceExW")
	procGetSystemTimes        = kernel32DLL.NewProc("GetSystemTimes")
	procGetTickCount64        = kernel32DLL.NewProc("GetTickCount64")

	cpuMu        sync.Mutex
	lastIdleTime int64
	lastKrnlTime int64
	lastUserTime int64
	lastCPUSample time.Time
	cachedCPUPercent float64 = 1.0
)

type memoryStatusEx struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type filetime struct {
	dwLowDateTime  uint32
	dwHighDateTime uint32
}

func (ft *filetime) toInt64() int64 {
	return int64(uint64(ft.dwHighDateTime)<<32 | uint64(ft.dwLowDateTime))
}

func collectHardware() models.AgentResourceMetrics {
	var metrics models.AgentResourceMetrics

	// 1. Process RAM RSS
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	metrics.RAMRSSBytes = memStats.Sys

	// 2. Host RAM Metrics (GlobalMemoryStatusEx)
	var memStatus memoryStatusEx
	memStatus.cbSize = uint32(unsafe.Sizeof(memStatus))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret != 0 {
		metrics.RAMTotalBytes = memStatus.ullTotalPhys
		metrics.RAMUsedBytes = memStatus.ullTotalPhys - memStatus.ullAvailPhys
		if memStatus.ullTotalPhys > 0 {
			metrics.RAMPercent = float64(metrics.RAMUsedBytes) / float64(memStatus.ullTotalPhys) * 100.0
		}
	}

	// 3. System Disk Metrics (GetDiskFreeSpaceExW for C:\)
	var freeBytes, totalBytes, totalFreeBytes uint64
	cPath, _ := syscall.UTF16PtrFromString("C:\\")
	retDisk, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(cPath)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if retDisk != 0 && totalBytes > 0 {
		metrics.DiskTotalBytes = totalBytes
		metrics.DiskUsedBytes = totalBytes - freeBytes
		metrics.DiskPercent = float64(metrics.DiskUsedBytes) / float64(totalBytes) * 100.0
	}

	// 4. Host CPU Load (GetSystemTimes)
	metrics.CPUPercent = sampleWindowsCPU()

	// 5. System Uptime (GetTickCount64)
	retTick, _, _ := procGetTickCount64.Call()
	if retTick > 0 {
		metrics.UptimeSeconds = uint64(retTick) / 1000
	}

	return metrics
}

func sampleWindowsCPU() float64 {
	cpuMu.Lock()
	defer cpuMu.Unlock()

	now := time.Now()
	var idle, kernel, user filetime
	r, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r == 0 {
		return cachedCPUPercent
	}

	currentIdle := idle.toInt64()
	currentKernel := kernel.toInt64()
	currentUser := user.toInt64()

	if lastCPUSample.IsZero() {
		lastIdleTime = currentIdle
		lastKrnlTime = currentKernel
		lastUserTime = currentUser
		lastCPUSample = now
		return cachedCPUPercent
	}

	idleDiff := currentIdle - lastIdleTime
	kernelDiff := currentKernel - lastKrnlTime
	userDiff := currentUser - lastUserTime

	lastIdleTime = currentIdle
	lastKrnlTime = currentKernel
	lastUserTime = currentUser
	lastCPUSample = now

	totalDiff := kernelDiff + userDiff
	if totalDiff > 0 {
		busy := totalDiff - idleDiff
		if busy > 0 {
			pct := float64(busy) / float64(totalDiff) * 100.0
			if pct > 100.0 {
				pct = 100.0
			}
			cachedCPUPercent = pct
		}
	}
	return cachedCPUPercent
}

// IsRebootRequired checks Windows Registry keys for pending reboots
func IsRebootRequired() bool {
	keys := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`},
	}

	for _, k := range keys {
		if key, err := registry.OpenKey(k.root, k.path, registry.READ); err == nil {
			key.Close()
			return true
		}
	}
	return false
}
