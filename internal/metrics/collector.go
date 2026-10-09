package metrics

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/syslog/pipeline"
)

// CPUCoreMetrics holds metrics for an individual CPU core
type CPUCoreMetrics struct {
	ID         int     `json:"id"`
	Name       string  `json:"name"`
	Percent    float64 `json:"percent"`
	Role       string  `json:"role"`
	IsReserved bool    `json:"is_reserved"`
}

// NetInterfaceMetrics holds metrics for an individual network interface
type NetInterfaceMetrics struct {
	Name            string  `json:"name"`
	RxBytes         uint64  `json:"rx_bytes"`
	RxPackets       uint64  `json:"rx_packets"`
	RxErrs          uint64  `json:"rx_errs"`
	RxDrop          uint64  `json:"rx_drop"`
	TxBytes         uint64  `json:"tx_bytes"`
	TxPackets       uint64  `json:"tx_packets"`
	TxErrs          uint64  `json:"tx_errs"`
	TxDrop          uint64  `json:"tx_drop"`
	NetInKBps       float64 `json:"net_in_kbps"`
	NetOutKBps      float64 `json:"net_out_kbps"`
	RxPacketsPerSec float64 `json:"rx_packets_per_sec"`
	TxPacketsPerSec float64 `json:"tx_packets_per_sec"`
}

// MetricPoint holds a single telemetry snapshot at a point in time
type MetricPoint struct {
	Timestamp        string  `json:"timestamp"`
	TimeEpoch        int64   `json:"time_epoch"`
	CPUPercent       float64 `json:"cpu_percent"`
	RAMUsedMB        float64 `json:"ram_used_mb"`
	RAMTotalMB       float64 `json:"ram_total_mb"`
	RAMPercent       float64 `json:"ram_percent"`
	LogsReceivedRate float64 `json:"logs_received_rate"` // EPS
	NetInKBps        float64 `json:"net_in_kbps"`        // Network Rx KB/s
	NetOutKBps       float64 `json:"net_out_kbps"`       // Network Tx KB/s
}

// CurrentMetrics holds current live stats
type CurrentMetrics struct {
	CPUPercent       float64               `json:"cpu_percent"`
	RAMUsedMB        float64               `json:"ram_used_mb"`
	RAMTotalMB       float64               `json:"ram_total_mb"`
	RAMPercent       float64               `json:"ram_percent"`
	LogsReceivedRate float64               `json:"logs_received_rate"`
	TotalPacketsRx   uint64                `json:"total_packets_rx"`
	NetInKBps        float64               `json:"net_in_kbps"`
	NetOutKBps       float64               `json:"net_out_kbps"`
	CPUCores         int                   `json:"cpu_cores"`
	GOMAXPROCS       int                   `json:"gomaxprocs"`
	ReservedCore     bool                  `json:"reserved_core"`
	OS               string                `json:"os"`
	Timestamp        string                `json:"timestamp"`
	CPUCoresList     []CPUCoreMetrics      `json:"cpu_cores_list"`
	NetInterfaces    []NetInterfaceMetrics `json:"net_interfaces"`
}

// HistoryResponse returns time-series arrays optimized for graphing
type HistoryResponse struct {
	Current   CurrentMetrics `json:"current"`
	Points    []MetricPoint  `json:"points"`
	MaxPoints int            `json:"max_points"`
}

type ifaceSample struct {
	rxBytes   uint64
	rxPackets uint64
	txBytes   uint64
	txPackets uint64
}

// Collector continuously gathers host and daemon telemetry
type Collector struct {
	pipe       *pipeline.Pipeline
	maxHistory int
	mu         sync.RWMutex
	history    []MetricPoint
	current    CurrentMetrics
	stopCh     chan struct{}

	// Previous sample state for delta calculations
	lastSampleTime time.Time
	prevCPUTotal   uint64
	prevCPUIdle    uint64
	prevPacketsRx  uint64
	prevNetRxBytes uint64
	prevNetTxBytes uint64

	prevCoreTotals map[string]uint64
	prevCoreIdles  map[string]uint64
	prevIfaceStats map[string]ifaceSample
}

// NewCollector initializes collector with pipeline binding
func NewCollector(pipe *pipeline.Pipeline) *Collector {
	return &Collector{
		pipe:       pipe,
		maxHistory: 60, // 60 data points (2 minutes at 2s interval)
		history:    make([]MetricPoint, 0, 60),
		stopCh:     make(chan struct{}),
	}
}

// Start begins the periodic metrics sampling loop
func (c *Collector) Start(ctx context.Context) {
	// Initial baseline sample
	c.sample()

	ticker := time.NewTicker(2 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.sample()
			}
		}
	}()
}

// Stop stops the collector
func (c *Collector) Stop() {
	close(c.stopCh)
}

// sample collects one round of system telemetry
func (c *Collector) sample() {
	now := time.Now().UTC()
	var timeDeltaSec float64 = 2.0
	if !c.lastSampleTime.IsZero() {
		timeDeltaSec = now.Sub(c.lastSampleTime).Seconds()
		if timeDeltaSec <= 0.1 {
			timeDeltaSec = 2.0
		}
	}
	c.lastSampleTime = now

	onlineCores := getOnlineCPUCores()
	currentMaxProcs := runtime.GOMAXPROCS(0)
	reservedCore := onlineCores > 1 && currentMaxProcs < onlineCores

	// 1. CPU Utilization (Total & Per-Core)
	cpuPct, cpuCoresList := c.readCPUMetrics(reservedCore, currentMaxProcs)

	// 2. RAM Memory Utilization
	ramUsedMB, ramTotalMB, ramPct := c.readMemory()

	// 3. Syslog Logs Ingestion Rate (EPS)
	var totalPackets uint64
	var logsRate float64
	if c.pipe != nil {
		totalPackets = c.pipe.PacketsReceived.Load()
		if c.prevPacketsRx > 0 && totalPackets >= c.prevPacketsRx {
			logsRate = float64(totalPackets-c.prevPacketsRx) / timeDeltaSec
		} else if c.prevPacketsRx == 0 {
			logsRate = 0
		}
		c.prevPacketsRx = totalPackets
	}

	// 4. Network Throughput (In / Out in KB/s & Per-Interface statistics)
	netInKBps, netOutKBps, netIfacesList := c.readNetworkThroughput(timeDeltaSec)

	// Format timestamp
	tsStr := now.Format("15:04:05")

	point := MetricPoint{
		Timestamp:        tsStr,
		TimeEpoch:        now.Unix(),
		CPUPercent:       math.Round(cpuPct*10) / 10,
		RAMUsedMB:        math.Round(ramUsedMB*10) / 10,
		RAMTotalMB:       math.Round(ramTotalMB*10) / 10,
		RAMPercent:       math.Round(ramPct*10) / 10,
		LogsReceivedRate: math.Round(logsRate*10) / 10,
		NetInKBps:        math.Round(netInKBps*10) / 10,
		NetOutKBps:       math.Round(netOutKBps*10) / 10,
	}

	current := CurrentMetrics{
		CPUPercent:       point.CPUPercent,
		RAMUsedMB:        point.RAMUsedMB,
		RAMTotalMB:       point.RAMTotalMB,
		RAMPercent:       point.RAMPercent,
		LogsReceivedRate: point.LogsReceivedRate,
		TotalPacketsRx:   totalPackets,
		NetInKBps:        point.NetInKBps,
		NetOutKBps:       point.NetOutKBps,
		CPUCores:         onlineCores,
		GOMAXPROCS:       currentMaxProcs,
		ReservedCore:     reservedCore,
		OS:               runtime.GOOS,
		Timestamp:        tsStr,
		CPUCoresList:     cpuCoresList,
		NetInterfaces:    netIfacesList,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.current = current
	c.history = append(c.history, point)
	if len(c.history) > c.maxHistory {
		c.history = c.history[len(c.history)-c.maxHistory:]
	}
}

// readCPUMetrics reads /proc/stat on Linux or generates fallback stats per core
func (c *Collector) readCPUMetrics(reservedCore bool, gomaxprocs int) (float64, []CPUCoreMetrics) {
	statBytes, err := os.ReadFile("/proc/stat")
	if err != nil {
		// Non-Linux fallback
		totalPct := fallbackCPU()
		cores := getOnlineCPUCores()
		coresList := make([]CPUCoreMetrics, cores)
		for i := 0; i < cores; i++ {
			isRes := reservedCore && i == cores-1
			role := "Worker Thread"
			if isRes {
				role = "Reserved for OS / Management"
			}
			var pct float64
			if cores > 1 {
				pct = totalPct + float64((i*7)%5) - 2.0
				if pct < 0.5 {
					pct = 0.5
				}
				if pct > 99.5 {
					pct = 99.5
				}
			} else {
				pct = totalPct
			}
			coresList[i] = CPUCoreMetrics{
				ID:         i,
				Name:       fmt.Sprintf("CPU Core %d", i),
				Percent:    math.Round(pct*10) / 10,
				Role:       role,
				IsReserved: isRes,
			}
		}
		return totalPct, coresList
	}

	scanner := bufio.NewScanner(bytes.NewReader(statBytes))
	var totalCPU float64
	coresMap := make(map[int]float64)
	coreIndices := make([]int, 0)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		if fields[0] == "cpu" {
			total, idle := parseCPULine(fields)
			if c.prevCPUTotal > 0 && total > c.prevCPUTotal {
				deltaTotal := total - c.prevCPUTotal
				deltaIdle := idle - c.prevCPUIdle
				if deltaTotal > deltaIdle {
					totalCPU = float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100.0
				}
			}
			c.prevCPUTotal = total
			c.prevCPUIdle = idle
			continue
		}

		if strings.HasPrefix(fields[0], "cpu") {
			coreNumStr := strings.TrimPrefix(fields[0], "cpu")
			coreID, err := strconv.Atoi(coreNumStr)
			if err != nil {
				continue
			}

			total, idle := parseCPULine(fields)
			coreKey := fields[0]
			if c.prevCoreTotals == nil {
				c.prevCoreTotals = make(map[string]uint64)
				c.prevCoreIdles = make(map[string]uint64)
			}

			prevTotal := c.prevCoreTotals[coreKey]
			prevIdle := c.prevCoreIdles[coreKey]

			var corePct float64
			if prevTotal > 0 && total > prevTotal {
				deltaTotal := total - prevTotal
				deltaIdle := idle - prevIdle
				if deltaTotal > deltaIdle {
					corePct = float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100.0
				}
			}
			c.prevCoreTotals[coreKey] = total
			c.prevCoreIdles[coreKey] = idle

			coresMap[coreID] = math.Round(corePct*10) / 10
			coreIndices = append(coreIndices, coreID)
		}
	}

	sort.Ints(coreIndices)
	numCores := len(coreIndices)
	coresList := make([]CPUCoreMetrics, 0, numCores)
	for idx, coreID := range coreIndices {
		isRes := reservedCore && idx == numCores-1
		role := "Worker Thread"
		if isRes {
			role = "Reserved for OS / Management"
		}
		coresList = append(coresList, CPUCoreMetrics{
			ID:         coreID,
			Name:       fmt.Sprintf("CPU Core %d", coreID),
			Percent:    coresMap[coreID],
			Role:       role,
			IsReserved: isRes,
		})
	}

	return totalCPU, coresList
}

func parseCPULine(fields []string) (total uint64, idle uint64) {
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		total += val
		if i == 4 || i == 5 { // idle & iowait
			idle += val
		}
	}
	return total, idle
}

// readMemory reads /proc/meminfo on Linux or runtime.MemStats on non-Linux
func (c *Collector) readMemory() (usedMB, totalMB, pct float64) {
	memBytes, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		// Non-Linux fallback using Go runtime
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		usedMB = float64(m.Alloc) / (1024 * 1024)
		totalMB = float64(m.Sys) / (1024 * 1024)
		if totalMB < usedMB*2 {
			totalMB = usedMB * 2
		}
		if totalMB > 0 {
			pct = (usedMB / totalMB) * 100
		}
		return usedMB, totalMB, pct
	}

	var memTotalKB, memAvailKB, memFreeKB, buffersKB, cachedKB uint64
	scanner := bufio.NewScanner(bytes.NewReader(memBytes))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			val, _ := strconv.ParseUint(parts[1], 10, 64)
			switch parts[0] {
			case "MemTotal:":
				memTotalKB = val
			case "MemAvailable:":
				memAvailKB = val
			case "MemFree:":
				memFreeKB = val
			case "Buffers:":
				buffersKB = val
			case "Cached:":
				cachedKB = val
			}
		}
	}

	totalMB = float64(memTotalKB) / 1024.0
	if memAvailKB > 0 {
		usedMB = float64(memTotalKB-memAvailKB) / 1024.0
	} else if memFreeKB > 0 {
		usedMB = float64(memTotalKB-(memFreeKB+buffersKB+cachedKB)) / 1024.0
	}
	if totalMB > 0 {
		pct = (usedMB / totalMB) * 100.0
	}
	return usedMB, totalMB, pct
}

// readNetworkThroughput reads /proc/net/dev on Linux or returns interface metrics
func (c *Collector) readNetworkThroughput(deltaSec float64) (float64, float64, []NetInterfaceMetrics) {
	netBytes, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		// Non-Linux fallback
		return 0, 0, []NetInterfaceMetrics{}
	}

	var totalRx uint64
	var totalTx uint64
	var totalInKBps float64
	var totalOutKBps float64

	if c.prevIfaceStats == nil {
		c.prevIfaceStats = make(map[string]ifaceSample)
	}

	ifaces := make([]NetInterfaceMetrics, 0)

	scanner := bufio.NewScanner(bytes.NewReader(netBytes))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		ifaceName := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}

		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		rxErrs, _ := strconv.ParseUint(fields[2], 10, 64)
		rxDrop, _ := strconv.ParseUint(fields[3], 10, 64)

		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[9], 10, 64)
		txErrs, _ := strconv.ParseUint(fields[10], 10, 64)
		txDrop, _ := strconv.ParseUint(fields[11], 10, 64)

		if ifaceName != "lo" {
			totalRx += rxBytes
			totalTx += txBytes
		}

		prev := c.prevIfaceStats[ifaceName]
		var inKBps, outKBps, rxPps, txPps float64

		if prev.rxBytes > 0 && rxBytes >= prev.rxBytes && deltaSec > 0 {
			inKBps = float64(rxBytes-prev.rxBytes) / deltaSec / 1024.0
			rxPps = float64(rxPackets-prev.rxPackets) / deltaSec
		}
		if prev.txBytes > 0 && txBytes >= prev.txBytes && deltaSec > 0 {
			outKBps = float64(txBytes-prev.txBytes) / deltaSec / 1024.0
			txPps = float64(txPackets-prev.txPackets) / deltaSec
		}

		c.prevIfaceStats[ifaceName] = ifaceSample{
			rxBytes:   rxBytes,
			rxPackets: rxPackets,
			txBytes:   txBytes,
			txPackets: txPackets,
		}

		if ifaceName != "lo" {
			totalInKBps += inKBps
			totalOutKBps += outKBps
		}

		ifaces = append(ifaces, NetInterfaceMetrics{
			Name:            ifaceName,
			RxBytes:         rxBytes,
			RxPackets:       rxPackets,
			RxErrs:          rxErrs,
			RxDrop:          rxDrop,
			TxBytes:         txBytes,
			TxPackets:       txPackets,
			TxErrs:          txErrs,
			TxDrop:          txDrop,
			NetInKBps:       math.Round(inKBps*10) / 10,
			NetOutKBps:      math.Round(outKBps*10) / 10,
			RxPacketsPerSec: math.Round(rxPps*10) / 10,
			TxPacketsPerSec: math.Round(txPps*10) / 10,
		})
	}

	c.prevNetRxBytes = totalRx
	c.prevNetTxBytes = totalTx

	return totalInKBps, totalOutKBps, ifaces
}

// fallbackCPU generates smooth fallback CPU stats for dev environments
func fallbackCPU() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return math.Min(95.0, 5.0+float64(m.NumGC%20))
}

// GetHistory returns historical data points and current snapshot
func (c *Collector) GetHistory() HistoryResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pointsCopy := make([]MetricPoint, len(c.history))
	copy(pointsCopy, c.history)

	return HistoryResponse{
		Current:   c.current,
		Points:    pointsCopy,
		MaxPoints: c.maxHistory,
	}
}

// GetCurrent returns latest snapshot
func (c *Collector) GetCurrent() CurrentMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// getOnlineCPUCores dynamically reads the number of active online CPUs from the Linux kernel
// to support CPU hot-plugging without requiring binary or container restart, falling back to runtime.NumCPU().
func getOnlineCPUCores() int {
	// 1. Check /sys/devices/system/cpu/online (e.g. "0-3" or "0-1,2-3")
	if data, err := os.ReadFile("/sys/devices/system/cpu/online"); err == nil {
		if cores := parseCPUOnlineRange(strings.TrimSpace(string(data))); cores > 0 {
			return cores
		}
	}

	// 2. Count active core lines in /proc/stat (cpu0, cpu1, cpu2, cpu3...)
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		count := 0
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) > 3 && line[:3] == "cpu" && line[3] >= '0' && line[3] <= '9' {
				count++
			}
		}
		if count > 0 {
			return count
		}
	}

	// 3. Fallback to runtime.NumCPU()
	return runtime.NumCPU()
}

// parseCPUOnlineRange parses a Linux CPU range string like "0-3", "0-1,2-3", or "0"
func parseCPUOnlineRange(s string) int {
	if s == "" {
		return 0
	}
	total := 0
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(rangeParts[0])
				end, err2 := strconv.Atoi(rangeParts[1])
				if err1 == nil && err2 == nil && end >= start {
					total += (end - start + 1)
					continue
				}
			}
		}
		if _, err := strconv.Atoi(part); err == nil {
			total++
		}
	}
	return total
}

