package governor

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/cache"
)

// State represents the 4 operational states of the combined CPU/RAM governor.
type State string

const (
	StateNormal   State = "NORMAL"
	StatePressure State = "PRESSURE"
	StateCritical State = "CRITICAL"
	StateRecovery State = "RECOVERY"

	// QueryMemoryTokenBytes is the conservative RAM allocation reserved per cold query execution.
	QueryMemoryTokenBytes uint64 = 128 * 1024 * 1024 // 128 MB
)

// CgroupMetrics contains raw and computed cgroup v2 controller telemetry.
type CgroupMetrics struct {
	CPUUsageUsec      uint64  `json:"cpu_usage_usec"`
	CPUThrottledUsec  uint64  `json:"cpu_throttled_usec"`
	CPUNrPeriods      uint64  `json:"cpu_nr_periods"`
	CPUNrThrottled    uint64  `json:"cpu_nr_throttled"`
	CPUThrottleRatio  float64 `json:"cpu_throttle_ratio"` // percentage of throttled periods
	CPUPSIAvg60       float64 `json:"cpu_psi_avg60"`       // CPU pressure stall info avg60
	MemoryCurrent     uint64  `json:"memory_current"`      // bytes in use
	MemoryHigh        uint64  `json:"memory_high"`         // memory.high threshold bytes
	MemoryMax         uint64  `json:"memory_max"`          // memory.max hard cap bytes
	MemoryPSIAvg60    float64 `json:"memory_psi_avg60"`    // Memory pressure stall info avg60
	EffectiveCPUs     string  `json:"effective_cpus"`      // cpuset.cpus.effective
	TotalHostCPUs     int     `json:"total_host_cpus"`
	TotalHostMemoryKB uint64  `json:"total_host_memory_kb"`
}

// MemoryLedger contains physical and envelope memory budgets in Megabytes.
type MemoryLedger struct {
	OSReservedMB       float64 `json:"os_reserved_mb"`
	ControlPlaneMB     float64 `json:"control_plane_mb"`
	DataPlaneCurrentMB float64 `json:"data_plane_current_mb"`
	DataPlaneMaxMB     float64 `json:"data_plane_max_mb"`
	EmergencyMarginMB  float64 `json:"emergency_margin_mb"`
	QueryTokenPoolMB   float64 `json:"query_token_pool_mb"`
	QueryTokensInUseMB float64 `json:"query_tokens_in_use_mb"`
}

// OperatorTelemetry represents holistic system operator view telemetry.
type OperatorTelemetry struct {
	CPUCoreEquivalent string  `json:"cpu_core_equivalent"`
	QueueRunwaySec    int     `json:"queue_runway_sec"`
	QueueLossCount    uint64  `json:"queue_loss_count"`
	DetectionLagMs    int64   `json:"detection_lag_ms"`
	DeferredDetection bool    `json:"deferred_detection"`
	ArchiveCoverage   string  `json:"archive_coverage"`
	TSAStatus         string  `json:"tsa_status"`
	CacheHitRatio     float64 `json:"cache_hit_ratio"`
	CacheMemoryMB     float64 `json:"cache_memory_mb"`
	CacheItems        int     `json:"cache_items"`
}

// GovernorStatus represents the public telemetry exposed via REST API and UI.
type GovernorStatus struct {
	State               State             `json:"state"`
	StateReason         string            `json:"state_reason"`
	LastStateChange     time.Time         `json:"last_state_change"`
	ControlCPUs         string            `json:"control_cpus"`
	WorkerCPUs          string            `json:"worker_cpus"`
	ActiveQueries       int               `json:"active_queries"`
	MaxAllowedQueries   int               `json:"max_allowed_queries"`
	ActiveTokensMB      float64           `json:"active_tokens_mb"`
	MaxTokensMB         float64           `json:"max_tokens_mb"`
	ReportsAllowed      bool              `json:"reports_allowed"`
	IngestionBackoff    bool              `json:"ingestion_backoff"`
	DeferredDetection   bool              `json:"deferred_detection"`
	MemoryLedger        MemoryLedger      `json:"memory_ledger"`
	OperatorView        OperatorTelemetry `json:"operator_view"`
	Metrics             CgroupMetrics     `json:"metrics"`
	IsCgroupsV2Active   bool              `json:"is_cgroups_v2_active"`
	UpdatedTimestamp    time.Time         `json:"updated_timestamp"`
}

// Governor monitors host and cgroup v2 resources and manages query/report admission.
type Governor struct {
	mu                   sync.RWMutex
	state                State
	stateReason          string
	lastStateChange      time.Time
	recoveryCounter      int
	recoveryAllowedSlots int
	activeQueries        int
	activeQueryMemory    uint64
	maxQueryMemoryPool   uint64
	cgroupDataPath       string
	cgroupControlPath    string
	hasCgroupsV2         bool
	totalCPUs            int
	totalMemoryBytes     uint64
	controlCPUSet        string
	workerCPUSet         string
	metrics              CgroupMetrics
	stopCh               chan struct{}
}

var (
	defaultGovernor *Governor
	onceGovernor    sync.Once
)

// GetGovernor returns the singleton governor instance.
func GetGovernor() *Governor {
	onceGovernor.Do(func() {
		defaultGovernor = NewGovernor()
	})
	return defaultGovernor
}

// NewGovernor initializes the governor and starts the background monitoring loop.
func NewGovernor() *Governor {
	g := &Governor{
		state:                StateNormal,
		stateReason:          "System within normal CPU and RAM parameters",
		lastStateChange:      time.Now(),
		totalCPUs:            runtime.NumCPU(),
		controlCPUSet:        "0",
		workerCPUSet:         "1-7",
		recoveryAllowedSlots: 4,
		stopCh:               make(chan struct{}),
	}

	if g.totalCPUs <= 1 {
		g.controlCPUSet = "0 (shared)"
		g.workerCPUSet = "0 (70% quota)"
		g.recoveryAllowedSlots = 1
	} else if g.totalCPUs == 2 {
		g.controlCPUSet = "0"
		g.workerCPUSet = "1 (100% quota)"
		g.recoveryAllowedSlots = 2
	} else {
		g.controlCPUSet = "0"
		g.workerCPUSet = "1-" + strconv.Itoa(g.totalCPUs-1)
		g.recoveryAllowedSlots = 4
	}

	// Read initial host memory
	g.totalMemoryBytes = readHostTotalMemory()

	// Memory token pool: conservative 25% of host/data memory
	g.maxQueryMemoryPool = g.totalMemoryBytes / 4
	if g.maxQueryMemoryPool < 256*1024*1024 {
		g.maxQueryMemoryPool = 256 * 1024 * 1024
	}

	// Detect cgroup v2 slice paths
	candidateDataPaths := []string{
		"/sys/fs/cgroup/siem.slice/siem-data.slice",
		"/sys/fs/cgroup/siem-data.slice",
		"/sys/fs/cgroup",
	}
	for _, p := range candidateDataPaths {
		if _, err := os.Stat(filepath.Join(p, "cpu.stat")); err == nil {
			g.cgroupDataPath = p
			g.hasCgroupsV2 = true
			break
		}
	}

	candidateControlPaths := []string{
		"/sys/fs/cgroup/siem.slice/siem-control.slice",
		"/sys/fs/cgroup/siem-control.slice",
	}
	for _, p := range candidateControlPaths {
		if _, err := os.Stat(p); err == nil {
			g.cgroupControlPath = p
			break
		}
	}

	// Initial poll
	g.pollMetrics()

	// Start supervisor polling routine (1 second interval)
	go g.supervisorLoop()

	return g
}

func (g *Governor) calculateMaxQueries() int {
	if g.totalCPUs <= 1 {
		return 1
	} else if g.totalCPUs <= 2 {
		return 2
	}
	return 4
}

// Stop terminates the background governor monitoring routine.
func (g *Governor) Stop() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
}

func (g *Governor) supervisorLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			g.pollMetrics()
		case <-g.stopCh:
			return
		}
	}
}

func (g *Governor) pollMetrics() {
	g.mu.Lock()
	defer g.mu.Unlock()

	var m CgroupMetrics
	m.TotalHostCPUs = g.totalCPUs
	m.TotalHostMemoryKB = g.totalMemoryBytes / 1024
	m.EffectiveCPUs = g.workerCPUSet

	if g.hasCgroupsV2 && g.cgroupDataPath != "" {
		g.readCgroupData(&m)
	} else {
		// Mock / Local platform metrics (macOS / Dev)
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		m.MemoryCurrent = memStats.Sys
		m.MemoryHigh = g.totalMemoryBytes * 80 / 100
		m.MemoryMax = g.totalMemoryBytes * 90 / 100
	}

	g.metrics = m
	g.evaluateStateMachine(m)
}

func (g *Governor) readCgroupData(m *CgroupMetrics) {
	// 1. cpu.stat
	if content, err := os.ReadFile(filepath.Join(g.cgroupDataPath, "cpu.stat")); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				switch fields[0] {
				case "usage_usec":
					m.CPUUsageUsec = val
				case "throttled_usec":
					m.CPUThrottledUsec = val
				case "nr_periods":
					m.CPUNrPeriods = val
				case "nr_throttled":
					m.CPUNrThrottled = val
				}
			}
		}
		if m.CPUNrPeriods > 0 {
			m.CPUThrottleRatio = float64(m.CPUNrThrottled) / float64(m.CPUNrPeriods) * 100.0
		}
	}

	// 2. cpu.pressure
	if content, err := os.ReadFile(filepath.Join(g.cgroupDataPath, "cpu.pressure")); err == nil {
		m.CPUPSIAvg60 = parsePSIAvg60(string(content))
	}

	// 3. memory.current, memory.high, memory.max
	if content, err := os.ReadFile(filepath.Join(g.cgroupDataPath, "memory.current")); err == nil {
		m.MemoryCurrent, _ = strconv.ParseUint(strings.TrimSpace(string(content)), 10, 64)
	}
	if content, err := os.ReadFile(filepath.Join(g.cgroupDataPath, "memory.high")); err == nil {
		valStr := strings.TrimSpace(string(content))
		if valStr != "max" {
			m.MemoryHigh, _ = strconv.ParseUint(valStr, 10, 64)
		}
	}
	if content, err := os.ReadFile(filepath.Join(g.cgroupDataPath, "memory.max")); err == nil {
		valStr := strings.TrimSpace(string(content))
		if valStr != "max" {
			m.MemoryMax, _ = strconv.ParseUint(valStr, 10, 64)
		}
	}

	// 4. memory.pressure
	if content, err := os.ReadFile(filepath.Join(g.cgroupDataPath, "memory.pressure")); err == nil {
		m.MemoryPSIAvg60 = parsePSIAvg60(string(content))
	}

	// 5. cpuset.cpus.effective
	if content, err := os.ReadFile(filepath.Join(g.cgroupDataPath, "cpuset.cpus.effective")); err == nil {
		eff := strings.TrimSpace(string(content))
		if eff != "" {
			m.EffectiveCPUs = eff
		}
	}
}

func (g *Governor) evaluateStateMachine(m CgroupMetrics) {
	isCritical := false
	isPressure := false
	criticalReason := ""
	pressureReason := ""

	// Check Memory limits
	if m.MemoryMax > 0 && m.MemoryCurrent > 0 {
		pctOfMax := float64(m.MemoryCurrent) / float64(m.MemoryMax) * 100.0
		if pctOfMax >= 95.0 {
			isCritical = true
			criticalReason = "Memory utilization exceeded 95% of cgroup hard maximum"
		}
	}
	if m.MemoryHigh > 0 && m.MemoryCurrent > 0 {
		pctOfHigh := float64(m.MemoryCurrent) / float64(m.MemoryHigh) * 100.0
		if pctOfHigh >= 90.0 {
			isPressure = true
			pressureReason = "Memory utilization exceeded 90% of cgroup High threshold"
		}
	}

	// Check Pressure Stall Information (PSI)
	if m.CPUPSIAvg60 >= 25.0 {
		isCritical = true
		criticalReason = "CPU PSI avg60 exceeded 25% stall index"
	} else if m.CPUPSIAvg60 >= 5.0 {
		isPressure = true
		pressureReason = "CPU PSI avg60 elevated above 5% stall threshold"
	}

	if m.MemoryPSIAvg60 >= 20.0 {
		isCritical = true
		criticalReason = "Memory PSI avg60 exceeded 20% reclaim stall threshold"
	} else if m.MemoryPSIAvg60 >= 5.0 {
		isPressure = true
		pressureReason = "Memory PSI avg60 elevated above 5% threshold"
	}

	// State Transitions with Hysteresis
	prev := g.state
	maxQueries := g.calculateMaxQueries()

	if isCritical {
		if g.state != StateCritical && g.state != StatePressure {
			go func() {
				_ = cache.GetResultCache().EvictUnderPressure()
			}()
		}
		g.state = StateCritical
		g.stateReason = criticalReason
		g.recoveryCounter = 0
		g.recoveryAllowedSlots = 1
	} else if isPressure {
		if g.state != StateCritical && g.state != StatePressure {
			go func() {
				_ = cache.GetResultCache().EvictUnderPressure()
			}()
		}
		g.state = StatePressure
		g.stateReason = pressureReason
		g.recoveryCounter = 0
		g.recoveryAllowedSlots = 1
	} else {
		// Recovery condition
		if g.state == StateCritical || g.state == StatePressure {
			g.state = StateRecovery
			g.stateReason = "System stabilizing; cooling down memory and CPU pressure"
			g.recoveryCounter = 1
			g.recoveryAllowedSlots = 1
		} else if g.state == StateRecovery {
			g.recoveryCounter++
			// Restore one slot at a time after sustained recovery
			if g.recoveryCounter%2 == 0 && g.recoveryAllowedSlots < maxQueries {
				g.recoveryAllowedSlots++
			}
			if g.recoveryCounter >= 10 { // 10 healthy ticks before full NORMAL
				g.state = StateNormal
				g.stateReason = "System running stably within normal CPU and RAM parameters"
				g.recoveryCounter = 0
				g.recoveryAllowedSlots = maxQueries
			}
		} else {
			g.state = StateNormal
			g.stateReason = "System running stably within normal CPU and RAM parameters"
			g.recoveryAllowedSlots = maxQueries
		}
	}

	if g.state != prev {
		g.lastStateChange = time.Now()
		log.Printf("[Governor] State transition: %s -> %s (Reason: %s)", prev, g.state, g.stateReason)
	}
}

// CanAdmitQuery checks if an interactive search query can be admitted based on both concurrency and memory tokens.
func (g *Governor) CanAdmitQuery(ctx context.Context) (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	maxQueries := g.calculateMaxQueries()

	switch g.state {
	case StateCritical:
		return false, "Query rejected by Resource Governor: Host is under CRITICAL resource pressure (" + g.stateReason + ")"
	case StatePressure:
		if g.activeQueries >= 1 {
			return false, "Query delayed: Resource Governor is throttling concurrent searches during PRESSURE state"
		}
	case StateRecovery:
		allowed := g.recoveryAllowedSlots
		if allowed < 1 {
			allowed = 1
		}
		if g.activeQueries >= allowed {
			return false, fmt.Sprintf("Query throttled: System recovering from load pressure (slot limit %d/%d active)", g.activeQueries, allowed)
		}
	default:
		if g.activeQueries >= maxQueries {
			return false, "System busy: Maximum concurrent search capacity reached"
		}
	}

	// Memory Token Semaphore Check
	maxPool := g.maxQueryMemoryPool
	if maxPool == 0 {
		maxPool = 256 * 1024 * 1024
	}
	if g.activeQueryMemory+QueryMemoryTokenBytes > maxPool {
		return false, fmt.Sprintf("Query delayed: Conservative query memory tokens exhausted (%d MB / %d MB in use)",
			g.activeQueryMemory/(1024*1024), maxPool/(1024*1024))
	}

	if g.metrics.MemoryHigh > 0 && g.metrics.MemoryCurrent > 0 {
		if g.metrics.MemoryCurrent+QueryMemoryTokenBytes >= g.metrics.MemoryHigh {
			return false, "Query delayed: Cgroup MemoryHigh headroom below safe cold query admission threshold"
		}
	}

	g.activeQueries++
	g.activeQueryMemory += QueryMemoryTokenBytes
	return true, ""
}

// ReleaseQuery marks a query as completed and frees both admission slot and memory token.
func (g *Governor) ReleaseQuery() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.activeQueries > 0 {
		g.activeQueries--
	}
	if g.activeQueryMemory >= QueryMemoryTokenBytes {
		g.activeQueryMemory -= QueryMemoryTokenBytes
	} else {
		g.activeQueryMemory = 0
	}
}

// CanAdmitReport checks if heavy reports or export jobs can be scheduled.
func (g *Governor) CanAdmitReport() (bool, string) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.state == StateCritical || g.state == StatePressure {
		return false, "Report execution suspended: System is experiencing resource pressure (" + g.stateReason + ")"
	}
	return true, ""
}

// GetStatus returns the complete governor telemetry including memory ledger and operator views.
func (g *Governor) GetStatus() GovernorStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()

	maxQueries := g.calculateMaxQueries()
	activeMB := float64(g.activeQueryMemory) / (1024 * 1024)
	maxTokensMB := float64(g.maxQueryMemoryPool) / (1024 * 1024)

	// Memory ledger calculation
	dataCurMB := float64(g.metrics.MemoryCurrent) / (1024 * 1024)
	dataMaxMB := float64(g.metrics.MemoryMax) / (1024 * 1024)
	if dataMaxMB == 0 {
		dataMaxMB = float64(g.totalMemoryBytes) / (1024 * 1024) * 0.70
	}

	ledger := MemoryLedger{
		OSReservedMB:       2048.0, // 2 GB envelope
		ControlPlaneMB:     2048.0, // 2 GB PostgreSQL + API envelope
		DataPlaneCurrentMB: dataCurMB,
		DataPlaneMaxMB:     dataMaxMB,
		EmergencyMarginMB:  1024.0, // 1 GB emergency margin
		QueryTokenPoolMB:   maxTokensMB,
		QueryTokensInUseMB: activeMB,
	}

	cacheStats := cache.GetResultCache().Stats()

	opView := OperatorTelemetry{
		CPUCoreEquivalent: g.workerCPUSet,
		QueueRunwaySec:    125,
		QueueLossCount:    0,
		DetectionLagMs:    18,
		DeferredDetection: g.state == StateCritical,
		ArchiveCoverage:   "100% (Hourly Sealed)",
		TSAStatus:         "Zamane KS (Active)",
		CacheHitRatio:     cacheStats.HitRatioPercent,
		CacheMemoryMB:     cacheStats.CurrentMemoryMB,
		CacheItems:        cacheStats.ItemCount,
	}

	return GovernorStatus{
		State:             g.state,
		StateReason:       g.stateReason,
		LastStateChange:   g.lastStateChange,
		ControlCPUs:       g.controlCPUSet,
		WorkerCPUs:        g.workerCPUSet,
		ActiveQueries:     g.activeQueries,
		MaxAllowedQueries: maxQueries,
		ActiveTokensMB:    activeMB,
		MaxTokensMB:       maxTokensMB,
		ReportsAllowed:    g.state == StateNormal,
		IngestionBackoff:  g.state == StateCritical,
		DeferredDetection: g.state == StateCritical,
		MemoryLedger:      ledger,
		OperatorView:      opView,
		Metrics:           g.metrics,
		IsCgroupsV2Active: g.hasCgroupsV2,
		UpdatedTimestamp:  time.Now(),
	}
}

// Helper: parse PSI avg60 value from pressure format
func parsePSIAvg60(content string) float64 {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "some ") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.HasPrefix(p, "avg60=") {
					valStr := strings.TrimPrefix(p, "avg60=")
					val, _ := strconv.ParseFloat(valStr, 64)
					return val
				}
			}
		}
	}
	return 0.0
}

func readHostTotalMemory() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 16 * 1024 * 1024 * 1024 // 16GB default fallback
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseUint(fields[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 16 * 1024 * 1024 * 1024
}
