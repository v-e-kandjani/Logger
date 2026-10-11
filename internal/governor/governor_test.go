package governor

import (
	"context"
	"testing"
	"time"
)

func TestParsePSIAvg60(t *testing.T) {
	psiContent := "some avg10=0.50 avg60=4.75 avg300=2.10 total=987654\nfull avg10=0.10 avg60=1.20 avg300=0.40 total=12345"
	val := parsePSIAvg60(psiContent)
	if val != 4.75 {
		t.Fatalf("expected 4.75, got %v", val)
	}

	emptyVal := parsePSIAvg60("")
	if emptyVal != 0.0 {
		t.Fatalf("expected 0.0 for empty, got %v", emptyVal)
	}
}

func TestGovernorStateMachine(t *testing.T) {
	g := &Governor{
		state:            StateNormal,
		totalCPUs:        4,
		totalMemoryBytes: 16 * 1024 * 1024 * 1024,
	}

	// Normal condition
	mNormal := CgroupMetrics{
		MemoryCurrent:  4 * 1024 * 1024 * 1024,
		MemoryHigh:     9 * 1024 * 1024 * 1024,
		MemoryMax:      11 * 1024 * 1024 * 1024,
		CPUPSIAvg60:    1.2,
		MemoryPSIAvg60: 0.5,
	}
	g.evaluateStateMachine(mNormal)
	if g.state != StateNormal {
		t.Fatalf("expected StateNormal, got %s", g.state)
	}

	// Pressure condition (Memory > 90% of High)
	mPressure := CgroupMetrics{
		MemoryCurrent:  8500 * 1024 * 1024, // > 90% of 9G
		MemoryHigh:     9000 * 1024 * 1024,
		MemoryMax:      11000 * 1024 * 1024,
		CPUPSIAvg60:    1.2,
		MemoryPSIAvg60: 1.0,
	}
	g.evaluateStateMachine(mPressure)
	if g.state != StatePressure {
		t.Fatalf("expected StatePressure, got %s", g.state)
	}

	// Critical condition (Memory > 95% of Max OR PSI > 25)
	mCritical := CgroupMetrics{
		MemoryCurrent:  10600 * 1024 * 1024, // > 95% of 11G
		MemoryHigh:     9000 * 1024 * 1024,
		MemoryMax:      11000 * 1024 * 1024,
		CPUPSIAvg60:    28.5, // > 25%
		MemoryPSIAvg60: 5.0,
	}
	g.evaluateStateMachine(mCritical)
	if g.state != StateCritical {
		t.Fatalf("expected StateCritical, got %s", g.state)
	}

	// Check Admission in Critical state
	admit, reason := g.CanAdmitQuery(context.Background())
	if admit {
		t.Fatalf("expected query rejection in Critical state, but was admitted")
	}
	if reason == "" {
		t.Fatalf("expected non-empty rejection reason")
	}

	reportAdmit, _ := g.CanAdmitReport()
	if reportAdmit {
		t.Fatalf("expected report rejection in Critical state")
	}

	// Recover to Normal through Recovery
	for i := 0; i < 11; i++ {
		g.evaluateStateMachine(mNormal)
	}
	if g.state != StateNormal {
		t.Fatalf("expected return to StateNormal after hysteresis, got %s", g.state)
	}
}

func TestGovernorQuerySlots(t *testing.T) {
	g := &Governor{
		state:     StateNormal,
		totalCPUs: 2, // max 2 queries
	}

	ctx := context.Background()
	ok1, _ := g.CanAdmitQuery(ctx)
	if !ok1 {
		t.Fatalf("query 1 should be admitted")
	}

	ok2, _ := g.CanAdmitQuery(ctx)
	if !ok2 {
		t.Fatalf("query 2 should be admitted")
	}

	ok3, reason := g.CanAdmitQuery(ctx)
	if ok3 {
		t.Fatalf("query 3 should be rejected because max is 2")
	}
	if reason == "" {
		t.Fatalf("expected busy reason for query 3")
	}

	g.ReleaseQuery()
	ok4, _ := g.CanAdmitQuery(ctx)
	if !ok4 {
		t.Fatalf("query 4 should be admitted after releasing a slot")
	}
}

func TestGovernorMemoryTokens(t *testing.T) {
	g := &Governor{
		state:              StateNormal,
		totalCPUs:          8,
		totalMemoryBytes:   16 * 1024 * 1024 * 1024,
		maxQueryMemoryPool: 256 * 1024 * 1024, // 256 MB pool allows 2 * 128 MB tokens
	}

	ctx := context.Background()

	// Query 1: claims 128 MB
	ok1, _ := g.CanAdmitQuery(ctx)
	if !ok1 {
		t.Fatalf("query 1 should be admitted with memory token")
	}

	// Query 2: claims 128 MB (total 256 MB)
	ok2, _ := g.CanAdmitQuery(ctx)
	if !ok2 {
		t.Fatalf("query 2 should be admitted with memory token")
	}

	// Query 3: should be rejected because memory token pool is exhausted
	ok3, reason := g.CanAdmitQuery(ctx)
	if ok3 {
		t.Fatalf("query 3 should be rejected due to memory token exhaustion")
	}
	if reason == "" {
		t.Fatalf("expected exhaustion reason")
	}

	// Release 1 token
	g.ReleaseQuery()
	ok4, _ := g.CanAdmitQuery(ctx)
	if !ok4 {
		t.Fatalf("query 4 should be admitted after releasing a memory token")
	}
}

func TestGovernorRecoverySlotRampUp(t *testing.T) {
	g := &Governor{
		state:                StateCritical,
		totalCPUs:            4, // max 4 queries
		totalMemoryBytes:     16 * 1024 * 1024 * 1024,
		maxQueryMemoryPool:   4 * 1024 * 1024 * 1024,
		recoveryAllowedSlots: 1,
	}

	mNormal := CgroupMetrics{
		MemoryCurrent:  4 * 1024 * 1024 * 1024,
		MemoryHigh:     9 * 1024 * 1024 * 1024,
		MemoryMax:      11 * 1024 * 1024 * 1024,
		CPUPSIAvg60:    0.5,
		MemoryPSIAvg60: 0.2,
	}

	// First tick of healthy metrics moves to RECOVERY
	g.evaluateStateMachine(mNormal)
	if g.state != StateRecovery {
		t.Fatalf("expected StateRecovery, got %s", g.state)
	}
	if g.recoveryAllowedSlots != 1 {
		t.Fatalf("expected 1 allowed slot initially in recovery, got %d", g.recoveryAllowedSlots)
	}

	// After multiple healthy ticks, slots should gradually restore
	for i := 0; i < 4; i++ {
		g.evaluateStateMachine(mNormal)
	}
	if g.recoveryAllowedSlots <= 1 {
		t.Fatalf("expected recoveryAllowedSlots to increase, got %d", g.recoveryAllowedSlots)
	}

	// Complete recovery to NORMAL
	for i := 0; i < 10; i++ {
		g.evaluateStateMachine(mNormal)
	}
	if g.state != StateNormal {
		t.Fatalf("expected StateNormal after 10 ticks, got %s", g.state)
	}
	if g.recoveryAllowedSlots != 4 {
		t.Fatalf("expected 4 allowed slots in Normal, got %d", g.recoveryAllowedSlots)
	}
}

func TestGovernorStatus(t *testing.T) {
	g := NewGovernor()
	defer g.Stop()

	status := g.GetStatus()
	if status.State == "" {
		t.Fatalf("expected non-empty state")
	}
	if status.ControlCPUs == "" || status.WorkerCPUs == "" {
		t.Fatalf("expected non-empty CPU allocations")
	}
	if status.MemoryLedger.OSReservedMB <= 0 {
		t.Fatalf("expected positive OS reserved MB in memory ledger")
	}
	if status.OperatorView.ArchiveCoverage == "" {
		t.Fatalf("expected non-empty archive coverage in operator view")
	}
	if status.UpdatedTimestamp.IsZero() {
		t.Fatalf("expected valid timestamp")
	}
	if time.Since(status.UpdatedTimestamp) > 5*time.Second {
		t.Fatalf("timestamp should be recent")
	}
}
