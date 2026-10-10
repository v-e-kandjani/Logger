package correlation

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/siem/normalizer"
)

type mockPersister struct {
	mu     sync.Mutex
	alerts []*models.SIEMAlert
}

func (m *mockPersister) CreateOrUpdateSIEMAlert(ctx context.Context, alert *models.SIEMAlert) (*models.SIEMAlert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.alerts {
		if existing.ID == alert.ID {
			alertCopy := *alert
			m.alerts[i] = &alertCopy
			return alert, nil
		}
	}
	alertCopy := *alert
	m.alerts = append(m.alerts, &alertCopy)
	return alert, nil
}

func (m *mockPersister) GetActiveSIEMAlertByRuleAndGroup(ctx context.Context, ruleID, groupKey, tenant string) (*models.SIEMAlert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.alerts {
		if a.RuleID == ruleID && (a.SourceIP == groupKey || a.Username == groupKey || a.DeviceName == groupKey || groupKey == "global") {
			if tenant == "" || tenant == "all" || a.Tenant == tenant || (a.Tenant == "" && tenant == "default") {
				if a.Status == "NEW" || a.Status == "IN_PROGRESS" {
					return a, nil
				}
			}
		}
	}
	return nil, nil
}

func (m *mockPersister) ListSIEMRules(ctx context.Context) ([]models.SIEMRule, error) {
	return nil, nil
}

func (m *mockPersister) ToggleSIEMRule(ctx context.Context, ruleID string, enabled bool) error {
	return nil
}

func TestCorrelationEngine_BruteForce(t *testing.T) {
	norm := normalizer.NewNormalizer()
	mock := &mockPersister{}
	engine := NewEngine(norm, mock)
	defer engine.Stop()

	alertCh := engine.SubscribeAlerts()
	defer engine.UnsubscribeAlerts(alertCh)

	now := time.Now().UTC()
	attackerIP := "198.51.100.77"

	// Feed 5 failed login events
	for i := 0; i < 5; i++ {
		event := &models.NormalizedEvent{
			EventID:        uuid.New(),
			Timestamp:      now.Add(time.Duration(i) * time.Second),
			SourceIP:       attackerIP,
			EventCategory:  "authentication",
			EventAction:    "login-failed",
			EventOutcome:   "failure",
			Username:       "admin",
			Severity:       "HIGH",
			RiskScore:      70,
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110",
			RawMessage:     "Failed password for admin",
		}
		engine.Evaluate(event)
	}

	// Verify alert is received via subscription channel
	select {
	case alert := <-alertCh:
		if alert.RuleID != "AUTH-001" {
			t.Errorf("expected rule AUTH-001, got %s", alert.RuleID)
		}
		if alert.SourceIP != attackerIP {
			t.Errorf("expected %s, got %s", attackerIP, alert.SourceIP)
		}
		if alert.EventCount != 5 {
			t.Errorf("expected 5 events, got %d", alert.EventCount)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for brute force alert")
	}
}

func TestCorrelationEngine_Simulation(t *testing.T) {
	norm := normalizer.NewNormalizer()
	mock := &mockPersister{}
	engine := NewEngine(norm, mock)
	defer engine.Stop()

	alertCh := engine.SubscribeAlerts()
	defer engine.UnsubscribeAlerts(alertCh)

	_, err := engine.SimulateScenario("threat")
	if err != nil {
		t.Fatalf("simulate error: %v", err)
	}

	select {
	case alert := <-alertCh:
		if alert.RuleID != "PERIM-004" && alert.RuleID != "THREAT-001" {
			t.Errorf("expected PERIM-004, got %s", alert.RuleID)
		}
		if alert.Severity != "HIGH" && alert.Severity != "CRITICAL" {
			t.Errorf("expected HIGH or CRITICAL, got %s", alert.Severity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for simulated threat alert")
	}
}

func TestCorrelationEngine_AlertDeduplicationAndAggregation(t *testing.T) {
	norm := normalizer.NewNormalizer()
	mock := &mockPersister{}
	engine := NewEngine(norm, mock)
	defer engine.Stop()

	now := time.Now().UTC()
	attackerIP := "198.51.100.99"

	// Feed initial 5 events to trigger alert
	for i := 0; i < 5; i++ {
		engine.Evaluate(&models.NormalizedEvent{
			EventID:        uuid.New(),
			Timestamp:      now.Add(time.Duration(i) * time.Second),
			SourceIP:       attackerIP,
			EventCategory:  "authentication",
			EventAction:    "login-failed",
			EventOutcome:   "failure",
			Username:       "root",
			Severity:       "HIGH",
			RawMessage:     "Failed password for root",
		})
	}

	// Wait up to 1 second for async persistence
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		mock.mu.Lock()
		count := len(mock.alerts)
		if count > 0 {
			mock.mu.Unlock()
			break
		}
		mock.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}

	mock.mu.Lock()
	initialAlertCount := len(mock.alerts)
	var firstAlertID uuid.UUID
	if initialAlertCount > 0 {
		firstAlertID = mock.alerts[0].ID
	}
	mock.mu.Unlock()

	if initialAlertCount == 0 {
		t.Fatal("expected at least 1 alert to be created")
	}

	// Feed 15 additional events over time
	for i := 5; i < 20; i++ {
		engine.Evaluate(&models.NormalizedEvent{
			EventID:        uuid.New(),
			Timestamp:      now.Add(time.Duration(i) * time.Second),
			SourceIP:       attackerIP,
			EventCategory:  "authentication",
			EventAction:    "login-failed",
			EventOutcome:   "failure",
			Username:       "root",
			Severity:       "HIGH",
			RawMessage:     "Failed password for root",
		})
	}

	// Wait up to 1 second for async persistence updates
	deadline = time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		mock.mu.Lock()
		if len(mock.alerts) > 0 && mock.alerts[0].EventCount == 20 {
			mock.mu.Unlock()
			break
		}
		mock.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}

	// Check that NO NEW unique alert IDs were created, but the single alert had its count updated to 20
	mock.mu.Lock()
	uniqueIDs := make(map[uuid.UUID]bool)
	var lastCount int
	for _, a := range mock.alerts {
		uniqueIDs[a.ID] = true
		lastCount = a.EventCount
	}
	mock.mu.Unlock()

	if len(uniqueIDs) != 1 {
		t.Errorf("expected exactly 1 unique alert ID due to deduplication, got %d unique IDs", len(uniqueIDs))
	}
	if !uniqueIDs[firstAlertID] {
		t.Errorf("expected alert ID to remain %s", firstAlertID)
	}
	if lastCount != 20 {
		t.Errorf("expected aggregated event count to be 20, got %d", lastCount)
	}
}

func TestCorrelationEngine_MultiTenantIsolation(t *testing.T) {
	norm := normalizer.NewNormalizer()
	mock := &mockPersister{}
	engine := NewEngine(norm, mock)
	defer engine.Stop()

	alertCh := engine.SubscribeAlerts()
	defer engine.UnsubscribeAlerts(alertCh)

	now := time.Now().UTC()
	sameIP := "192.168.10.50"

	// Tenant A sends 3 events (threshold is 5 for AUTH-001)
	for i := 0; i < 3; i++ {
		engine.Evaluate(&models.NormalizedEvent{
			EventID:        uuid.New(),
			Timestamp:      now.Add(time.Duration(i) * time.Second),
			SourceIP:       sameIP,
			EventCategory:  "authentication",
			EventAction:    "login-failed",
			EventOutcome:   "failure",
			Username:       "admin",
			Tenant:         "tenant-a",
			Severity:       "HIGH",
			RiskScore:      70,
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110",
			RawMessage:     "Failed password for admin",
		})
	}

	// Tenant B sends 3 events with the EXACT same IP
	for i := 0; i < 3; i++ {
		engine.Evaluate(&models.NormalizedEvent{
			EventID:        uuid.New(),
			Timestamp:      now.Add(time.Duration(i) * time.Second),
			SourceIP:       sameIP,
			EventCategory:  "authentication",
			EventAction:    "login-failed",
			EventOutcome:   "failure",
			Username:       "admin",
			Tenant:         "tenant-b",
			Severity:       "HIGH",
			RiskScore:      70,
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110",
			RawMessage:     "Failed password for admin",
		})
	}

	// Neither tenant should have triggered an alert yet (both at 3 < 5)
	select {
	case a := <-alertCh:
		t.Fatalf("unexpected alert triggered early across tenant boundary: %+v", a)
	case <-time.After(150 * time.Millisecond):
		// Expected: no cross-tenant threshold leak
	}

	// Now Tenant A sends 2 more events -> reaches 5 -> should trigger alert for tenant-a only
	for i := 3; i < 5; i++ {
		engine.Evaluate(&models.NormalizedEvent{
			EventID:        uuid.New(),
			Timestamp:      now.Add(time.Duration(i) * time.Second),
			SourceIP:       sameIP,
			EventCategory:  "authentication",
			EventAction:    "login-failed",
			EventOutcome:   "failure",
			Username:       "admin",
			Tenant:         "tenant-a",
			Severity:       "HIGH",
			RiskScore:      70,
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110",
			RawMessage:     "Failed password for admin",
		})
	}

	select {
	case alert := <-alertCh:
		if alert.Tenant != "tenant-a" {
			t.Errorf("expected alert tenant to be tenant-a, got %s", alert.Tenant)
		}
		if alert.EventCount != 5 {
			t.Errorf("expected event count 5, got %d", alert.EventCount)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for tenant-a alert")
	}
}

