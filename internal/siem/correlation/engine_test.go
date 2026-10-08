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
	m.alerts = append(m.alerts, alert)
	return alert, nil
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
			EventID:         uuid.New(),
			Timestamp:       now.Add(time.Duration(i) * time.Second),
			SourceIP:        attackerIP,
			EventCategory:   "authentication",
			EventAction:     "login-failed",
			EventOutcome:    "failure",
			Username:        "admin",
			Severity:        "HIGH",
			RiskScore:       70,
			MitreTactic:     "Credential Access",
			MitreTechnique:  "T1110",
			RawMessage:      "Failed password for admin",
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
