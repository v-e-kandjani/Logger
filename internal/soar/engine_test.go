package soar

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

func TestSOARMatchesTrigger(t *testing.T) {
	engine := NewEngine(nil)

	pb := &models.SOARPlaybook{
		ID:        uuid.New(),
		Name:      "Ransomware Isolation",
		IsEnabled: true,
		TriggerConditions: models.SOARTriggerConditions{
			Severities:   []string{"CRITICAL"},
			MinRiskScore: 80,
			Categories:   []string{"threat", "defense_evasion"},
			MitreTactics: []string{"Impact"},
		},
	}

	// Case 1: Perfect match
	alertMatch := &models.SIEMAlert{
		Severity:    "CRITICAL",
		RiskScore:   90,
		Category:    "threat",
		MitreTactic: "Impact - Data Encrypted for Impact",
	}
	if !engine.matchesTrigger(pb, alertMatch) {
		t.Errorf("Expected alert to match trigger conditions")
	}

	// Case 2: Risk score too low
	alertLowRisk := &models.SIEMAlert{
		Severity:    "CRITICAL",
		RiskScore:   60,
		Category:    "threat",
		MitreTactic: "Impact",
	}
	if engine.matchesTrigger(pb, alertLowRisk) {
		t.Errorf("Expected low risk alert to be rejected")
	}

	// Case 3: Severity mismatch
	alertLowSev := &models.SIEMAlert{
		Severity:    "MEDIUM",
		RiskScore:   95,
		Category:    "threat",
		MitreTactic: "Impact",
	}
	if engine.matchesTrigger(pb, alertLowSev) {
		t.Errorf("Expected medium severity alert to be rejected")
	}

	// Case 4: Category mismatch
	alertWrongCat := &models.SIEMAlert{
		Severity:    "CRITICAL",
		RiskScore:   95,
		Category:    "authentication",
		MitreTactic: "Impact",
	}
	if engine.matchesTrigger(pb, alertWrongCat) {
		t.Errorf("Expected wrong category to be rejected")
	}

	// Case 5: Tactic mismatch
	alertWrongTactic := &models.SIEMAlert{
		Severity:    "CRITICAL",
		RiskScore:   95,
		Category:    "threat",
		MitreTactic: "Discovery",
	}
	if engine.matchesTrigger(pb, alertWrongTactic) {
		t.Errorf("Expected wrong tactic to be rejected")
	}
}

func TestSOARCooldownLogic(t *testing.T) {
	engine := NewEngine(nil)

	pbID := uuid.New()
	cooldownKey := pbID.String() + ":host-alpha"

	// Initial store
	engine.cooldowns.Store(cooldownKey, time.Now().UTC())

	val, ok := engine.cooldowns.Load(cooldownKey)
	if !ok {
		t.Fatalf("Expected cooldown key to exist")
	}
	lastFired, ok := val.(time.Time)
	if !ok || time.Since(lastFired) > 1*time.Minute {
		t.Errorf("Expected recent timestamp in cooldown map")
	}
}
