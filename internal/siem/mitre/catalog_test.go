package mitre

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

func TestCatalog_Baseline(t *testing.T) {
	cat := NewCatalog()

	tech, found := cat.GetTechnique("T1110")
	if !found {
		t.Fatalf("expected technique T1110 to be present in baseline")
	}
	if tech.Name != "Brute Force" {
		t.Errorf("expected 'Brute Force', got '%s'", tech.Name)
	}
	if tech.TacticID != "TA0006" {
		t.Errorf("expected tactic TA0006, got '%s'", tech.TacticID)
	}

	techSub, found := cat.GetTechnique("T1110.003")
	if !found {
		t.Fatalf("expected sub-technique T1110.003 to be present")
	}
	if techSub.SubTechniqueOf != "T1110" {
		t.Errorf("expected parent T1110, got '%s'", techSub.SubTechniqueOf)
	}
}

func TestCatalog_CoverageReport(t *testing.T) {
	cat := NewCatalog()

	rules := []models.SIEMRule{
		{
			ID:             "AUTH-001",
			Name:           "Multiple Failed Logins (Brute Force)",
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110",
			IsEnabled:      true,
		},
		{
			ID:             "NET-001",
			Name:           "Port Scan",
			MitreTactic:    "Discovery",
			MitreTechnique: "T1046",
			IsEnabled:      true,
		},
	}

	alerts := []models.SIEMAlert{
		{
			ID:             uuid.New(),
			MitreTechnique: "T1110",
			EventCount:     5,
			LastSeen:       time.Now(),
		},
	}

	report := cat.GenerateCoverageReport(rules, alerts)

	if report.CoveredTechniques < 2 {
		t.Errorf("expected at least 2 covered techniques, got %d", report.CoveredTechniques)
	}
	if report.TotalAlertsMapped != 1 {
		t.Errorf("expected 1 alert mapped, got %d", report.TotalAlertsMapped)
	}

	var credAccess *CoverageTactic
	for i := range report.Tactics {
		if report.Tactics[i].ID == "TA0006" {
			credAccess = &report.Tactics[i]
			break
		}
	}
	if credAccess == nil {
		t.Fatalf("expected Credential Access (TA0006) tactic in report")
	}
	if credAccess.CoveredTechniques < 1 {
		t.Errorf("expected at least 1 covered technique in Credential Access")
	}
}

func TestCatalog_ParseSTIX(t *testing.T) {
	stixJSON := `{
		"objects": [
			{
				"type": "attack-pattern",
				"name": "Custom Automated Recon",
				"description": "Adversary probes perimeter",
				"external_references": [
					{
						"source_name": "mitre-attack",
						"external_id": "T9999",
						"url": "https://attack.mitre.org/techniques/T9999/"
					}
				],
				"kill_chain_phases": [
					{
						"kill_chain_name": "mitre-attack",
						"phase_name": "reconnaissance"
					}
				],
				"revoked": false
			}
		]
	}`

	cat := NewCatalog()
	count, err := cat.ParseSTIXStream(strings.NewReader(stixJSON), "test-stream")
	if err != nil {
		t.Fatalf("ParseSTIXStream failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 parsed technique, got %d", count)
	}

	tech, found := cat.GetTechnique("T9999")
	if !found {
		t.Fatalf("expected technique T9999 to be present")
	}
	if tech.Name != "Custom Automated Recon" {
		t.Errorf("expected name 'Custom Automated Recon', got '%s'", tech.Name)
	}
	if tech.TacticID != "TA0043" {
		t.Errorf("expected Tactic TA0043, got '%s'", tech.TacticID)
	}
}
