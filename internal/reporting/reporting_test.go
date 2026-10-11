package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

func sampleTestReport() models.ComprehensiveIncidentReport {
	now := time.Now().UTC()
	return models.ComprehensiveIncidentReport{
		ReportID:       "TEST-IR-001",
		ReportType:     "incident_rca",
		Title:          "Critical Test Incident Forensics",
		Classification: "CONFIDENTIAL / TLP:AMBER",
		StartTime:      now.Add(-2 * time.Hour),
		EndTime:        now,
		GeneratedAt:    now,
		Tenant: models.TenantBranding{
			TenantSlug: "acme",
			TenantName: "Acme Corporation",
		},
		ExecutiveSummary: "Test executive summary of correlation alert.",
		MTTDMinutes:      5,
		MTTAMinutes:      10,
		MTTRMinutes:      25,
		TotalEvents:      150000,
		TotalAlerts:      12,
		CriticalAlerts:   3,
		ThreatMappings: []models.ThreatMapping{
			{
				TacticID:    "Initial Access",
				TechniqueID: "T1110.003",
				Name:        "Password Spraying",
				RuleName:    "AUTH-002: Password Spray Detected",
				D3FENDID:    "D3-IT (Inbound Filter)",
			},
		},
		IOCs: []models.IndicatorOfCompromise{
			{
				Type:        "IPv4",
				Value:       "198.51.100.44",
				Confidence:  "High",
				Reputation:  "Perimeter Threat Intel",
				ActionTaken: "Blocked at Gateway",
			},
		},
		Timeline: []models.TimelineEntry{
			{
				Timestamp:   now.Add(-1 * time.Hour),
				Source:      "Firewall-01",
				Description: "Connection dropped from untrusted source",
				Actor:       "198.51.100.44",
			},
		},
		ChainOfCustody: []models.ForensicArtifact{
			{
				EvidenceID:    "EV-0001",
				ArtifactType:  "Law 5651 Hourly Archive (.tar.gz)",
				SourceHost:    "Core-Syslog-01",
				AcquisitionAt: now.Add(-1 * time.Hour),
				SHA256Hash:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
				TSATokenZD:    "TÜBİTAK KamuSM .zd",
				Custodian:     "LogSeal Sealer",
			},
		},
		RootCause: "External credential spray against edge VPN.",
		RemediationPlan: []string{
			"Block source IP range",
			"Enforce MFA policy",
		},
	}
}

func TestExportIncidentCSV(t *testing.T) {
	report := sampleTestReport()
	var buf bytes.Buffer
	err := ExportIncidentCSV(&buf, report)
	if err != nil {
		t.Fatalf("ExportIncidentCSV returned error: %v", err)
	}

	content := buf.String()
	if !strings.Contains(content, "# Valtrivo LogSeal SIEM & Forensic Reporting Engine") {
		t.Errorf("CSV missing header metadata comment")
	}
	if !strings.Contains(content, "Acme Corporation (Slug: acme)") {
		t.Errorf("CSV missing tenant metadata")
	}
	if !strings.Contains(content, "198.51.100.44") {
		t.Errorf("CSV missing IOC data")
	}
	if !strings.Contains(content, "TÜBİTAK KamuSM .zd") {
		t.Errorf("CSV missing Law 5651 timestamp token")
	}
}

func TestGenerateForensicIncidentPDF(t *testing.T) {
	report := sampleTestReport()
	var buf bytes.Buffer
	err := GenerateForensicIncidentPDF(&buf, report)
	if err != nil {
		t.Fatalf("GenerateForensicIncidentPDF returned error: %v", err)
	}

	pdfBytes := buf.Bytes()
	if len(pdfBytes) < 500 {
		t.Fatalf("Generated PDF unexpectedly small (%d bytes)", len(pdfBytes))
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-")) {
		t.Errorf("Generated output does not start with %%PDF- magic header")
	}
}

func TestExportIncidentDOCX(t *testing.T) {
	report := sampleTestReport()
	var buf bytes.Buffer
	err := ExportIncidentDOCX("", report, &buf)
	if err != nil {
		t.Fatalf("ExportIncidentDOCX returned error: %v", err)
	}

	docxBytes := buf.Bytes()
	if len(docxBytes) < 500 {
		t.Fatalf("Generated DOCX unexpectedly small (%d bytes)", len(docxBytes))
	}
	// Check standard ZIP magic bytes (PK\x03\x04)
	if docxBytes[0] != 0x50 || docxBytes[1] != 0x4B {
		t.Errorf("Generated DOCX does not start with ZIP PK header")
	}
}

func TestRenderTextReport_AllTemplates(t *testing.T) {
	report := sampleTestReport()

	templates := []string{
		"exec_posture",
		"incident_rca",
		"shift_handover",
		"compliance_audit",
		"vuln_exposure",
	}

	for _, tmpl := range templates {
		report.ReportType = tmpl
		out, err := RenderTextReport(report)
		if err != nil {
			t.Errorf("RenderTextReport failed for template %s: %v", tmpl, err)
			continue
		}
		if len(out) == 0 {
			t.Errorf("RenderTextReport returned empty string for template %s", tmpl)
		}
		if !strings.Contains(out, "Valtrivo LogSeal SIEM Engine") {
			t.Errorf("RenderTextReport missing signature for template %s", tmpl)
		}
	}
}
