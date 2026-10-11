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
	// 1. English
	reportEN := sampleTestReport()
	reportEN.Language = "en"
	var bufEN bytes.Buffer
	if err := ExportIncidentCSV(&bufEN, reportEN); err != nil {
		t.Fatalf("ExportIncidentCSV (EN) returned error: %v", err)
	}
	contentEN := bufEN.String()
	if !strings.Contains(contentEN, "# Valtrivo LogSeal SIEM & Forensic Reporting Engine") {
		t.Errorf("CSV EN missing header metadata comment")
	}
	if !strings.Contains(contentEN, "Tenant Name: Acme Corporation (Slug: acme)") {
		t.Errorf("CSV EN missing tenant metadata")
	}
	if !strings.Contains(contentEN, "198.51.100.44") {
		t.Errorf("CSV EN missing IOC data")
	}

	// 2. Turkish
	reportTR := sampleTestReport()
	reportTR.Language = "tr"
	var bufTR bytes.Buffer
	if err := ExportIncidentCSV(&bufTR, reportTR); err != nil {
		t.Fatalf("ExportIncidentCSV (TR) returned error: %v", err)
	}
	contentTR := bufTR.String()
	if !strings.Contains(contentTR, "# Valtrivo LogSeal SIEM & Adli Bilişim Raporlama Motoru") {
		t.Errorf("CSV TR missing header metadata comment")
	}
	if !strings.Contains(contentTR, "Kiracı Adı: Acme Corporation (Kısa Ad: acme)") {
		t.Errorf("CSV TR missing tenant metadata")
	}
	if !strings.Contains(contentTR, "[YÖNETİCİ ÖZETİ VE OPERASYONEL METRİKLER]") {
		t.Errorf("CSV TR missing localized section header")
	}
}

func TestGenerateForensicIncidentPDF(t *testing.T) {
	for _, lang := range []string{"en", "tr"} {
		report := sampleTestReport()
		report.Language = lang
		var buf bytes.Buffer
		err := GenerateForensicIncidentPDF(&buf, report)
		if err != nil {
			t.Fatalf("GenerateForensicIncidentPDF (%s) returned error: %v", lang, err)
		}

		pdfBytes := buf.Bytes()
		if len(pdfBytes) < 500 {
			t.Fatalf("Generated PDF (%s) unexpectedly small (%d bytes)", lang, len(pdfBytes))
		}
		if !bytes.HasPrefix(pdfBytes, []byte("%PDF-")) {
			t.Errorf("Generated output (%s) does not start with %%PDF- magic header", lang)
		}
	}
}

func TestExportIncidentDOCX(t *testing.T) {
	for _, lang := range []string{"en", "tr"} {
		report := sampleTestReport()
		report.Language = lang
		var buf bytes.Buffer
		err := ExportIncidentDOCX("", report, &buf)
		if err != nil {
			t.Fatalf("ExportIncidentDOCX (%s) returned error: %v", lang, err)
		}

		docxBytes := buf.Bytes()
		if len(docxBytes) < 500 {
			t.Fatalf("Generated DOCX (%s) unexpectedly small (%d bytes)", lang, len(docxBytes))
		}
		// Check standard ZIP magic bytes (PK\x03\x04)
		if docxBytes[0] != 0x50 || docxBytes[1] != 0x4B {
			t.Errorf("Generated DOCX (%s) does not start with ZIP PK header", lang)
		}
	}
}

func TestRenderTextReport_AllTemplates(t *testing.T) {
	templates := []string{
		"exec_posture",
		"incident_rca",
		"shift_handover",
		"compliance_audit",
		"vuln_exposure",
	}

	for _, lang := range []string{"en", "tr"} {
		report := sampleTestReport()
		report.Language = lang

		for _, tmpl := range templates {
			report.ReportType = tmpl
			out, err := RenderTextReport(report)
			if err != nil {
				t.Errorf("RenderTextReport failed for template %s (%s): %v", tmpl, lang, err)
				continue
			}
			if len(out) == 0 {
				t.Errorf("RenderTextReport returned empty string for template %s (%s)", tmpl, lang)
			}
			if lang == "en" && !strings.Contains(out, "Valtrivo LogSeal SIEM Engine") {
				t.Errorf("RenderTextReport missing signature for template %s (en)", tmpl)
			}
			if lang == "tr" && !strings.Contains(out, "Valtrivo LogSeal SIEM Motoru") {
				t.Errorf("RenderTextReport missing signature for template %s (tr)", tmpl)
			}
		}
	}
}
