package reporting

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jung-kurt/gofpdf"
	"github.com/syslog-platform/logger/internal/models"
)

// GenerateForensicIncidentPDF generates a forensic-grade A4 PDF report matching Document 1 specification.
func GenerateForensicIncidentPDF(w io.Writer, report models.ComprehensiveIncidentReport) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(true, 18)

	// Custom Footer with confidentiality and page numbers
	pdf.SetFooterFunc(func() {
		pdf.SetY(-14)
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(90, 8, fmt.Sprintf("Valtrivo LogSeal | %s | Report ID: %s", report.Classification, report.ReportID), "", 0, "L", false, 0, "")
		pdf.CellFormat(92, 8, fmt.Sprintf("Page %d of {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")
	})
	pdf.AliasNbPages("{nb}")
	pdf.AddPage()

	branding := report.Tenant.ResolveLogo()

	// 1. Header (Logo + Metadata)
	if _, err := os.Stat(branding.LogoPath); err == nil {
		var imgOpt gofpdf.ImageOptions
		imgOpt.ImageType = "PNG"
		pdf.ImageOptions(branding.LogoPath, 14, 12, 22, 0, false, imgOpt, 0, "")
	}

	pdf.SetFont("Arial", "B", 13)
	pdf.SetTextColor(26, 32, 44)
	pdf.SetXY(40, 11)

	headerTitle := "SOC INCIDENT & FORENSIC INVESTIGATION REPORT"
	if report.Title != "" {
		headerTitle = strings.ToUpper(report.Title)
	}
	pdf.CellFormat(156, 6, headerTitle, "", 1, "R", false, 0, "")

	pdf.SetFont("Arial", "B", 8.5)
	pdf.SetTextColor(200, 35, 51) // Red callout for classification
	pdf.SetX(40)
	pdf.CellFormat(156, 4, fmt.Sprintf("CLASSIFICATION: %s", report.Classification), "", 1, "R", false, 0, "")

	pdf.SetFont("Arial", "", 8)
	pdf.SetTextColor(100, 116, 139)

	pdf.SetX(40)
	pdf.CellFormat(156, 4, fmt.Sprintf("Tenant: %s [Slug: %s]", report.Tenant.TenantName, report.Tenant.TenantSlug), "", 1, "R", false, 0, "")

	pdf.SetX(40)
	timeframeLine := fmt.Sprintf("Timeframe: %s to %s",
		report.StartTime.UTC().Format("2006-01-02 15:04"),
		report.EndTime.UTC().Format("2006-01-02 15:04 UTC"),
	)
	pdf.CellFormat(156, 4, timeframeLine, "", 1, "R", false, 0, "")

	// Horizontal Rule Divider
	pdf.SetDrawColor(226, 232, 240)
	pdf.SetLineWidth(0.4)
	pdf.Line(14, 34, 196, 34)
	pdf.SetY(38)

	// 2. Executive Overview & SLA KPI Cards
	renderSectionHeader(pdf, "1. Executive Summary & Operational Metrics")
	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(51, 65, 85)
	pdf.MultiCell(182, 4.5, report.ExecutiveSummary, "", "L", false)
	pdf.Ln(3)

	kpiWidth := 43.5
	kpiHeight := 14.0
	pdf.SetFillColor(248, 250, 252)
	pdf.SetDrawColor(203, 213, 225)
	pdf.SetLineWidth(0.2)

	startX := 14.0
	currentY := pdf.GetY()
	drawKPICard(pdf, startX, currentY, kpiWidth, kpiHeight, "MTTD (Detect)", fmt.Sprintf("%dm", report.MTTDMinutes))
	drawKPICard(pdf, startX+kpiWidth+2, currentY, kpiWidth, kpiHeight, "MTTA (Triage)", fmt.Sprintf("%dm", report.MTTAMinutes))
	drawKPICard(pdf, startX+((kpiWidth+2)*2), currentY, kpiWidth, kpiHeight, "MTTR (Contain)", fmt.Sprintf("%dm", report.MTTRMinutes))

	regStatus := "Compliant"
	if report.RegulatoryImpact.BreachConfirmed {
		regStatus = strings.Join(report.RegulatoryImpact.Regulations, ", ")
	} else if report.RegulatoryImpact.Law5651Relevant {
		regStatus = "Law 5651 Sealed"
	}
	drawKPICard(pdf, startX+((kpiWidth+2)*3), currentY, kpiWidth, kpiHeight, "Legal / Compliance", regStatus)
	pdf.SetY(currentY + kpiHeight + 6)

	// 3. MITRE ATT&CK & D3FEND Threat Matrix
	if len(report.ThreatMappings) > 0 {
		renderSectionHeader(pdf, "2. Tactical Threat Mapping (MITRE ATT&CK & D3FEND)")
		colWidthsMitre := []float64{26, 28, 40, 58, 30}
		drawTableHeader(pdf, colWidthsMitre, []string{"Tactic ID", "Technique ID", "Technique Name", "SIEM Detection Rule", "D3FEND Counter"})
		pdf.SetFont("Arial", "", 8)
		pdf.SetTextColor(30, 41, 59)
		for _, m := range report.ThreatMappings {
			ensurePageSpace(pdf, 6.5)
			pdf.CellFormat(colWidthsMitre[0], 6.5, m.TacticID, "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsMitre[1], 6.5, m.TechniqueID, "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsMitre[2], 6.5, truncate(m.Name, 22), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsMitre[3], 6.5, truncate(m.RuleName, 34), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsMitre[4], 6.5, m.D3FENDID, "1", 0, "C", false, 0, "")
			pdf.Ln(-1)
		}
		pdf.Ln(4)
	}

	// 4. Indicators of Compromise (IOC)
	if len(report.IOCs) > 0 {
		renderSectionHeader(pdf, "3. Extracted Threat Intelligence & IOCs")
		colWidthsIOC := []float64{24, 70, 24, 32, 32}
		drawTableHeader(pdf, colWidthsIOC, []string{"Type", "Indicator Value", "Confidence", "Reputation/Feed", "Action Taken"})
		pdf.SetFont("Arial", "", 8)
		pdf.SetTextColor(30, 41, 59)
		for _, ioc := range report.IOCs {
			ensurePageSpace(pdf, 6.5)
			pdf.CellFormat(colWidthsIOC[0], 6.5, ioc.Type, "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsIOC[1], 6.5, truncate(ioc.Value, 42), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsIOC[2], 6.5, ioc.Confidence, "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsIOC[3], 6.5, truncate(ioc.Reputation, 18), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsIOC[4], 6.5, truncate(ioc.ActionTaken, 18), "1", 0, "L", false, 0, "")
			pdf.Ln(-1)
		}
		pdf.Ln(4)
	}

	// 5. Chain of Custody & Law 5651 Evidence Ledger
	if len(report.ChainOfCustody) > 0 {
		renderSectionHeader(pdf, "4. Forensic Evidence & Cryptographic Chain of Custody (Law 5651)")
		colWidthsCustody := []float64{20, 28, 28, 32, 46, 28}
		drawTableHeader(pdf, colWidthsCustody, []string{"Evidence ID", "Artifact Type", "Host/Device", "Acquired (UTC)", "SHA-256 Checksum", "Custodian"})
		pdf.SetFont("Arial", "", 7.5)
		pdf.SetTextColor(30, 41, 59)
		for _, ev := range report.ChainOfCustody {
			ensurePageSpace(pdf, 6.5)
			pdf.CellFormat(colWidthsCustody[0], 6.5, ev.EvidenceID, "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsCustody[1], 6.5, ev.ArtifactType, "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsCustody[2], 6.5, truncate(ev.SourceHost, 15), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsCustody[3], 6.5, ev.AcquisitionAt.UTC().Format("06-01-02 15:04:05"), "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsCustody[4], 6.5, truncate(ev.SHA256Hash, 26), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsCustody[5], 6.5, truncate(ev.Custodian, 14), "1", 0, "L", false, 0, "")
			pdf.Ln(-1)
		}
		pdf.Ln(4)
	}

	// 6. Root Cause Finding & Corrective Actions
	if report.RootCause != "" || len(report.RemediationPlan) > 0 {
		renderSectionHeader(pdf, "5. Root Cause & Corrective Recommendations")
		ensurePageSpace(pdf, 20)
		if report.RootCause != "" {
			pdf.SetFont("Arial", "B", 8.5)
			pdf.SetTextColor(30, 41, 59)
			pdf.CellFormat(182, 5, "Root Cause Finding:", "", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 8.5)
			pdf.MultiCell(182, 4.5, report.RootCause, "", "L", false)
			pdf.Ln(2)
		}

		if len(report.RemediationPlan) > 0 {
			pdf.SetFont("Arial", "B", 8.5)
			pdf.CellFormat(182, 5, "Action Items & Engineering Directives:", "", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 8.5)
			for i, planItem := range report.RemediationPlan {
				ensurePageSpace(pdf, 6)
				pdf.MultiCell(182, 4.5, fmt.Sprintf("%d. %s", i+1, planItem), "", "L", false)
			}
		}
	}

	return pdf.Output(w)
}

func renderSectionHeader(pdf *gofpdf.Fpdf, title string) {
	ensurePageSpace(pdf, 12)
	pdf.SetFont("Arial", "B", 10)
	pdf.SetTextColor(30, 41, 59)
	pdf.CellFormat(182, 6, title, "B", 1, "L", false, 0, "")
	pdf.Ln(2)
}

func drawTableHeader(pdf *gofpdf.Fpdf, widths []float64, headers []string) {
	ensurePageSpace(pdf, 10)
	pdf.SetFont("Arial", "B", 8)
	pdf.SetFillColor(241, 245, 249)
	pdf.SetTextColor(51, 65, 85)
	pdf.SetDrawColor(203, 213, 225)
	pdf.SetLineWidth(0.2)
	for i, h := range headers {
		pdf.CellFormat(widths[i], 6.5, h, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)
}

func drawKPICard(pdf *gofpdf.Fpdf, x, y, w, h float64, label, value string) {
	pdf.Rect(x, y, w, h, "FD")
	pdf.SetXY(x, y+1.5)
	pdf.SetFont("Arial", "", 7.5)
	pdf.SetTextColor(100, 116, 139)
	pdf.CellFormat(w, 3.5, label, "", 2, "C", false, 0, "")
	pdf.SetFont("Arial", "B", 9)
	pdf.SetTextColor(15, 23, 42)
	pdf.CellFormat(w, 5.5, value, "", 0, "C", false, 0, "")
}

func ensurePageSpace(pdf *gofpdf.Fpdf, requiredHeight float64) {
	if pdf.GetY()+requiredHeight > 275 {
		pdf.AddPage()
	}
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-2] + ".."
	}
	return s
}
