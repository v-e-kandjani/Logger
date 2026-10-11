package reporting

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jung-kurt/gofpdf"
	"github.com/syslog-platform/logger/internal/models"
)

// GenerateForensicIncidentPDF generates a forensic-grade A4 Landscape PDF report with optimally seated columns.
func GenerateForensicIncidentPDF(w io.Writer, report models.ComprehensiveIncidentReport) error {
	isTR := strings.ToLower(report.Language) != "en"

	// A4 Landscape: 297mm width x 210mm height. Margins: 14mm left/right -> Printable width: 269mm.
	pdf := gofpdf.New("L", "mm", "A4", "")
	pdf.SetMargins(14, 12, 14)
	pdf.SetAutoPageBreak(true, 16)

	// Custom Landscape Footer with confidentiality and page numbers
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		footerLeft := fmt.Sprintf("Valtrivo LogSeal | %s | Report ID: %s", report.Classification, report.ReportID)
		footerRight := fmt.Sprintf("Page %d of {nb}", pdf.PageNo())
		if isTR {
			footerLeft = fmt.Sprintf("Valtrivo LogSeal | %s | Rapor ID: %s", report.Classification, report.ReportID)
			footerRight = fmt.Sprintf("Sayfa %d / {nb}", pdf.PageNo())
		}
		pdf.CellFormat(135, 8, cleanPDFText(footerLeft), "", 0, "L", false, 0, "")
		pdf.CellFormat(134, 8, cleanPDFText(footerRight), "", 0, "R", false, 0, "")
	})
	pdf.AliasNbPages("{nb}")
	pdf.AddPage()

	branding := report.Tenant.ResolveLogo()

	// 1. Header (Logo + Metadata)
	if _, err := os.Stat(branding.LogoPath); err == nil {
		var imgOpt gofpdf.ImageOptions
		imgOpt.ImageType = "PNG"
		pdf.ImageOptions(branding.LogoPath, 14, 10, 26, 0, false, imgOpt, 0, "")
	}

	pdf.SetFont("Arial", "B", 13)
	pdf.SetTextColor(26, 32, 44)
	pdf.SetXY(45, 9)

	headerTitle := "SOC INCIDENT & FORENSIC INVESTIGATION REPORT"
	if isTR {
		headerTitle = "SOC OLAY VE ADLI BILISIM INCELEME RAPORU"
	}
	if report.Title != "" {
		headerTitle = strings.ToUpper(cleanPDFText(report.Title))
	}
	pdf.CellFormat(238, 5.5, headerTitle, "", 1, "R", false, 0, "")

	pdf.SetFont("Arial", "B", 8.5)
	pdf.SetTextColor(200, 35, 51) // Red callout for classification
	pdf.SetX(45)
	classificationPrefix := "CLASSIFICATION"
	if isTR {
		classificationPrefix = "SINIFLANDIRMA"
	}
	pdf.CellFormat(238, 4, fmt.Sprintf("%s: %s", classificationPrefix, cleanPDFText(report.Classification)), "", 1, "R", false, 0, "")

	pdf.SetFont("Arial", "", 8)
	pdf.SetTextColor(100, 116, 139)

	pdf.SetX(45)
	tenantLine := fmt.Sprintf("Tenant: %s [Slug: %s]", report.Tenant.TenantName, report.Tenant.TenantSlug)
	if isTR {
		tenantLine = fmt.Sprintf("Kiraci: %s [Kisa Ad: %s]", report.Tenant.TenantName, report.Tenant.TenantSlug)
	}
	pdf.CellFormat(238, 3.8, cleanPDFText(tenantLine), "", 1, "R", false, 0, "")

	pdf.SetX(45)
	timeframeLine := fmt.Sprintf("Timeframe: %s to %s",
		report.StartTime.UTC().Format("2006-01-02 15:04"),
		report.EndTime.UTC().Format("2006-01-02 15:04 UTC"),
	)
	if isTR {
		timeframeLine = fmt.Sprintf("Zaman Araligi: %s ile %s UTC arasi",
			report.StartTime.UTC().Format("2006-01-02 15:04"),
			report.EndTime.UTC().Format("2006-01-02 15:04"),
		)
	}
	pdf.CellFormat(238, 3.8, cleanPDFText(timeframeLine), "", 1, "R", false, 0, "")

	// Horizontal Rule Divider across 269mm printable width
	pdf.SetDrawColor(226, 232, 240)
	pdf.SetLineWidth(0.4)
	pdf.Line(14, 30, 283, 30)
	pdf.SetY(33)

	// 2. Executive Overview & SLA KPI Cards
	sec1Title := "1. Executive Summary & Operational Metrics"
	if isTR {
		sec1Title = "1. Yonetici Ozeti ve Operasyonel Metrikler"
	}
	renderSectionHeader(pdf, sec1Title)
	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(51, 65, 85)
	pdf.MultiCell(269, 4.5, cleanPDFText(report.ExecutiveSummary), "", "L", false)
	pdf.Ln(2.5)

	kpiWidth := 65.0
	kpiHeight := 13.0
	kpiGap := 3.0
	pdf.SetFillColor(248, 250, 252)
	pdf.SetDrawColor(203, 213, 225)
	pdf.SetLineWidth(0.2)

	startX := 14.0
	currentY := pdf.GetY()
	lblMTTD := "MTTD (Detect)"
	lblMTTA := "MTTA (Triage)"
	lblMTTR := "MTTR (Contain)"
	lblLegal := "Legal / Compliance"
	if isTR {
		lblMTTD = "MTTD (Tespit Suresi)"
		lblMTTA = "MTTA (Inceleme Suresi)"
		lblMTTR = "MTTR (Mudahale Suresi)"
		lblLegal = "Yasal / Mevzuat Uyumu"
	}

	drawKPICard(pdf, startX, currentY, kpiWidth, kpiHeight, lblMTTD, fmt.Sprintf("%dm", report.MTTDMinutes))
	drawKPICard(pdf, startX+kpiWidth+kpiGap, currentY, kpiWidth, kpiHeight, lblMTTA, fmt.Sprintf("%dm", report.MTTAMinutes))
	drawKPICard(pdf, startX+((kpiWidth+kpiGap)*2), currentY, kpiWidth, kpiHeight, lblMTTR, fmt.Sprintf("%dm", report.MTTRMinutes))

	regStatus := "Compliant"
	if report.RegulatoryImpact.BreachConfirmed {
		regStatus = strings.Join(report.RegulatoryImpact.Regulations, ", ")
	} else if report.RegulatoryImpact.Law5651Relevant {
		if isTR {
			regStatus = "5651 Muhurlendi"
		} else {
			regStatus = "Law 5651 Sealed"
		}
	} else if isTR {
		regStatus = "Uyumlu"
	}
	drawKPICard(pdf, startX+((kpiWidth+kpiGap)*3), currentY, kpiWidth, kpiHeight, lblLegal, regStatus)
	pdf.SetY(currentY + kpiHeight + 5)

	// 3. MITRE ATT&CK & D3FEND Threat Matrix (269mm total)
	if len(report.ThreatMappings) > 0 {
		sec2Title := "2. Tactical Threat Mapping (MITRE ATT&CK & D3FEND)"
		mitreHeaders := []string{"Tactic ID", "Technique ID", "Technique Name", "SIEM Detection Rule", "D3FEND Counter"}
		if isTR {
			sec2Title = "2. Taktik Tehdit Matrisi (MITRE ATT&CK & D3FEND)"
			mitreHeaders = []string{"Taktik ID", "Teknik ID", "Teknik Adi", "SIEM Tespit Kurali", "D3FEND Savunma"}
		}
		renderSectionHeader(pdf, sec2Title)
		colWidthsMitre := []float64{34, 36, 62, 92, 45} // 34+36+62+92+45 = 269mm
		drawTableHeader(pdf, colWidthsMitre, mitreHeaders)
		pdf.SetFont("Arial", "", 8)
		pdf.SetTextColor(30, 41, 59)
		for _, m := range report.ThreatMappings {
			ensurePageSpace(pdf, 6.5)
			pdf.CellFormat(colWidthsMitre[0], 6.5, cleanPDFText(m.TacticID), "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsMitre[1], 6.5, cleanPDFText(m.TechniqueID), "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsMitre[2], 6.5, cleanPDFText(truncate(m.Name, 36)), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsMitre[3], 6.5, cleanPDFText(truncate(m.RuleName, 58)), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsMitre[4], 6.5, cleanPDFText(m.D3FENDID), "1", 0, "C", false, 0, "")
			pdf.Ln(-1)
		}
		pdf.Ln(3.5)
	}

	// 4. Indicators of Compromise (IOC) (269mm total)
	if len(report.IOCs) > 0 {
		sec3Title := "3. Extracted Threat Intelligence & IOCs"
		iocHeaders := []string{"Type", "Indicator Value", "Confidence", "Reputation/Feed", "Action Taken"}
		if isTR {
			sec3Title = "3. Tespit Edilen Tehdit Istihbarati ve IOC Kayitlari"
			iocHeaders = []string{"Tur", "Tehdit Degeri (IOC)", "Guven", "Itibar / Istihbarat", "Uygulanan Eylem"}
		}
		renderSectionHeader(pdf, sec3Title)
		colWidthsIOC := []float64{32, 105, 32, 50, 50} // 32+105+32+50+50 = 269mm
		drawTableHeader(pdf, colWidthsIOC, iocHeaders)
		pdf.SetFont("Arial", "", 8)
		pdf.SetTextColor(30, 41, 59)
		for _, ioc := range report.IOCs {
			ensurePageSpace(pdf, 6.5)
			pdf.CellFormat(colWidthsIOC[0], 6.5, cleanPDFText(ioc.Type), "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsIOC[1], 6.5, cleanPDFText(truncate(ioc.Value, 65)), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsIOC[2], 6.5, cleanPDFText(ioc.Confidence), "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsIOC[3], 6.5, cleanPDFText(truncate(ioc.Reputation, 30)), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsIOC[4], 6.5, cleanPDFText(truncate(ioc.ActionTaken, 30)), "1", 0, "L", false, 0, "")
			pdf.Ln(-1)
		}
		pdf.Ln(3.5)
	}

	// 5. Chain of Custody & Law 5651 Evidence Ledger (269mm total)
	if len(report.ChainOfCustody) > 0 {
		sec4Title := "4. Forensic Evidence & Cryptographic Chain of Custody (Law 5651)"
		custodyHeaders := []string{"Evidence ID", "Artifact Type", "Host/Device", "Acquired (UTC)", "SHA-256 Checksum", "Custodian"}
		if isTR {
			sec4Title = "4. Adli Kanit Defteri ve Kriptografik Kanit Zinciri (5651)"
			custodyHeaders = []string{"Kanit ID", "Delil Turu", "Kaynak Cihaz", "Alinma Zamani (UTC)", "SHA-256 Ozeti", "Emanetci"}
		}
		renderSectionHeader(pdf, sec4Title)
		colWidthsCustody := []float64{28, 40, 42, 42, 75, 42} // 28+40+42+42+75+42 = 269mm
		drawTableHeader(pdf, colWidthsCustody, custodyHeaders)
		pdf.SetFont("Arial", "", 7.5)
		pdf.SetTextColor(30, 41, 59)
		for _, ev := range report.ChainOfCustody {
			ensurePageSpace(pdf, 6.5)
			pdf.CellFormat(colWidthsCustody[0], 6.5, cleanPDFText(ev.EvidenceID), "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsCustody[1], 6.5, cleanPDFText(ev.ArtifactType), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsCustody[2], 6.5, cleanPDFText(truncate(ev.SourceHost, 24)), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsCustody[3], 6.5, ev.AcquisitionAt.UTC().Format("2006-01-02 15:04:05"), "1", 0, "C", false, 0, "")
			pdf.CellFormat(colWidthsCustody[4], 6.5, cleanPDFText(truncate(ev.SHA256Hash, 46)), "1", 0, "L", false, 0, "")
			pdf.CellFormat(colWidthsCustody[5], 6.5, cleanPDFText(truncate(ev.Custodian, 24)), "1", 0, "L", false, 0, "")
			pdf.Ln(-1)
		}
		pdf.Ln(3.5)
	}

	// 6. Root Cause Finding & Corrective Actions
	if report.RootCause != "" || len(report.RemediationPlan) > 0 {
		sec5Title := "5. Root Cause & Corrective Recommendations"
		rcLabel := "Root Cause Finding:"
		actLabel := "Action Items & Engineering Directives:"
		if isTR {
			sec5Title = "5. Kok Neden Tespiti ve Iyilestirme Onerileri"
			rcLabel = "Kok Neden Tespiti:"
			actLabel = "Eylem Maddeleri ve Muhendislik Direktifleri:"
		}
		renderSectionHeader(pdf, sec5Title)
		ensurePageSpace(pdf, 18)
		if report.RootCause != "" {
			pdf.SetFont("Arial", "B", 8.5)
			pdf.SetTextColor(30, 41, 59)
			pdf.CellFormat(269, 5, rcLabel, "", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 8.5)
			pdf.MultiCell(269, 4.5, cleanPDFText(report.RootCause), "", "L", false)
			pdf.Ln(2)
		}

		if len(report.RemediationPlan) > 0 {
			pdf.SetFont("Arial", "B", 8.5)
			pdf.CellFormat(269, 5, actLabel, "", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 8.5)
			for i, planItem := range report.RemediationPlan {
				ensurePageSpace(pdf, 5.5)
				pdf.MultiCell(269, 4.2, cleanPDFText(fmt.Sprintf("%d. %s", i+1, planItem)), "", "L", false)
			}
		}
	}

	return pdf.Output(w)
}

func renderSectionHeader(pdf *gofpdf.Fpdf, title string) {
	ensurePageSpace(pdf, 10)
	pdf.SetFont("Arial", "B", 9.5)
	pdf.SetTextColor(30, 41, 59)
	pdf.CellFormat(269, 5.5, cleanPDFText(title), "B", 1, "L", false, 0, "")
	pdf.Ln(2)
}

func drawTableHeader(pdf *gofpdf.Fpdf, widths []float64, headers []string) {
	ensurePageSpace(pdf, 9)
	pdf.SetFont("Arial", "B", 8)
	pdf.SetFillColor(241, 245, 249)
	pdf.SetTextColor(51, 65, 85)
	pdf.SetDrawColor(203, 213, 225)
	pdf.SetLineWidth(0.2)
	for i, h := range headers {
		pdf.CellFormat(widths[i], 6.5, cleanPDFText(h), "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)
}

func drawKPICard(pdf *gofpdf.Fpdf, x, y, w, h float64, label, value string) {
	pdf.Rect(x, y, w, h, "FD")
	pdf.SetXY(x, y+1.2)
	pdf.SetFont("Arial", "", 7.5)
	pdf.SetTextColor(100, 116, 139)
	pdf.CellFormat(w, 3.5, cleanPDFText(label), "", 2, "C", false, 0, "")
	pdf.SetFont("Arial", "B", 9)
	pdf.SetTextColor(15, 23, 42)
	pdf.CellFormat(w, 5.5, cleanPDFText(value), "", 0, "C", false, 0, "")
}

func ensurePageSpace(pdf *gofpdf.Fpdf, requiredHeight float64) {
	if pdf.GetY()+requiredHeight > 190 {
		pdf.AddPage()
	}
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-2] + ".."
	}
	return s
}

// cleanPDFText converts non-ASCII characters to standard ASCII equivalents for gofpdf core font rendering.
func cleanPDFText(s string) string {
	replacer := strings.NewReplacer(
		"ğ", "g", "Ğ", "G",
		"ş", "s", "Ş", "S",
		"ı", "i", "İ", "I",
		"ç", "c", "Ç", "C",
		"ö", "o", "Ö", "O",
		"ü", "u", "Ü", "U",
	)
	return replacer.Replace(s)
}
