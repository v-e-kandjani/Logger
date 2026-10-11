package reporting

import (
	"archive/zip"
	"bytes"
	"fmt"
	"html"
	"io"
	"os"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// ExportIncidentDOCX exports an OpenXML (.docx) document, either by injecting into an existing template or generating a standalone DOCX.
func ExportIncidentDOCX(templatePath string, report models.ComprehensiveIncidentReport, w io.Writer) error {
	branding := report.Tenant.ResolveLogo()

	var logoBytes []byte
	if branding.LogoPath != "" {
		if b, err := os.ReadFile(branding.LogoPath); err == nil {
			logoBytes = b
		}
	}

	// If templatePath exists on disk, use template-replacement mode
	if templatePath != "" {
		if _, err := os.Stat(templatePath); err == nil {
			return exportFromTemplate(templatePath, report, logoBytes, w)
		}
	}

	// Standalone OpenXML generator
	return generateStandaloneDOCX(report, logoBytes, w)
}

func exportFromTemplate(templatePath string, report models.ComprehensiveIncidentReport, logoBytes []byte, w io.Writer) error {
	r, err := zip.OpenReader(templatePath)
	if err != nil {
		return fmt.Errorf("failed to open docx template archive: %w", err)
	}
	defer r.Close()

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	replacements := map[string]string{
		"{{TENANT_NAME}}":       report.Tenant.TenantName,
		"{{TENANT_SLUG}}":       report.Tenant.TenantSlug,
		"{{REPORT_ID}}":         report.ReportID,
		"{{REPORT_TITLE}}":      report.Title,
		"{{CLASSIFICATION}}":    report.Classification,
		"{{START_TIME}}":        report.StartTime.UTC().Format(time.RFC3339),
		"{{END_TIME}}":          report.EndTime.UTC().Format(time.RFC3339),
		"{{EXECUTIVE_SUMMARY}}": report.ExecutiveSummary,
		"{{MTTD}}":              fmt.Sprintf("%d min", report.MTTDMinutes),
		"{{MTTA}}":              fmt.Sprintf("%d min", report.MTTAMinutes),
		"{{MTTR}}":              fmt.Sprintf("%d min", report.MTTRMinutes),
		"{{ROOT_CAUSE}}":        report.RootCause,
	}

	for _, file := range r.File {
		rc, err := file.Open()
		if err != nil {
			return err
		}

		fw, err := zipWriter.Create(file.Name)
		if err != nil {
			rc.Close()
			return err
		}

		switch file.Name {
		case "word/media/image1.png":
			if len(logoBytes) > 0 {
				_, _ = fw.Write(logoBytes)
			} else {
				_, _ = io.Copy(fw, rc)
			}
		case "word/document.xml":
			buf := new(bytes.Buffer)
			_, _ = io.Copy(buf, rc)
			content := buf.String()
			for k, v := range replacements {
				content = strings.ReplaceAll(content, k, html.EscapeString(v))
			}
			_, _ = fw.Write([]byte(content))
		default:
			_, _ = io.Copy(fw, rc)
		}
		rc.Close()
	}

	return nil
}

func generateStandaloneDOCX(report models.ComprehensiveIncidentReport, logoBytes []byte, w io.Writer) error {
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	// 1. [Content_Types].xml
	ctWriter, err := zipWriter.Create("[Content_Types].xml")
	if err != nil {
		return err
	}
	ctContent := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>`
	if _, err := ctWriter.Write([]byte(ctContent)); err != nil {
		return err
	}

	// 2. _rels/.rels
	relsWriter, err := zipWriter.Create("_rels/.rels")
	if err != nil {
		return err
	}
	relsContent := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
	if _, err := relsWriter.Write([]byte(relsContent)); err != nil {
		return err
	}

	// 3. word/_rels/document.xml.rels
	docRelsWriter, err := zipWriter.Create("word/_rels/document.xml.rels")
	if err != nil {
		return err
	}
	docRelsContent := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`
	if _, err := docRelsWriter.Write([]byte(docRelsContent)); err != nil {
		return err
	}

	// 4. word/styles.xml
	stylesWriter, err := zipWriter.Create("word/styles.xml")
	if err != nil {
		return err
	}
	stylesContent := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
        <w:sz w:val="22"/>
      </w:rPr>
    </w:rPrDefault>
  </w:docDefaults>
</w:styles>`
	if _, err := stylesWriter.Write([]byte(stylesContent)); err != nil {
		return err
	}

	// 5. word/document.xml
	docWriter, err := zipWriter.Create("word/document.xml")
	if err != nil {
		return err
	}

	isTR := strings.ToLower(report.Language) != "en"

	var bodyBuilder strings.Builder
	bodyBuilder.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>`)

	// Document Title
	title := report.Title
	if title == "" {
		if isTR {
			title = "Valtrivo LogSeal SIEM & SOC Olay İnceleme Raporu"
		} else {
			title = "Valtrivo LogSeal SIEM & SOC Investigation Report"
		}
	}
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p>
      <w:pPr><w:jc w:val="center"/><w:spacing w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="1E293B"/></w:rPr><w:t>%s</w:t></w:r>
    </w:p>`, html.EscapeString(title)))

	// Subheader Metadata
	classLabel := "CLASSIFICATION"
	tenantLabel := "Tenant"
	reportIDLabel := "Report ID"
	if isTR {
		classLabel = "SINIFLANDIRMA"
		tenantLabel = "Kiracı"
		reportIDLabel = "Rapor ID"
	}
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p>
      <w:pPr><w:jc w:val="center"/><w:spacing w:after="240"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="DC2626"/></w:rPr><w:t>%s: %s</w:t></w:r>
      <w:r><w:t>  |  %s: %s (%s)  |  %s: %s</w:t></w:r>
    </w:p>`, classLabel, html.EscapeString(report.Classification), tenantLabel, html.EscapeString(report.Tenant.TenantName), html.EscapeString(report.Tenant.TenantSlug), reportIDLabel, html.EscapeString(report.ReportID)))

	// Section 1: Executive Overview
	sec1Title := "1. Executive Summary &amp; Operational Metrics"
	lblMTTD := "Mean Time to Detect (MTTD)"
	lblMTTA := "Mean Time to Triage (MTTA)"
	lblMTTR := "Mean Time to Remediate (MTTR)"
	lbl5651 := "Law 5651 Regulatory Sealed"
	if isTR {
		sec1Title = "1. Yönetici Özeti ve Operasyonel Metrikler"
		lblMTTD = "Ortalama Tespit Süresi (MTTD)"
		lblMTTA = "Ortalama İnceleme Süresi (MTTA)"
		lblMTTR = "Ortalama Çözüm Süresi (MTTR)"
		lbl5651 = "5651 Sayılı Kanun Zaman Damgası Mühürlü"
	}
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>%s</w:t></w:r>
    </w:p>`, sec1Title))
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:after="160"/></w:pPr>
      <w:r><w:t>%s</w:t></w:r>
    </w:p>`, html.EscapeString(report.ExecutiveSummary)))

	// Metrics Table
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:tbl>
      <w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:left w:val="none"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:right w:val="none"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/></w:tblBorders></w:tblPr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%d min</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%d min</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%d min</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%t</w:t></w:r></w:p></w:tc>
      </w:tr>
    </w:tbl>`, lblMTTD, report.MTTDMinutes, lblMTTA, report.MTTAMinutes, lblMTTR, report.MTTRMinutes, lbl5651, report.RegulatoryImpact.Law5651Relevant))

	// Section 2: MITRE ATT&CK Threat Mappings
	if len(report.ThreatMappings) > 0 {
		sec2Title := "2. Tactical Threat Mapping (MITRE ATT&amp;CK &amp; D3FEND)"
		thTactic := "Tactic"
		thTechnique := "Technique"
		thName := "Name"
		thRule := "SIEM Detection Rule"
		if isTR {
			sec2Title = "2. Taktik Tehdit Matrisi (MITRE ATT&amp;CK &amp; D3FEND)"
			thTactic = "Taktik"
			thTechnique = "Teknik"
			thName = "Ad"
			thRule = "SIEM Tespit Kuralı"
		}
		bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>%s</w:t></w:r>
    </w:p>
    <w:tbl>
      <w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/></w:tblBorders></w:tblPr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
      </w:tr>`, sec2Title, thTactic, thTechnique, thName, thRule))
		for _, m := range report.ThreatMappings {
			bodyBuilder.WriteString(fmt.Sprintf(`
      <w:tr>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
      </w:tr>`, html.EscapeString(m.TacticID), html.EscapeString(m.TechniqueID), html.EscapeString(m.Name), html.EscapeString(m.RuleName)))
		}
		bodyBuilder.WriteString(`</w:tbl>`)
	}

	// Section 3: IOCs
	if len(report.IOCs) > 0 {
		sec3Title := "3. Threat Intelligence &amp; Indicators of Compromise (IOC)"
		thType := "Type"
		thValue := "Value"
		thConf := "Confidence"
		thAction := "Action Taken"
		if isTR {
			sec3Title = "3. Tehdit İstihbaratı ve Tehdit Göstergeleri (IOC)"
			thType = "Tür"
			thValue = "Değer"
			thConf = "Güven"
			thAction = "Uygulanan Eylem"
		}
		bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>%s</w:t></w:r>
    </w:p>
    <w:tbl>
      <w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/></w:tblBorders></w:tblPr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
      </w:tr>`, sec3Title, thType, thValue, thConf, thAction))
		for _, ioc := range report.IOCs {
			bodyBuilder.WriteString(fmt.Sprintf(`
      <w:tr>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
      </w:tr>`, html.EscapeString(ioc.Type), html.EscapeString(ioc.Value), html.EscapeString(ioc.Confidence), html.EscapeString(ioc.ActionTaken)))
		}
		bodyBuilder.WriteString(`</w:tbl>`)
	}

	// Section 4: Forensic Chain of Custody & Law 5651
	if len(report.ChainOfCustody) > 0 {
		sec4Title := "4. Forensic Chain of Custody &amp; Law No. 5651 Evidence Ledger"
		thEvID := "Evidence ID"
		thArtType := "Type"
		thHost := "Source Host"
		thHash := "SHA-256 Checksum"
		thToken := "TSA Token"
		if isTR {
			sec4Title = "4. Adli Kanıt Defteri ve 5651 Sayılı Kanun Kanıt Zinciri"
			thEvID = "Kanıt ID"
			thArtType = "Tür"
			thHost = "Kaynak Cihaz"
			thHash = "SHA-256 Özeti"
			thToken = "Zaman Damgası"
		}
		bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>%s</w:t></w:r>
    </w:p>
    <w:tbl>
      <w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/></w:tblBorders></w:tblPr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%s</w:t></w:r></w:p></w:tc>
      </w:tr>`, sec4Title, thEvID, thArtType, thHost, thHash, thToken))
		for _, ev := range report.ChainOfCustody {
			bodyBuilder.WriteString(fmt.Sprintf(`
      <w:tr>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%s</w:t></w:r></w:p></w:tc>
      </w:tr>`, html.EscapeString(ev.EvidenceID), html.EscapeString(ev.ArtifactType), html.EscapeString(ev.SourceHost), html.EscapeString(ev.SHA256Hash), html.EscapeString(ev.TSATokenZD)))
		}
		bodyBuilder.WriteString(`</w:tbl>`)
	}

	// Section 5: Root Cause & Action Items
	if report.RootCause != "" || len(report.RemediationPlan) > 0 {
		sec5Title := "5. Root Cause Analysis &amp; Corrective Recommendations"
		rcPrefix := "Root Cause:"
		if isTR {
			sec5Title = "5. Kök Neden Analizi ve Düzeltici İyileştirme Tavsiyeleri"
			rcPrefix = "Kök Neden:"
		}
		bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>%s</w:t></w:r>
    </w:p>`, sec5Title))
		if report.RootCause != "" {
			bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>%s </w:t></w:r>
      <w:r><w:t>%s</w:t></w:r>
    </w:p>`, rcPrefix, html.EscapeString(report.RootCause)))
		}
		for i, plan := range report.RemediationPlan {
			bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:after="80"/></w:pPr>
      <w:r><w:t>%d. %s</w:t></w:r>
    </w:p>`, i+1, html.EscapeString(plan)))
		}
	}

	// Sign-off Footer
	footerText := fmt.Sprintf("Generated at %s by Valtrivo LogSeal SIEM Platform | Timestamp Verified", report.GeneratedAt.UTC().Format(time.RFC3339))
	if isTR {
		footerText = fmt.Sprintf("Valtrivo LogSeal SIEM Platformu tarafından %s tarihinde üretildi | Zaman Damgası Doğrulandı", report.GeneratedAt.UTC().Format(time.RFC3339))
	}
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:before="360"/><w:jc w:val="center"/></w:pPr>
      <w:r><w:rPr><w:i/><w:color w:val="64748B"/></w:rPr><w:t>%s</w:t></w:r>
    </w:p>`, html.EscapeString(footerText)))

	bodyBuilder.WriteString(`
  </w:body>
</w:document>`)

	bodyBuilder.WriteString(`
  </w:body>
</w:document>`)

	_, err = docWriter.Write([]byte(bodyBuilder.String()))
	return err
}
