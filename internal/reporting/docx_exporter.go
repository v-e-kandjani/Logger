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

	var bodyBuilder strings.Builder
	bodyBuilder.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>`)

	// Document Title
	title := report.Title
	if title == "" {
		title = "Valtrivo LogSeal SIEM & SOC Investigation Report"
	}
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p>
      <w:pPr><w:jc w:val="center"/><w:spacing w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="1E293B"/></w:rPr><w:t>%s</w:t></w:r>
    </w:p>`, html.EscapeString(title)))

	// Subheader Metadata
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p>
      <w:pPr><w:jc w:val="center"/><w:spacing w:after="240"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="DC2626"/></w:rPr><w:t>CLASSIFICATION: %s</w:t></w:r>
      <w:r><w:t>  |  Tenant: %s (%s)  |  Report ID: %s</w:t></w:r>
    </w:p>`, html.EscapeString(report.Classification), html.EscapeString(report.Tenant.TenantName), html.EscapeString(report.Tenant.TenantSlug), html.EscapeString(report.ReportID)))

	// Section 1: Executive Overview
	bodyBuilder.WriteString(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>1. Executive Summary &amp; Operational Metrics</w:t></w:r>
    </w:p>`)
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:after="160"/></w:pPr>
      <w:r><w:t>%s</w:t></w:r>
    </w:p>`, html.EscapeString(report.ExecutiveSummary)))

	// Metrics Table
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:tbl>
      <w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:left w:val="none"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:right w:val="none"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/></w:tblBorders></w:tblPr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Mean Time to Detect (MTTD)</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%d min</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Mean Time to Triage (MTTA)</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%d min</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Mean Time to Remediate (MTTR)</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%d min</w:t></w:r></w:p></w:tc>
      </w:tr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Law 5651 Regulatory Sealed</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:t>%t</w:t></w:r></w:p></w:tc>
      </w:tr>
    </w:tbl>`, report.MTTDMinutes, report.MTTAMinutes, report.MTTRMinutes, report.RegulatoryImpact.Law5651Relevant))

	// Section 2: MITRE ATT&CK Threat Mappings
	if len(report.ThreatMappings) > 0 {
		bodyBuilder.WriteString(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>2. Tactical Threat Mapping (MITRE ATT&amp;CK &amp; D3FEND)</w:t></w:r>
    </w:p>
    <w:tbl>
      <w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/></w:tblBorders></w:tblPr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Tactic</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Technique</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Name</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>SIEM Detection Rule</w:t></w:r></w:p></w:tc>
      </w:tr>`)
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
		bodyBuilder.WriteString(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>3. Threat Intelligence &amp; Indicators of Compromise (IOC)</w:t></w:r>
    </w:p>
    <w:tbl>
      <w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/></w:tblBorders></w:tblPr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Type</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Value</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Confidence</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Action Taken</w:t></w:r></w:p></w:tc>
      </w:tr>`)
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
		bodyBuilder.WriteString(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>4. Forensic Chain of Custody &amp; Law No. 5651 Evidence Ledger</w:t></w:r>
    </w:p>
    <w:tbl>
      <w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/></w:tblBorders></w:tblPr>
      <w:tr>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Evidence ID</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Type</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>Source Host</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>SHA-256 Checksum</w:t></w:r></w:p></w:tc>
        <w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>TSA Token</w:t></w:r></w:p></w:tc>
      </w:tr>`)
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
		bodyBuilder.WriteString(`
    <w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr><w:t>5. Root Cause Analysis &amp; Corrective Recommendations</w:t></w:r>
    </w:p>`)
		if report.RootCause != "" {
			bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:after="120"/></w:pPr>
      <w:r><w:rPr><w:b/></w:rPr><w:t>Root Cause: </w:t></w:r>
      <w:r><w:t>%s</w:t></w:r>
    </w:p>`, html.EscapeString(report.RootCause)))
		}
		for i, plan := range report.RemediationPlan {
			bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:after="80"/></w:pPr>
      <w:r><w:t>%d. %s</w:t></w:r>
    </w:p>`, i+1, html.EscapeString(plan)))
		}
	}

	// Sign-off Footer
	bodyBuilder.WriteString(fmt.Sprintf(`
    <w:p><w:pPr><w:spacing w:before="360"/><w:jc w:val="center"/></w:pPr>
      <w:r><w:rPr><w:i/><w:color w:val="64748B"/></w:rPr><w:t>Generated at %s by Valtrivo LogSeal SIEM Platform | Timestamp Verified</w:t></w:r>
    </w:p>`, report.GeneratedAt.UTC().Format(time.RFC3339)))

	bodyBuilder.WriteString(`
  </w:body>
</w:document>`)

	_, err = docWriter.Write([]byte(bodyBuilder.String()))
	return err
}
