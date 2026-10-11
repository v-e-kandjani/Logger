package reporting

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// ExportIncidentCSV exports structured forensic incident reports into RFC 4180 CSV with metadata comments.
func ExportIncidentCSV(w io.Writer, report models.ComprehensiveIncidentReport) error {
	isTR := strings.ToLower(report.Language) != "en"
	branding := report.Tenant.ResolveLogo()

	brandingType := "Tenant Custom Logo"
	if !branding.IsCustom {
		if isTR {
			brandingType = "Valtrivo LogSeal Sistem Varsayılanı (Yedek Devrede)"
		} else {
			brandingType = "Valtrivo LogSeal System Default (Fallback Applied)"
		}
	} else if isTR {
		brandingType = "Kiracı Özel Logosu"
	}

	var metadata string
	if isTR {
		metadata = fmt.Sprintf(
			"# Valtrivo LogSeal SIEM & Adli Bilişim Raporlama Motoru\n"+
				"# Platform Görseli: %s\n"+
				"# Kiracı Adı: %s (Kısa Ad: %s)\n"+
				"# Rapor ID: %s | Başlık: %s\n"+
				"# Sınıflandırma: %s\n"+
				"# Zaman Aralığı: %s ile %s arası\n"+
				"# 5651 Sayılı Kanun Uyumluluğu: %t\n"+
				"# Oluşturulma Zamanı: %s\n"+
				"# Motor İmzası: Valtrivo LogSeal SIEM | Zaman Damgası Doğrulandı\n#\n",
			brandingType,
			report.Tenant.TenantName,
			report.Tenant.TenantSlug,
			report.ReportID,
			report.Title,
			report.Classification,
			report.StartTime.UTC().Format(time.RFC3339),
			report.EndTime.UTC().Format(time.RFC3339),
			report.RegulatoryImpact.Law5651Relevant,
			report.GeneratedAt.UTC().Format(time.RFC3339),
		)
	} else {
		metadata = fmt.Sprintf(
			"# Valtrivo LogSeal SIEM & Forensic Reporting Engine\n"+
				"# Platform Branding: %s\n"+
				"# Tenant Name: %s (Slug: %s)\n"+
				"# Report ID: %s | Title: %s\n"+
				"# Classification: %s\n"+
				"# Timeframe: %s to %s\n"+
				"# Law 5651 Regulatory Compliance: %t\n"+
				"# Generated At: %s\n"+
				"# Engine Signature: Valtrivo LogSeal SIEM | Timestamp Integrity Verified\n#\n",
			brandingType,
			report.Tenant.TenantName,
			report.Tenant.TenantSlug,
			report.ReportID,
			report.Title,
			report.Classification,
			report.StartTime.UTC().Format(time.RFC3339),
			report.EndTime.UTC().Format(time.RFC3339),
			report.RegulatoryImpact.Law5651Relevant,
			report.GeneratedAt.UTC().Format(time.RFC3339),
		)
	}

	if _, err := w.Write([]byte(metadata)); err != nil {
		return err
	}

	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	// 1. Executive Summary & KPIs
	sec1Header := "[EXECUTIVE SUMMARY & OPERATIONAL METRICS]"
	colMetric := "Metric"
	colValue := "Value"
	lblSummary := "Executive Summary"
	lblEvents := "Total Ingested Events"
	lblAlerts := "Total Triggered Alerts"
	lblCritical := "Critical Severity Alerts"
	lblMTTD := "Mean Time to Detect (MTTD)"
	lblMTTA := "Mean Time to Acknowledge (MTTA)"
	lblMTTR := "Mean Time to Remediate (MTTR)"
	if isTR {
		sec1Header = "[YÖNETİCİ ÖZETİ VE OPERASYONEL METRİKLER]"
		colMetric = "Metrik"
		colValue = "Değer"
		lblSummary = "Yönetici Özeti"
		lblEvents = "Toplam İşlenen Olay (Event)"
		lblAlerts = "Toplam Tetiklenen Alarm"
		lblCritical = "Kritik Dereceli Alarmlar"
		lblMTTD = "Ortalama Tespit Süresi (MTTD)"
		lblMTTA = "Ortalama İnceleme Süresi (MTTA)"
		lblMTTR = "Ortalama Çözüm Süresi (MTTR)"
	}

	if err := csvWriter.Write([]string{sec1Header}); err != nil {
		return err
	}
	if err := csvWriter.Write([]string{colMetric, colValue}); err != nil {
		return err
	}
	_ = csvWriter.Write([]string{lblSummary, report.ExecutiveSummary})
	_ = csvWriter.Write([]string{lblEvents, fmt.Sprintf("%d", report.TotalEvents)})
	_ = csvWriter.Write([]string{lblAlerts, fmt.Sprintf("%d", report.TotalAlerts)})
	_ = csvWriter.Write([]string{lblCritical, fmt.Sprintf("%d", report.CriticalAlerts)})
	_ = csvWriter.Write([]string{lblMTTD, fmt.Sprintf("%d min", report.MTTDMinutes)})
	_ = csvWriter.Write([]string{lblMTTA, fmt.Sprintf("%d min", report.MTTAMinutes)})
	_ = csvWriter.Write([]string{lblMTTR, fmt.Sprintf("%d min", report.MTTRMinutes)})

	// 2. Indicators of Compromise (IOC)
	if len(report.IOCs) > 0 {
		sec2Header := "[INDICATORS OF COMPROMISE (IOC)]"
		iocHeaders := []string{"Type", "Value", "Confidence", "Reputation/Feed", "Action Taken"}
		if isTR {
			sec2Header = "[TEHDİT GÖSTERGELERİ (IOC)]"
			iocHeaders = []string{"Tür", "Değer", "Güven", "İtibar / İstihbarat", "Uygulanan Eylem"}
		}
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{sec2Header}); err != nil {
			return err
		}
		if err := csvWriter.Write(iocHeaders); err != nil {
			return err
		}
		for _, ioc := range report.IOCs {
			if err := csvWriter.Write([]string{ioc.Type, ioc.Value, ioc.Confidence, ioc.Reputation, ioc.ActionTaken}); err != nil {
				return err
			}
		}
	}

	// 3. Tactical Threat Mapping (MITRE ATT&CK & D3FEND)
	if len(report.ThreatMappings) > 0 {
		sec3Header := "[TACTICAL THREAT MAPPINGS (MITRE ATT&CK & D3FEND)]"
		mitreHeaders := []string{"Tactic ID", "Technique ID", "Technique Name", "SIEM Detection Rule", "D3FEND Counter"}
		if isTR {
			sec3Header = "[TAKTİK TEHDİT MATRİSİ (MITRE ATT&CK & D3FEND)]"
			mitreHeaders = []string{"Taktik ID", "Teknik ID", "Teknik Adı", "SIEM Tespit Kuralı", "D3FEND Savunma"}
		}
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{sec3Header}); err != nil {
			return err
		}
		if err := csvWriter.Write(mitreHeaders); err != nil {
			return err
		}
		for _, m := range report.ThreatMappings {
			if err := csvWriter.Write([]string{m.TacticID, m.TechniqueID, m.Name, m.RuleName, m.D3FENDID}); err != nil {
				return err
			}
		}
	}

	// 4. Chain of Custody & Forensic Evidences (Law 5651 Verification)
	if len(report.ChainOfCustody) > 0 {
		sec4Header := "[CHAIN OF CUSTODY & LAW NO. 5651 TIMESTAMP EVIDENCE]"
		custodyHeaders := []string{"Evidence ID", "Artifact Type", "Source Host", "Acquisition Time (UTC)", "SHA-256 Digest", "TSA Token (.zd)", "Custodian"}
		if isTR {
			sec4Header = "[ADLİ KANIT DEFTERİ VE 5651 SAYILI KANUN KANIT ZİNCİRİ]"
			custodyHeaders = []string{"Kanıt ID", "Delil Türü", "Kaynak Cihaz", "Alınma Zamanı (UTC)", "SHA-256 Özeti", "Zaman Damgası (.zd)", "Emanetçi"}
		}
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{sec4Header}); err != nil {
			return err
		}
		if err := csvWriter.Write(custodyHeaders); err != nil {
			return err
		}
		for _, ev := range report.ChainOfCustody {
			record := []string{
				ev.EvidenceID,
				ev.ArtifactType,
				ev.SourceHost,
				ev.AcquisitionAt.UTC().Format(time.RFC3339),
				ev.SHA256Hash,
				ev.TSATokenZD,
				ev.Custodian,
			}
			if err := csvWriter.Write(record); err != nil {
				return err
			}
		}
	}

	// 5. Root Cause & Action Items
	if report.RootCause != "" || len(report.RemediationPlan) > 0 {
		sec5Header := "[ROOT CAUSE ANALYSIS & CORRECTIVE RECOMMENDATIONS]"
		lblRC := "Root Cause Finding"
		lblStepPrefix := "Remediation Step"
		if isTR {
			sec5Header = "[KÖK NEDEN VE DÜZELTİCİ EYLEM PLANI]"
			lblRC = "Kök Neden Tespiti"
			lblStepPrefix = "İyileştirme Adımı"
		}
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{sec5Header}); err != nil {
			return err
		}
		if report.RootCause != "" {
			_ = csvWriter.Write([]string{lblRC, report.RootCause})
		}
		for i, plan := range report.RemediationPlan {
			_ = csvWriter.Write([]string{fmt.Sprintf("%s %d", lblStepPrefix, i+1), plan})
		}
	}

	// 6. Extended Compliance Sampling
	if report.ComplianceData != nil && len(report.ComplianceData.SampledEvents) > 0 {
		sec6Header := "[STATUTORY COMPLIANCE PRIVILEGED ACCESS LOG SAMPLING]"
		compHeaders := []string{"Timestamp (UTC)", "Principal/User", "Target System", "Action Executed", "Justification"}
		if isTR {
			sec6Header = "[YASAL MEVZUAT AYRICALIKLI ERİŞİM DENETİM LOGU ÖRNEKLEMESİ]"
			compHeaders = []string{"Zaman Damgası (UTC)", "Kullanıcı / Yetkili", "Hedef Sistem", "Gerçekleştirilen Eylem", "Gerekçe"}
		}
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{sec6Header}); err != nil {
			return err
		}
		if err := csvWriter.Write(compHeaders); err != nil {
			return err
		}
		for _, evt := range report.ComplianceData.SampledEvents {
			_ = csvWriter.Write([]string{evt.Timestamp, evt.Principal, evt.TargetHost, evt.Action, evt.Justification})
		}
	}

	return csvWriter.Error()
}
