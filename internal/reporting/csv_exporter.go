package reporting

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// ExportIncidentCSV exports structured forensic incident reports into RFC 4180 CSV with metadata comments.
func ExportIncidentCSV(w io.Writer, report models.ComprehensiveIncidentReport) error {
	branding := report.Tenant.ResolveLogo()

	brandingType := "Tenant Custom Logo"
	if !branding.IsCustom {
		brandingType = "Valtrivo LogSeal System Default (Fallback Applied)"
	}

	metadata := fmt.Sprintf(
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

	if _, err := w.Write([]byte(metadata)); err != nil {
		return err
	}

	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	// 1. Executive Summary & KPIs
	if err := csvWriter.Write([]string{"[EXECUTIVE SUMMARY & OPERATIONAL METRICS]"}); err != nil {
		return err
	}
	if err := csvWriter.Write([]string{"Metric", "Value"}); err != nil {
		return err
	}
	_ = csvWriter.Write([]string{"Executive Summary", report.ExecutiveSummary})
	_ = csvWriter.Write([]string{"Total Ingested Events", fmt.Sprintf("%d", report.TotalEvents)})
	_ = csvWriter.Write([]string{"Total Triggered Alerts", fmt.Sprintf("%d", report.TotalAlerts)})
	_ = csvWriter.Write([]string{"Critical Severity Alerts", fmt.Sprintf("%d", report.CriticalAlerts)})
	_ = csvWriter.Write([]string{"Mean Time to Detect (MTTD)", fmt.Sprintf("%d min", report.MTTDMinutes)})
	_ = csvWriter.Write([]string{"Mean Time to Acknowledge (MTTA)", fmt.Sprintf("%d min", report.MTTAMinutes)})
	_ = csvWriter.Write([]string{"Mean Time to Remediate (MTTR)", fmt.Sprintf("%d min", report.MTTRMinutes)})

	// 2. Indicators of Compromise (IOC)
	if len(report.IOCs) > 0 {
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"[INDICATORS OF COMPROMISE (IOC)]"}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"Type", "Value", "Confidence", "Reputation/Feed", "Action Taken"}); err != nil {
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
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"[TACTICAL THREAT MAPPINGS (MITRE ATT&CK & D3FEND)]"}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"Tactic ID", "Technique ID", "Technique Name", "SIEM Detection Rule", "D3FEND Counter"}); err != nil {
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
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"[CHAIN OF CUSTODY & LAW NO. 5651 TIMESTAMP EVIDENCE]"}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"Evidence ID", "Artifact Type", "Source Host", "Acquisition Time (UTC)", "SHA-256 Digest", "TSA Token (.zd)", "Custodian"}); err != nil {
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
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"[ROOT CAUSE ANALYSIS & CORRECTIVE RECOMMENDATIONS]"}); err != nil {
			return err
		}
		if report.RootCause != "" {
			_ = csvWriter.Write([]string{"Root Cause Finding", report.RootCause})
		}
		for i, plan := range report.RemediationPlan {
			_ = csvWriter.Write([]string{fmt.Sprintf("Remediation Step %d", i+1), plan})
		}
	}

	// 6. Extended Compliance Sampling
	if report.ComplianceData != nil && len(report.ComplianceData.SampledEvents) > 0 {
		if err := csvWriter.Write([]string{""}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"[STATUTORY COMPLIANCE PRIVILEGED ACCESS LOG SAMPLING]"}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"Timestamp (UTC)", "Principal/User", "Target System", "Action Executed", "Justification"}); err != nil {
			return err
		}
		for _, evt := range report.ComplianceData.SampledEvents {
			_ = csvWriter.Write([]string{evt.Timestamp, evt.Principal, evt.TargetHost, evt.Action, evt.Justification})
		}
	}

	return csvWriter.Error()
}
