package models

import (
	"os"
	"time"
)

// TenantBranding defines dynamic logo lookup and fallback metadata.
type TenantBranding struct {
	TenantSlug      string `json:"tenant_slug"`
	TenantName      string `json:"tenant_name"`
	CustomLogoPath  string `json:"custom_logo_path,omitempty"`
	DefaultLogoPath string `json:"default_logo_path,omitempty"`
}

// ResolvedBranding contains the resolved path and fallback flag.
type ResolvedBranding struct {
	LogoPath string `json:"logo_path"`
	IsCustom bool   `json:"is_custom"`
}

// ResolveLogo checks disk availability for custom logo, falling back to LogSeal default.
func (b *TenantBranding) ResolveLogo() ResolvedBranding {
	if b.CustomLogoPath != "" {
		if _, err := os.Stat(b.CustomLogoPath); err == nil {
			return ResolvedBranding{LogoPath: b.CustomLogoPath, IsCustom: true}
		}
	}
	// Fallback candidates for LogSeal application logo
	fallbackCandidates := []string{
		"/opt/syslog-platform/web/static/img/logseal_logo.png",
		"/opt/syslog-platform/web/static/images/logo.png",
		"web/static/img/logseal_logo.png",
		"web/static/images/logo.png",
	}
	for _, cand := range fallbackCandidates {
		if _, err := os.Stat(cand); err == nil {
			return ResolvedBranding{LogoPath: cand, IsCustom: false}
		}
	}
	if b.DefaultLogoPath != "" {
		return ResolvedBranding{LogoPath: b.DefaultLogoPath, IsCustom: false}
	}
	return ResolvedBranding{LogoPath: "web/static/img/logseal_logo.png", IsCustom: false}
}

// ThreatMapping maps SIEM alerts to MITRE ATT&CK & D3FEND defensive countermeasures.
type ThreatMapping struct {
	TacticID    string `json:"tactic_id"`    // e.g., "TA0001" (Initial Access)
	TechniqueID string `json:"technique_id"` // e.g., "T1110.003" (Password Spraying)
	Name        string `json:"name"`         // e.g., "Password Spraying"
	RuleName    string `json:"rule_name"`    // e.g., "AUTH-002: Password Spray Detected"
	D3FENDID    string `json:"d3fend_id"`    // e.g., "D3-IT" (Inbound Traffic Filtering)
}

// IndicatorOfCompromise represents actionable intelligence extracted from logs.
type IndicatorOfCompromise struct {
	Type        string `json:"type"`         // IPv4, SHA-256, FQDN, URL
	Value       string `json:"value"`
	Confidence  string `json:"confidence"`   // High, Medium, Low
	Reputation  string `json:"reputation"`   // e.g., "AbuseIPDB 100%", "FortiGuard IPS"
	ActionTaken string `json:"action_taken"` // e.g., "Blocked via Edge Firewall"
}

// TimelineEntry captures chronological event steps with microsecond accuracy.
type TimelineEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	Description string    `json:"description"`
	Actor       string    `json:"actor"`
}

// ForensicArtifact aligns with LogSeal Law No. 5651 and chain of custody standards.
type ForensicArtifact struct {
	EvidenceID    string    `json:"evidence_id"`     // e.g., "EV-2026-001"
	ArtifactType  string    `json:"artifact_type"`   // Raw Log Slice, Memory Dump, PCAP
	SourceHost    string    `json:"source_host"`     // Device IP or Hostname
	AcquisitionAt time.Time `json:"acquisition_at"`
	SHA256Hash    string    `json:"sha256_hash"`     // Cryptographic proof
	TSATokenZD    string    `json:"tsa_token_zd"`    // TÜBİTAK KamuSM .zd Token or Internal Hash
	Custodian     string    `json:"custodian"`       // Analyst or LogSeal Daemon
}

// ComprehensiveIncidentReport is the complete dataset exported across all formats.
type ComprehensiveIncidentReport struct {
	ReportID       string         `json:"report_id"`
	ReportType     string         `json:"report_type"` // incident_rca, exec_posture, shift_handover, compliance_audit, vuln_exposure
	Language       string         `json:"language"`    // "tr" or "en"
	Title          string         `json:"title"`
	Classification string         `json:"classification"` // e.g., "TLP:AMBER", "CONFIDENTIAL", "LAW 5651 LEGAL EVIDENCE"
	StartTime      time.Time      `json:"start_time"`
	EndTime        time.Time      `json:"end_time"`
	GeneratedAt    time.Time      `json:"generated_at"`
	Tenant         TenantBranding `json:"tenant"`

	// Operational SLAs
	ExecutiveSummary string `json:"executive_summary"`
	MTTDMinutes      int    `json:"mttd_minutes"` // Mean Time to Detect
	MTTAMinutes      int    `json:"mtta_minutes"` // Mean Time to Acknowledge
	MTTRMinutes      int    `json:"mttr_minutes"` // Mean Time to Remediate
	TotalEvents      int64  `json:"total_events"`
	TotalAlerts      int    `json:"total_alerts"`
	CriticalAlerts   int    `json:"critical_alerts"`

	RegulatoryImpact struct {
		Law5651Relevant bool     `json:"law5651_relevant"` // Turkish Law No. 5651 Log Compliance
		BreachConfirmed bool     `json:"breach_confirmed"` // GDPR / KVKK / PCI-DSS / HIPAA
		Regulations     []string `json:"regulations"`      // ["KVKK", "Law 5651", "PCI-DSS 4.0"]
		Disclosed       bool     `json:"disclosed"`
	} `json:"regulatory_impact"`

	// Forensic & Tactical Correlation
	ThreatMappings []ThreatMapping         `json:"threat_mappings"`
	IOCs           []IndicatorOfCompromise `json:"iocs"`
	Timeline       []TimelineEntry         `json:"timeline"`
	ChainOfCustody []ForensicArtifact      `json:"chain_of_custody"`

	// Root Cause & Corrective Action
	RootCause       string   `json:"root_cause"`
	RemediationPlan []string `json:"remediation_plan"`

	// Template-Specific Extended Sub-Objects
	ExecData       *ExecReportData          `json:"exec_data,omitempty"`
	ForensicData   *ForensicReportData      `json:"forensic_data,omitempty"`
	HandoverData   *HandoverReportData      `json:"handover_data,omitempty"`
	ComplianceData *ComplianceReportData    `json:"compliance_data,omitempty"`
	VulnData       *VulnerabilityReportData `json:"vuln_data,omitempty"`
}

// 1. Executive Weekly Threat Landscape & Posture Report
type ExecReportData struct {
	TenantName       string   `json:"tenant_name"`
	ReportWindow     string   `json:"report_window"`
	OverallPosture   string   `json:"overall_posture"` // "STABLE", "ELEVATED", "CRITICAL"
	TotalAlerts      int      `json:"total_alerts"`
	TruePositives    int      `json:"true_positives"`
	MTTDMinutes      float64  `json:"mttd_minutes"`
	MTTRMinutes      float64  `json:"mttr_minutes"`
	PreventionRatio  string   `json:"prevention_ratio"`
	TopAttackedHosts []string `json:"top_attacked_hosts"`
	TopThreatActors  []string `json:"top_threat_actors"`
	KeyMilestones    []string `json:"key_milestones"`
	ResourceNeeds    []string `json:"resource_needs"`
}

// 2. Single Critical Incident Forensics & Root Cause Analysis (RCA)
type ForensicReportData struct {
	TenantName        string           `json:"tenant_name"`
	IncidentID        string           `json:"incident_id"`
	Severity          string           `json:"severity"` // "P1 - CRITICAL"
	DetectionTime     string           `json:"detection_time"`
	ResolutionTime    string           `json:"resolution_time"`
	LeadAnalyst       string           `json:"lead_analyst"`
	Summary           string           `json:"summary"`
	AffectedAssets    []string         `json:"affected_assets"`
	AffectedUsers     []string         `json:"affected_users"`
	KillChainSteps    []KillChainEntry `json:"kill_chain_steps"`
	EvidenceArtifacts []string         `json:"evidence_artifacts"`
	RootCause         string           `json:"root_cause"`
	ActionItems       []ActionItem     `json:"action_items"`
}

type KillChainEntry struct {
	Phase     string `json:"phase"` // e.g., "Initial Access", "Lateral Movement"
	Timestamp string `json:"timestamp"`
	Evidence  string `json:"evidence"`
}

type ActionItem struct {
	Action   string `json:"action"`
	Owner    string `json:"owner"`
	Deadline string `json:"deadline"`
}

// 3. SOC Operational & Shift Handover Report
type HandoverReportData struct {
	TenantName       string            `json:"tenant_name"`
	ShiftID          string            `json:"shift_id"` // "Shift Alpha (00:00 - 08:00 UTC)"
	DepartingAnalyst string            `json:"departing_analyst"`
	IncomingAnalyst  string            `json:"incoming_analyst"`
	ActiveIncidents  []ShiftIncident   `json:"active_incidents"`
	CollectorHealth  []CollectorStatus `json:"collector_health"`
	TuningNotes      []string          `json:"tuning_notes"`
}

type ShiftIncident struct {
	TicketID string `json:"ticket_id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	NextStep string `json:"next_step"`
}

type CollectorStatus struct {
	SensorName string `json:"sensor_name"`
	Status     string `json:"status"` // "HEALTHY", "LAGGING", "OFFLINE"
	EventRate  int    `json:"event_rate"` // EPS
}

// 4. Regulatory Compliance & Audit Log Inspection Report (PCI-DSS / HIPAA / SOC2 / Law 5651)
type ComplianceReportData struct {
	TenantName       string            `json:"tenant_name"`
	Framework        string            `json:"framework"` // "Law No. 5651 / 5070", "PCI-DSS v4.0", "ISO/IEC 27001", "KVKK / GDPR"
	AuditPeriod      string            `json:"audit_period"`
	PrivAccessEvents int               `json:"priv_access_events"`
	FailedAuthRatio  string            `json:"failed_auth_ratio"`
	LogIntegrityPass bool              `json:"log_integrity_pass"`
	SampledEvents    []ComplianceEvent `json:"sampled_events"`
}

type ComplianceEvent struct {
	Timestamp     string `json:"timestamp"`
	Principal     string `json:"principal"`
	TargetHost    string `json:"target_host"`
	Action        string `json:"action"`
	Justification string `json:"justification"`
}

// 5. Vulnerability & Attack Surface Exposure Report
type VulnerabilityReportData struct {
	TenantName       string          `json:"tenant_name"`
	ReportWindow     string          `json:"report_window"`
	HighCriticalCVEs int             `json:"high_critical_cves"`
	ExploitedInWild  int             `json:"exploited_in_wild"`
	TopVulnerableIPs []VulnAssetEntry `json:"top_vulnerable_ips"`
}

type VulnAssetEntry struct {
	HostIP        string  `json:"host_ip"`
	Hostname      string  `json:"hostname"`
	CVE           string  `json:"cve"`
	CVSS          float64 `json:"cvss"`
	ActiveAttacks int     `json:"active_attacks"` // How many correlation alerts triggered on this CVE
}

// ReportTypeInfo describes an available report template
type ReportTypeInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameTR      string   `json:"name_tr"`
	Description string   `json:"description"`
	Audience    string   `json:"audience"`
	Cadence     string   `json:"cadence"`
	Formats     []string `json:"formats"`
}

// ReportExportRequest carries user filter arguments for generation
type ReportExportRequest struct {
	Type           string `json:"type"`   // exec_posture, incident_rca, shift_handover, compliance_audit, vuln_exposure
	Format         string `json:"format"` // pdf, csv, docx, json, txt
	Timeframe      string `json:"timeframe"` // 24h, 7d, 30d, custom
	StartTime      string `json:"start_time,omitempty"`
	EndTime        string `json:"end_time,omitempty"`
	Classification string `json:"classification,omitempty"`
	IncidentID     string `json:"incident_id,omitempty"`
	LeadAnalyst    string `json:"lead_analyst,omitempty"`
	ShiftID        string `json:"shift_id,omitempty"`
	IncomingUser   string `json:"incoming_user,omitempty"`
	Framework      string `json:"framework,omitempty"`
	TenantSlug     string `json:"tenant_slug,omitempty"`
}

// GeneratedReportSummary represents a report logged in history
type GeneratedReportSummary struct {
	ID             string    `json:"id"`
	ReportType     string    `json:"report_type"`
	Title          string    `json:"title"`
	TenantSlug     string    `json:"tenant_slug"`
	Classification string    `json:"classification"`
	Format         string    `json:"format"`
	FileSizeBytes  int64     `json:"file_size_bytes"`
	GeneratedAt    time.Time `json:"generated_at"`
	GeneratedBy    string    `json:"generated_by"`
}
