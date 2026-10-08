package models

import (
	"time"

	"github.com/google/uuid"
)

// NormalizedEvent represents a vendor-neutral standardized security event
type NormalizedEvent struct {
	EventID           uuid.UUID         `json:"event_id"`
	Timestamp         time.Time         `json:"timestamp"`
	ReceivedAt        time.Time         `json:"received_at"`
	SourceIP          string            `json:"source_ip"`
	SourcePort        uint16            `json:"source_port"`
	DestinationIP     string            `json:"destination_ip"`
	DestinationPort   uint16            `json:"destination_port"`
	DeviceID          uuid.UUID         `json:"device_id"`
	DeviceName        string            `json:"device_name"`
	Vendor            string            `json:"vendor"`
	Product           string            `json:"product"`
	EventCategory     string            `json:"event_category"` // authentication, network, threat, system, configuration
	EventAction       string            `json:"event_action"`   // login-failed, login-success, connection-denied, port-scan, privilege-escalation, malware-blocked, account-created
	EventOutcome      string            `json:"event_outcome"`  // failure, success, blocked, allowed
	Username          string            `json:"username"`
	Severity          string            `json:"severity"`       // CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	RiskScore         int               `json:"risk_score"`     // 0-100
	MitreTactic       string            `json:"mitre_tactic"`   // e.g. Credential Access, Discovery, Lateral Movement
	MitreTechnique    string            `json:"mitre_technique"`// e.g. T1110, T1046, T1548
	Message           string            `json:"message"`
	RawMessage        string            `json:"raw_message"`
	Extra             map[string]string `json:"extra,omitempty"`
}

// SIEMRule defines a security detection and correlation rule
type SIEMRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Severity         string    `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	RiskScore        int       `json:"risk_score"`
	Category         string    `json:"category"` // authentication, privilege, network_admin, perimeter, network, windows, linux, cloud, mail_web, data, defense_evasion, health
	Priority         string    `json:"priority,omitempty"` // P1, P2
	SourceRef        string    `json:"source_ref,omitempty"`
	Threshold        int       `json:"threshold"`
	TimeframeSeconds int       `json:"timeframe_seconds"`
	GroupBy          []string  `json:"group_by"` // source_ip, username, device_name
	MitreTactic      string    `json:"mitre_tactic"`
	MitreTechnique   string    `json:"mitre_technique"`
	IsEnabled        bool      `json:"is_enabled"`
	MatchCategory    string    `json:"match_category"`
	MatchAction      string    `json:"match_action"`
	MatchOutcome     string    `json:"match_outcome"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// SIEMAlert represents a triggered security incident
type SIEMAlert struct {
	ID              uuid.UUID `json:"id"`
	RuleID          string    `json:"rule_id"`
	RuleName        string    `json:"rule_name"`
	Severity        string    `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	RiskScore       int       `json:"risk_score"`
	Category        string    `json:"category"`
	Status          string    `json:"status"` // NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	Username        string    `json:"username"`
	DeviceName      string    `json:"device_name"`
	EventCount      int       `json:"event_count"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	MitreTactic     string    `json:"mitre_tactic"`
	MitreTechnique  string    `json:"mitre_technique"`
	Summary         string    `json:"summary"`
	EvidenceLogs    []string  `json:"evidence_logs"`
	AssignedTo      string    `json:"assigned_to"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SIEMIncidentNote represents an analyst forensic case note
type SIEMIncidentNote struct {
	ID        uuid.UUID `json:"id"`
	AlertID   uuid.UUID `json:"alert_id"`
	Author    string    `json:"author"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// KeyValueCount represents aggregated statistical pairs for top charts
type KeyValueCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// SIEMOverviewStats aggregates SOC security dashboard telemetry
type SIEMOverviewStats struct {
	TotalAlerts             int64           `json:"total_alerts"`
	CriticalAlerts          int64           `json:"critical_alerts"`
	HighAlerts              int64           `json:"high_alerts"`
	MediumAlerts            int64           `json:"medium_alerts"`
	LowAlerts               int64           `json:"low_alerts"`
	ActiveIncidents         int64           `json:"active_incidents"` // NEW + INVESTIGATING
	ResolvedIncidents       int64           `json:"resolved_incidents"`
	MeanRiskScore           int             `json:"mean_risk_score"`
	TopAttackers            []KeyValueCount `json:"top_attackers"`
	TopTargetUsers          []KeyValueCount `json:"top_target_users"`
	TopTargetDevices        []KeyValueCount `json:"top_target_devices"`
	MitreTacticDistribution []KeyValueCount `json:"mitre_tactic_distribution"`
}
