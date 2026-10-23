package models

import (
	"time"

	"github.com/google/uuid"
)

// FIMEvent represents a detected file or registry integrity deviation
type FIMEvent struct {
	ID             uuid.UUID `json:"id"`
	TenantSlug     string    `json:"tenant_slug"`
	AgentID        uuid.UUID `json:"agent_id"`
	AgentHostname  string    `json:"agent_hostname,omitempty"`
	AgentIP        string    `json:"agent_ip,omitempty"`
	AgentOS        string    `json:"agent_os,omitempty"`
	EventType      string    `json:"event_type"`  // created, modified, deleted, permissions
	TargetType     string    `json:"target_type"` // file, registry
	TargetPath     string    `json:"target_path"`
	PreviousHash   string    `json:"previous_hash,omitempty"`
	CurrentHash    string    `json:"current_hash,omitempty"`
	FileSizeBytes  int64     `json:"file_size_bytes"`
	Permissions    string    `json:"permissions,omitempty"`
	ProcessName    string    `json:"process_name,omitempty"`
	ProcessPID     int       `json:"process_pid,omitempty"`
	UserName       string    `json:"user_name,omitempty"`
	Severity       string    `json:"severity"`        // CRITICAL, HIGH, MEDIUM, LOW
	MITRETactic    string    `json:"mitre_tactic"`    // Persistence, Privilege Escalation, Defense Evasion
	MITRETechnique string    `json:"mitre_technique"` // T1547.001, T1053, T1565.001
	Details        string    `json:"details,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// FIMBaselineItem stores the cryptographically hashed baseline of a file or registry key
type FIMBaselineItem struct {
	ID            uuid.UUID `json:"id"`
	TenantSlug    string    `json:"tenant_slug"`
	AgentID       uuid.UUID `json:"agent_id"`
	TargetPath    string    `json:"target_path"`
	TargetType    string    `json:"target_type"` // file, registry
	SHA256Hash    string    `json:"sha256_hash"`
	FileSizeBytes int64     `json:"file_size_bytes"`
	Permissions   string    `json:"permissions,omitempty"`
	LastChecked   time.Time `json:"last_checked"`
}

// FIMSummary represents high-level metrics for the FIM dashboard
type FIMSummary struct {
	TotalEvents         int        `json:"total_events"`
	CriticalDeviations  int        `json:"critical_deviations"`
	HighDeviations      int        `json:"high_deviations"`
	MonitoredPathsCount int        `json:"monitored_paths_count"`
	ImpactedAgentsCount int        `json:"impacted_agents_count"`
	RecentEvents        []FIMEvent `json:"recent_events"`
}

// AgentFIMSubmission is sent by native agents containing batched integrity deviation events
type AgentFIMSubmission struct {
	AgentUUID     string            `json:"agent_uuid"`
	Hostname      string            `json:"hostname"`
	Events        []FIMEvent        `json:"events"`
	BaselineItems []FIMBaselineItem `json:"baseline_items,omitempty"`
}
