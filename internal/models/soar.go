package models

import (
	"time"

	"github.com/google/uuid"
)

// SOARPlaybook defines an automated or semi-automated incident response playbook
type SOARPlaybook struct {
	ID                uuid.UUID             `json:"id"`
	TenantSlug        string                `json:"tenant_slug"`
	Name              string                `json:"name"`
	Description       string                `json:"description"`
	IsEnabled         bool                  `json:"is_enabled"`
	ExecutionMode     string                `json:"execution_mode"` // "autonomous" or "manual_approval"
	TriggerConditions SOARTriggerConditions `json:"trigger_conditions"`
	Actions           []SOARAction          `json:"actions"`
	CooldownMinutes   int                   `json:"cooldown_minutes"`
	TotalExecutions   int                   `json:"total_executions"`
	LastExecutedAt    *time.Time            `json:"last_executed_at,omitempty"`
	CreatedAt         time.Time             `json:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
}

// SOARTriggerConditions specifies the SIEM alert criteria to activate a playbook
type SOARTriggerConditions struct {
	Severities   []string `json:"severities,omitempty"`    // e.g. ["CRITICAL", "HIGH"]
	RuleIDs      []string `json:"rule_ids,omitempty"`      // e.g. ["AUTH-004", "RANSOMWARE-001"]
	MitreTactics []string `json:"mitre_tactics,omitempty"` // e.g. ["Initial Access", "Execution"]
	MinRiskScore int      `json:"min_risk_score,omitempty"`// e.g. 70
	Categories   []string `json:"categories,omitempty"`    // e.g. ["authentication", "perimeter"]
}

// SOARAction represents a discrete mitigation step within a playbook
type SOARAction struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // "isolate_host", "kill_process", "file_quarantine", "osquery_run", "webhook_notify", "email_notify"
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// SOARPlaybookExecution records a single execution of a SOAR playbook
type SOARPlaybookExecution struct {
	ID              uuid.UUID        `json:"id"`
	PlaybookID      uuid.UUID        `json:"playbook_id"`
	PlaybookName    string           `json:"playbook_name"`
	AlertID         *uuid.UUID       `json:"alert_id,omitempty"`
	TenantSlug      string           `json:"tenant_slug"`
	TriggeredBy     string           `json:"triggered_by"`
	TargetAgentID   *uuid.UUID       `json:"target_agent_id,omitempty"`
	TargetHost      string           `json:"target_host,omitempty"`
	Status          string           `json:"status"` // "PENDING_APPROVAL", "RUNNING", "COMPLETED", "FAILED", "REJECTED", "SKIPPED"
	ExecutionLog    []SOARActionLog  `json:"execution_log"`
	ActionsExecuted int              `json:"actions_executed"`
	ErrorMsg        string           `json:"error_msg,omitempty"`
	ApprovedBy      string           `json:"approved_by,omitempty"`
	ApprovedAt      *time.Time       `json:"approved_at,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	CompletedAt     *time.Time       `json:"completed_at,omitempty"`
}

// SOARActionLog captures individual step telemetry during playbook execution
type SOARActionLog struct {
	ActionType string                 `json:"action_type"`
	Status     string                 `json:"status"` // "success", "failed", "skipped", "dispatched"
	Message    string                 `json:"message"`
	Timestamp  time.Time              `json:"timestamp"`
	DurationMs int64                  `json:"duration_ms"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// SOARStats aggregates playbook telemetry for dashboard cards
type SOARStats struct {
	TotalPlaybooks   int `json:"total_playbooks"`
	ActivePlaybooks  int `json:"active_playbooks"`
	TotalExecutions  int `json:"total_executions"`
	PendingApprovals int `json:"pending_approvals"`
	ContainedHosts   int `json:"contained_hosts"`
}
