package models

import (
	"time"
)

// TIFeed represents an external threat intelligence feed configuration (Phase Q)
type TIFeed struct {
	ID                  int        `json:"id"`
	Name                string     `json:"name"`
	FeedType            string     `json:"feed_type"` // 'plain_list', 'csv', 'json', 'cisa_kev', 'abuseipdb'
	URL                 string     `json:"url"`
	APIKey              string     `json:"api_key,omitempty"`
	PollIntervalMinutes int        `json:"poll_interval_minutes"`
	IsEnabled           bool       `json:"is_enabled"`
	IndicatorType       string     `json:"indicator_type"` // 'ip', 'domain', 'sha256', 'url', 'mixed'
	ThreatCategory      string     `json:"threat_category"`
	DefaultConfidence   int        `json:"default_confidence"`
	LastSyncAt          *time.Time `json:"last_sync_at,omitempty"`
	LastStatus          string     `json:"last_status"` // 'IDLE', 'SYNCING', 'SUCCESS', 'FAILED'
	IndicatorCount      int        `json:"indicator_count"`
	ErrorMessage        string     `json:"error_message,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// TIIndicator represents an individual threat indicator extracted from feeds or added manually (Phase Q)
type TIIndicator struct {
	ID             int64      `json:"id"`
	FeedID         *int       `json:"feed_id,omitempty"`
	FeedName       string     `json:"feed_name,omitempty"`
	IndicatorType  string     `json:"indicator_type"` // 'ip', 'domain', 'sha256', 'url'
	IndicatorValue string     `json:"indicator_value"`
	ThreatCategory string     `json:"threat_category"`
	Severity       string     `json:"severity"` // 'low', 'medium', 'high', 'critical'
	Confidence     int        `json:"confidence"`
	Description    string     `json:"description,omitempty"`
	Source         string     `json:"source"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	IsActive       bool       `json:"is_active"`
}

// TIMatch represents a detected match between an incoming event/telemetry and an active threat indicator (Phase Q)
type TIMatch struct {
	ID              int64     `json:"id"`
	TenantSlug      string    `json:"tenant_slug"`
	IndicatorID     *int64    `json:"indicator_id,omitempty"`
	IndicatorType   string    `json:"indicator_type"`
	IndicatorValue  string    `json:"indicator_value"`
	ThreatCategory  string    `json:"threat_category"`
	Severity        string    `json:"severity"`
	SourceType      string    `json:"source_type"` // 'syslog', 'agent_network', 'agent_process', 'agent_fim'
	SourceIP        string    `json:"source_ip,omitempty"`
	DestinationIP   string    `json:"destination_ip,omitempty"`
	Domain          string    `json:"domain,omitempty"`
	FileHash        string    `json:"file_hash,omitempty"`
	DeviceName      string    `json:"device_name,omitempty"`
	HostIdentifier  string    `json:"host_identifier,omitempty"`
	MatchedAt       time.Time `json:"matched_at"`
	SIEMAlertID     string    `json:"siem_alert_id,omitempty"`
	RawEventSummary string    `json:"raw_event_summary,omitempty"`
	ActionTaken     string    `json:"action_taken"` // 'ALERT', 'BLOCKED', 'QUARANTINED'
}

// TIStats represents executive KPIs and distribution metrics for Threat Intelligence (Phase Q)
type TIStats struct {
	TotalIndicators   int            `json:"total_indicators"`
	ActiveFeeds       int            `json:"active_feeds"`
	MatchesToday      int            `json:"matches_today"`
	HighCriticalIOCs  int            `json:"high_critical_iocs"`
	IndicatorsByType  map[string]int `json:"indicators_by_type"`
	MatchesBySeverity map[string]int `json:"matches_by_severity"`
}

// IndicatorHit represents an in-memory fast cache match hit
type IndicatorHit struct {
	IndicatorID    int64
	IndicatorType  string
	IndicatorValue string
	ThreatCategory string
	Severity       string
	Confidence     int
	Source         string
	Description    string
}
