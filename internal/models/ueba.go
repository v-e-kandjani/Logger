package models

import (
	"time"

	"github.com/google/uuid"
)

// UEBAUserProfile represents the learned behavioral baseline for an identity
type UEBAUserProfile struct {
	ID                 int64      `json:"id"`
	TenantSlug         string     `json:"tenant_slug"`
	Username           string     `json:"username"`
	PrimaryWorkstation string     `json:"primary_workstation"`
	TypicalLoginWindow string     `json:"typical_login_window"` // e.g. "08:00-19:00"
	UsualCIDRs         []string   `json:"usual_cidrs"`
	BaselineDailyEPS   float64    `json:"baseline_daily_eps"`
	TotalEvents        int64      `json:"total_events"`
	HourlyHistogram    [24]int    `json:"hourly_histogram"`
	LastSeenIP         string     `json:"last_seen_ip"`
	LastSeenCountry    string     `json:"last_seen_country"`
	LastSeenCity       string     `json:"last_seen_city"`
	LastSeenLatitude   float64    `json:"last_seen_latitude"`
	LastSeenLongitude  float64    `json:"last_seen_longitude"`
	LastSeenAt         *time.Time `json:"last_seen_at,omitempty"`
	FirstSeenAt        time.Time  `json:"first_seen_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// UEBARiskScore represents the dynamic calculated risk score for a user
type UEBARiskScore struct {
	ID              int64     `json:"id"`
	TenantSlug      string    `json:"tenant_slug"`
	Username        string    `json:"username"`
	RiskScore       int       `json:"risk_score"` // 0 to 100
	RiskLevel       string    `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
	RiskFactors     []string  `json:"risk_factors"`
	Trend           string    `json:"trend"` // INCREASING, STABLE, DECREASING
	ActiveAnomalies int       `json:"active_anomalies"`
	LastEvaluatedAt time.Time `json:"last_evaluated_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// UEBAAnomaly represents a specific detected behavioral deviation
type UEBAAnomaly struct {
	ID          uuid.UUID              `json:"id"`
	TenantSlug  string                 `json:"tenant_slug"`
	Username    string                 `json:"username"`
	AnomalyType string                 `json:"anomaly_type"` // IMPOSSIBLE_TRAVEL, OFF_HOURS, PRIVILEGE_BURST, DORMANT_ACCOUNT, BRUTE_FORCE_BURST
	Severity    string                 `json:"severity"`     // LOW, MEDIUM, HIGH, CRITICAL
	RiskPoints  int                    `json:"risk_points"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	SourceIP    string                 `json:"source_ip"`
	DeviceName  string                 `json:"device_name"`
	Evidence    map[string]interface{} `json:"evidence"`
	DetectedAt  time.Time              `json:"detected_at"`
}

// UEBAStats provides aggregated telemetry for UEBA operations
type UEBAStats struct {
	MonitoredUsers  int `json:"monitored_users"`
	HighRiskUsers   int `json:"high_risk_users"`
	AnomaliesToday  int `json:"anomalies_today"`
	AverageRiskScore int `json:"average_risk_score"`
}

// UEBARiskLeaderboardItem represents a top risky identity for operations display
type UEBARiskLeaderboardItem struct {
	Username        string    `json:"username"`
	RiskScore       int       `json:"risk_score"`
	RiskLevel       string    `json:"risk_level"`
	Trend           string    `json:"trend"`
	ActiveAnomalies int       `json:"active_anomalies"`
	TopAnomaly      string    `json:"top_anomaly"`
	PrimaryHost     string    `json:"primary_host"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}
