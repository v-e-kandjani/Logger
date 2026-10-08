package models

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// LogEvent represents an enriched, parsed syslog message for analytical storage
type LogEvent struct {
	InternalID         uuid.UUID `json:"internal_id"`
	EventTimestamp     time.Time `json:"event_timestamp"`
	ReceivedAt         time.Time `json:"received_at"`
	SourceIP           net.IP    `json:"source_ip"`
	SourcePort         uint16    `json:"source_port"`
	TransportProtocol  string    `json:"transport_protocol"` // UDP, TCP, TLS
	DeviceID           uuid.UUID `json:"device_id"`
	DeviceName         string    `json:"device_name"`
	DeviceGroup        string    `json:"device_group"`
	Vendor             string    `json:"vendor"`
	Product            string    `json:"product"`
	FacilityCode       uint8     `json:"facility_code"`
	Facility           string    `json:"facility"`
	SeverityCode       uint8     `json:"severity_code"`
	Severity           string    `json:"severity"`
	Hostname           string    `json:"hostname"`
	ApplicationName    string    `json:"application_name"`
	ProcessID          string    `json:"process_id"`
	MessageID          string    `json:"message_id"`
	StructuredData     string    `json:"structured_data"`
	Message            string    `json:"message"`
	RawMessage         string    `json:"raw_message"`
	CollectorNode      string    `json:"collector_node"`
	ParserStatus       string    `json:"parser_status"` // SUCCESS, PARTIAL, FAILED
	IngestionTimestamp time.Time `json:"ingestion_timestamp"`
}

// Device represents a registered syslog sending asset
type Device struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	IPAddress         string    `json:"ip_address"`
	Hostname          string    `json:"hostname"`
	Description       string    `json:"description"`
	Vendor            string    `json:"vendor"`
	DeviceType        string    `json:"device_type"`
	GroupID           *uuid.UUID `json:"group_id,omitempty"`
	GroupName         string    `json:"group_name,omitempty"`
	SiteLocation      string    `json:"site_location"`
	ExpectedProtocol  string    `json:"expected_protocol"` // UDP, TCP, TLS, ANY
	ExpectedPort      int       `json:"expected_port"`
	IsEnabled         bool      `json:"is_enabled"`
	RetentionDays     int       `json:"retention_days"`
	TimestampPolicy   string    `json:"timestamp_policy"` // HOURLY, DAILY, NONE
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	Tags              []string  `json:"tags"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	SyslogStatus      string    `json:"syslog_status"` // HEALTHY, WARNING, OFFLINE, NEVER_SEEN
}

// DeviceGroup groups devices for management, search, and policy enforcement
type DeviceGroup struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	DeviceCount int       `json:"device_count"`
	CreatedAt   time.Time `json:"created_at"`
}

// UnregisteredSource records an unknown host transmitting syslog messages
type UnregisteredSource struct {
	IPAddress        string    `json:"ip_address"`
	Hostname         string    `json:"hostname,omitempty"`
	DetectedVendor   string    `json:"detected_vendor,omitempty"`
	DetectedType     string    `json:"detected_type,omitempty"`
	Confidence       string    `json:"confidence,omitempty"`
	FirstSeenAt      time.Time `json:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at"`
	PacketCount      int64     `json:"packet_count"`
	LastRawSample    string    `json:"last_raw_sample"`
	DetectedFacility string    `json:"detected_facility"`
	DetectedSeverity string    `json:"detected_severity"`
}

// LogArchive records an immutable compressed time-slice of logs with cryptographic hashes
type LogArchive struct {
	ID                      uuid.UUID  `json:"id"`
	ArchiveName             string     `json:"archive_name"`
	StartTimestamp          time.Time  `json:"start_timestamp"`
	EndTimestamp            time.Time  `json:"end_timestamp"`
	RecordCount             int64      `json:"record_count"`
	ArchivePath             string     `json:"archive_path"`
	ArchiveSize             int64      `json:"archive_size"`
	HashAlgorithm           string     `json:"hash_algorithm"`
	HashValue               string     `json:"hash_value"`
	TimestampStatus         string     `json:"timestamp_status"` // PENDING, IN_PROGRESS, STAMPED, FAILED, VERIFIED
	TimestampRequestTime    *time.Time `json:"timestamp_request_time,omitempty"`
	TimestampCompletionTime *time.Time `json:"timestamp_completion_time,omitempty"`
	TimestampEvidencePath   string     `json:"timestamp_evidence_path,omitempty"`
	RetryCount              int        `json:"retry_count"`
	LastError               string     `json:"last_error,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
}

// AuditLog tracks administrative actions
type AuditLog struct {
	ID        uuid.UUID              `json:"id"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	Username  string                 `json:"username"`
	SourceIP  string                 `json:"source_ip"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Result    string                 `json:"result"` // SUCCESS, FAILED, DENIED
	Details   map[string]interface{} `json:"details,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// User represents an administrative or security operator
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	FullName     string    `json:"full_name"`
	Email        string    `json:"email"`
	Role         string    `json:"role"` // Super Administrator, Administrator, Security Analyst, Read Only, Auditor
	IsEnabled    bool      `json:"is_enabled"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
