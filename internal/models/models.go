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
	Tenant             string    `json:"tenant"` // owning tenant slug ("default" = root)
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
	TenantSlug        string    `json:"tenant_slug"`   // owning tenant ("default" = root)
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
	TenantSlug       string    `json:"tenant_slug"`
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
	Tenant                  string     `json:"tenant"` // Multi-tenant isolation: tenant slug (e.g. "default", "1ware")
	CreatedAt               time.Time  `json:"created_at"`
}

// ArchiveJob represents an asynchronous sealing task in the deterministic state machine
type ArchiveJob struct {
	ID             uuid.UUID  `json:"id"`
	TenantSlug     string     `json:"tenant_slug"`
	RequestType    string     `json:"request_type"` // HOURLY_SCHEDULED, MANUAL_PERIOD
	PeriodStart    time.Time  `json:"period_start"`
	PeriodEnd      time.Time  `json:"period_end"`
	TimeBasis      string     `json:"time_basis"` // receipt_time, event_time
	IdempotencyKey string     `json:"idempotency_key"`
	Requester      string     `json:"requester"`
	Reason         string     `json:"reason,omitempty"`
	LeaseUntil     *time.Time `json:"lease_until,omitempty"`
	Attempts       int        `json:"attempts"`
	State          string     `json:"state"` // QUEUED, BUILDING, SEALED, TSA_PENDING, VERIFIED, COMMITTED, FAILED
	ErrorMessage   string     `json:"error_message,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ArchiveManifest records exact canonical manifest bytes and SHA-256 payload digests
type ArchiveManifest struct {
	ID                   uuid.UUID `json:"id"`
	ArchiveID            uuid.UUID `json:"archive_id"`
	ManifestContent      []byte    `json:"manifest_content,omitempty"`
	ManifestSHA256       string    `json:"manifest_sha256"`
	PayloadSHA256        string    `json:"payload_sha256"`
	SchemaVersion        string    `json:"schema_version"`
	PriorManifestSHA256  string    `json:"prior_manifest_sha256,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// ArchiveTimestamp records verified RFC 3161 / TÜBİTAK Zamane KS evidence tokens
type ArchiveTimestamp struct {
	ID                  uuid.UUID  `json:"id"`
	ManifestID          uuid.UUID  `json:"manifest_id"`
	RequestID           string     `json:"request_id"`
	TokenBytes          []byte     `json:"token_bytes,omitempty"`
	TSAIdentity         string     `json:"tsa_identity"`
	TSAPolicy           string     `json:"tsa_policy"`
	TSASerial           string     `json:"tsa_serial"`
	TSATime             *time.Time `json:"tsa_time,omitempty"`
	ImprintAlgorithm    string     `json:"imprint_algorithm"`
	SignatureAlgorithm  string     `json:"signature_algorithm"`
	VerificationOutcome string     `json:"verification_outcome"` // VERIFIED, FAILED, PENDING
	VerificationDetails string     `json:"verification_details,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// ArchiveAudit tracks append-only evidence preservation, verification, and retrieval events
type ArchiveAudit struct {
	ID         uuid.UUID              `json:"id"`
	ArchiveID  *uuid.UUID             `json:"archive_id,omitempty"`
	TenantSlug string                 `json:"tenant_slug"`
	Action     string                 `json:"action"` // SEAL_STARTED, SEAL_COMPLETED, TSA_STAMPED, VERIFIED, EXPORTED, LEGAL_HOLD_APPLIED
	Operator   string                 `json:"operator"`
	Details    map[string]interface{} `json:"details,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

// AuditLog tracks administrative actions
type AuditLog struct {
	ID         uuid.UUID              `json:"id"`
	UserID     *uuid.UUID             `json:"user_id,omitempty"`
	Username   string                 `json:"username"`
	SourceIP   string                 `json:"source_ip"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	Result     string                 `json:"result"` // SUCCESS, FAILED, DENIED
	Details    map[string]interface{} `json:"details,omitempty"`
	TenantSlug string                 `json:"tenant_slug"`
	CreatedAt  time.Time              `json:"created_at"`
}

// User represents an administrative or security operator
type User struct {
	ID               uuid.UUID  `json:"id"`
	Username         string     `json:"username"`
	PasswordHash     string     `json:"-"`
	FullName         string     `json:"full_name"`
	Email            string     `json:"email"`
	Role             string     `json:"role"` // Super Administrator, Administrator, Security Analyst, Read Only, Auditor
	IsEnabled        bool       `json:"is_enabled"`
	AuthSource       string     `json:"auth_source"` // "local" or "ad"
	MFAEnabled       bool       `json:"mfa_enabled"`
	MFASecret        string     `json:"-"`
	MFARecoveryCodes []string   `json:"-"`
	MFAEnrolledAt    *time.Time `json:"mfa_enrolled_at,omitempty"`
	MFAProvider      string     `json:"mfa_provider"` // "totp", "ms_authenticator", "google_authenticator", "watchguard_authpoint", "forti_authenticator"
	TenantSlug       string     `json:"tenant_slug"` // "default" or tenant slug
	IsTenantAdmin    bool       `json:"is_tenant_admin"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Tenant represents an enterprise customer organization (multi-tenant MSSP)
type Tenant struct {
	ID            uuid.UUID `json:"id"`
	Slug          string    `json:"slug"` // "acme", "fintech"
	Name          string    `json:"name"` // "Acme Corporation"
	Description   string    `json:"description"`
	AdminName     string    `json:"admin_name"`
	AdminEmail    string    `json:"admin_email"`
	AdminUsername string    `json:"admin_username"`
	Status        string    `json:"status"`        // "active", "suspended", "pending_activation"
	IngestPolicy  string    `json:"ingest_policy"` // "permissive" (auto-discovery), "strict" (whitelist only)
	MaxNodes      int       `json:"max_nodes"`
	MaxEPS        int       `json:"max_eps"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// EdgeNode represents a remote proxy forwarder node
type EdgeNode struct {
	ID               uuid.UUID              `json:"id"`
	Name             string                 `json:"name"`
	Token            string                 `json:"token"`
	TenantName       string                 `json:"tenant_name"`
	SyncInterval     string                 `json:"sync_interval"` // "online", "every 60 second", "every 5 min", "every 15 min", "every 30 min", "every hour"
	LastSeenAt       *time.Time             `json:"last_seen_at,omitempty"`
	LastIP           string                 `json:"last_ip"`
	Version          string                 `json:"version"`
	Status           string                 `json:"status"` // "online", "offline", "pending"
	LogsForwarded    int64                  `json:"logs_forwarded"`
	AdminName        string                 `json:"admin_name"`
	AdminEmail       string                 `json:"admin_email"`
	AdminUsername    string                 `json:"admin_username"`
	AdminInitialPass string                 `json:"admin_initial_pass,omitempty"`
	ActivationStatus string                 `json:"activation_status"` // "active", "pending_activation", "suspended"
	TokenHash        string                 `json:"token_hash,omitempty"`
	TokenPrefix      string                 `json:"token_prefix,omitempty"`
	KeyExpiresAt     *time.Time             `json:"key_expires_at,omitempty"`
	AllowedCIDRs     string                 `json:"allowed_cidrs"`
	LastKeyRotatedAt *time.Time             `json:"last_key_rotated_at,omitempty"`
	LDAPConfig       map[string]interface{} `json:"ldap_config,omitempty"`
	MinSpecs         map[string]string      `json:"min_specs,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// SupportBundle represents an archived diagnostic support bundle in tar.gz format
type SupportBundle struct {
	ID               string    `json:"id"`
	Filename         string    `json:"filename"`
	FilePath         string    `json:"file_path"`
	FileSize         int64     `json:"file_size"`
	SHA256           string    `json:"sha256"`
	AccessPasscode   string    `json:"access_passcode"`
	AccessToken      string    `json:"access_token"`
	RequestedBy      string    `json:"requested_by"`
	TenantSlug       string    `json:"tenant_slug"`
	IssueDescription string    `json:"issue_description"`
	ContactEmail     string    `json:"contact_email"`
	DownloadCount    int       `json:"download_count"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}
