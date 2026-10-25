package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// EndpointAgent represents an enrolled endpoint running the LOGGER Agent daemon
type EndpointAgent struct {
	ID                     uuid.UUID       `json:"id"`
	TenantSlug             string          `json:"tenant_slug"`
	AgentUUID              string          `json:"agent_uuid"`
	Hostname               string          `json:"hostname"`
	FQDN                   string          `json:"fqdn"`
	OSType                 string          `json:"os_type"`     // windows, darwin, linux
	OSFamily               string          `json:"os_family"`   // ubuntu, debian, rhel, rocky, etc.
	OSName                 string          `json:"os_name"`     // e.g. "Ubuntu 22.04.4 LTS"
	OSVersion              string          `json:"os_version"`  // e.g. "22.04"
	OSBuild                string          `json:"os_build"`    // e.g. "22631.3007"
	KernelVersion          string          `json:"kernel_version"`
	Architecture           string          `json:"architecture"` // amd64, arm64
	AgentVersion           string          `json:"agent_version"`
	IPAddress              string          `json:"ip_address"`
	MACAddress             string          `json:"mac_address"`
	Status                 string          `json:"status"` // healthy, warning, offline, stale, updating, error, unenrolled
	HealthScore            int             `json:"health_score"`
	PolicyID               *uuid.UUID      `json:"policy_id,omitempty"`
	PolicyName             string          `json:"policy_name,omitempty"`
	PolicyRevision         int             `json:"policy_revision"`
	GroupID                *uuid.UUID      `json:"group_id,omitempty"`
	GroupName              string          `json:"group_name,omitempty"`
	LastSeen               *time.Time      `json:"last_seen,omitempty"`
	LastInventory          *time.Time      `json:"last_inventory,omitempty"`
	LastPatchScan          *time.Time      `json:"last_patch_scan,omitempty"`
	LastVulnScan           *time.Time      `json:"last_vuln_scan,omitempty"`
	ClientCertSerial       string          `json:"client_cert_serial,omitempty"`
	ClientCertFingerprint  string          `json:"client_cert_fingerprint,omitempty"`
	Tags                   []string        `json:"tags"`
	Labels                 json.RawMessage `json:"labels,omitempty"`
	ResourceUsage          json.RawMessage `json:"resource_usage,omitempty"`
	OpenVulnsCount         int             `json:"open_vulns_count"`
	CriticalVulnsCount     int             `json:"critical_vulns_count"`
	MissingPatchesCount    int             `json:"missing_patches_count"`
	RebootRequired         bool            `json:"reboot_required"`
	IsIsolated             bool            `json:"is_isolated"`
	IsolatedAt             *time.Time      `json:"isolated_at,omitempty"`
	IsolationReason        string          `json:"isolation_reason,omitempty"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`
}

// EndpointAgentGroup represents a logical or dynamic cluster of agents
type EndpointAgentGroup struct {
	ID          uuid.UUID  `json:"id"`
	TenantSlug  string     `json:"tenant_slug"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	QueryFilter string     `json:"query_filter"`
	PolicyID    *uuid.UUID `json:"policy_id,omitempty"`
	PolicyName  string     `json:"policy_name,omitempty"`
	AgentCount  int        `json:"agent_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// EndpointEnrollmentToken represents a cryptographic secret allowing agent self-enrollment
type EndpointEnrollmentToken struct {
	ID          uuid.UUID  `json:"id"`
	TenantSlug  string     `json:"tenant_slug"`
	Token       string     `json:"token,omitempty"` // Only exposed at generation time
	TokenHash   string     `json:"token_hash"`
	TokenPrefix string     `json:"token_prefix"`
	Name        string     `json:"name"`
	GroupID     *uuid.UUID `json:"group_id,omitempty"`
	GroupName   string     `json:"group_name,omitempty"`
	MaxUses     int        `json:"max_uses"` // 0 = unlimited
	CurrentUses int        `json:"current_uses"`
	IsOneTime   bool       `json:"is_one_time"`
	AllowedOS   []string   `json:"allowed_os"`
	Labels      json.RawMessage `json:"labels,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
}

// EndpointPolicy defines intervals, throttling, and collection rules for agents
type EndpointPolicy struct {
	ID           uuid.UUID             `json:"id"`
	TenantSlug   string                `json:"tenant_slug"`
	Name         string                `json:"name"`
	Description  string                `json:"description"`
	Revision     int                   `json:"revision"`
	Config       json.RawMessage       `json:"config"`
	PolicyConfig *EndpointPolicyConfig `json:"policy_config,omitempty"`
	IsDefault    bool                  `json:"is_default"`
	AgentCount   int                   `json:"agent_count"`
	CreatedAt    time.Time             `json:"created_at"`
	UpdatedAt    time.Time             `json:"updated_at"`
}

// EndpointPolicyConfig defines the strongly-typed settings stored in Config JSON
type EndpointPolicyConfig struct {
	HeartbeatIntervalSec int      `json:"heartbeat_interval_sec"`
	InventoryIntervalSec int      `json:"inventory_interval_sec"`
	PatchScanIntervalSec int      `json:"patch_scan_interval_sec"`
	VulnScanIntervalSec  int      `json:"vuln_scan_interval_sec"`
	MaxCPUPercent        int      `json:"max_cpu_percent"`
	MaxRAMMB             int      `json:"max_ram_mb"`
	SpoolMaxDiskMB       int      `json:"spool_max_disk_mb"`
	SpoolMaxAgeHours     int      `json:"spool_max_age_hours"`
	LogCollectionEnabled bool     `json:"log_collection_enabled"`
	EventChannels        []string `json:"event_channels"`
	OsqueryEnabled       bool     `json:"osquery_enabled"`
	UpdateChannel        string   `json:"update_channel"` // stable, beta, development

	// FIM (File & Registry Integrity Monitoring - Phase L)
	FIMEnabled           bool     `json:"fim_enabled"`
	FIMScanIntervalSec   int      `json:"fim_scan_interval_sec"`
	FIMPaths             []string `json:"fim_paths"`
	FIMExcludePaths      []string `json:"fim_exclude_paths"`
	FIMRegistryKeys      []string `json:"fim_registry_keys"`
	FIMSeverityThreshold string   `json:"fim_severity_threshold"` // LOW, MEDIUM, HIGH, CRITICAL

	// USB & Storage DLP Control (Phase M)
	USBControlEnabled   bool     `json:"usb_control_enabled"`
	USBStorageMode      string   `json:"usb_storage_mode"` // "allow", "read_only", "block"
	USBEnforceWhitelist bool     `json:"usb_enforce_whitelist"`
	USBAlertOnInsertion bool     `json:"usb_alert_on_insertion"`
	USBScanIntervalSec  int      `json:"usb_scan_interval_sec"`
	USBAllowedDevices   []string `json:"usb_allowed_devices"` // List of VID:PID or Serial numbers
	USBBlockedClasses   []string `json:"usb_blocked_classes"` // e.g. ["mass_storage", "mtp"]

	// Behavioral Anomaly & Script-Based Attack Prevention EDR (Phase N)
	EDRBehaviorEnabled      bool   `json:"edr_behavior_enabled"`
	EDRKillOnCritical       bool   `json:"edr_kill_on_critical"`       // Autonomous process tree termination
	EDRMonitorScriptEngines bool   `json:"edr_monitor_script_engines"` // PowerShell, bash, cmd, cscript, mshta
	EDRBlockLOLBins         bool   `json:"edr_block_lolbins"`          // Living-off-the-Land binary weaponization
	EDRScanIntervalSec      int    `json:"edr_scan_interval_sec"`
	EDRSeverityThreshold    string `json:"edr_severity_threshold"`     // "LOW", "MEDIUM", "HIGH", "CRITICAL"

	// Network & DNS Protection / Micro-Segmentation EDR (Phase O)
	EDRNetMonEnabled     bool     `json:"edr_netmon_enabled"`
	EDRDNSAuditEnabled   bool     `json:"edr_dns_audit_enabled"`
	EDRBlockMaliciousIPs bool     `json:"edr_block_malicious_ips"`
	EDRDetectC2Beaconing bool     `json:"edr_detect_c2_beaconing"`
	EDRDetectDGA         bool     `json:"edr_detect_dga"`
	EDRBeaconIntervalSec int      `json:"edr_beacon_interval_sec"`
	EDRBlockedPorts      []int    `json:"edr_blocked_ports"`
	EDRBlockedIPs        []string `json:"edr_blocked_ips"`
	EDRBlockedDomains    []string `json:"edr_blocked_domains"`
}

// EndpointSoftware represents a normalized software package installed on an endpoint
type EndpointSoftware struct {
	ID              uuid.UUID `json:"id"`
	AgentID         uuid.UUID `json:"agent_id"`
	TenantSlug      string    `json:"tenant_slug"`
	AgentHostname   string    `json:"agent_hostname,omitempty"`
	AgentIP         string    `json:"agent_ip,omitempty"`
	AgentOS         string    `json:"agent_os,omitempty"`
	Name            string    `json:"name"`
	Vendor          string    `json:"vendor"`
	Version         string    `json:"version"`
	Arch            string    `json:"arch"`
	PackageType     string    `json:"package_type"` // deb, rpm, msi, apk, pkg, app, etc.
	PackageName     string    `json:"package_name"`
	InstallLocation string    `json:"install_location"`
	PURL            string    `json:"purl"`
	CPE             string    `json:"cpe"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// EndpointCVE represents a normalized Common Vulnerabilities and Exposures record
type EndpointCVE struct {
	CVEID           string          `json:"cve_id"`
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	PublishedAt     *time.Time      `json:"published_at,omitempty"`
	ModifiedAt      *time.Time      `json:"modified_at,omitempty"`
	CVSSVersion     string          `json:"cvss_version"`
	CVSSScore       float64         `json:"cvss_score"`
	CVSSVector      string          `json:"cvss_vector"`
	Severity        string          `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	CWE             string          `json:"cwe"`
	References      json.RawMessage `json:"references_json,omitempty"`
	CPECriteria     json.RawMessage `json:"cpe_criteria_json,omitempty"`
	CISAKEV         bool            `json:"cisa_kev"`
	KEVDateAdded    *time.Time      `json:"kev_date_added,omitempty"`
	KEVDueDate      *time.Time      `json:"kev_due_date,omitempty"`
	EPSSProbability float64         `json:"epss_probability"`
	EPSSPercentile  float64         `json:"epss_percentile"`
	ExploitStatus   string          `json:"exploit_status"`
	Source          string          `json:"source"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// EndpointFinding represents a detected vulnerability on a specific endpoint
type EndpointFinding struct {
	ID              uuid.UUID       `json:"id"`
	TenantSlug      string          `json:"tenant_slug"`
	AgentID         uuid.UUID       `json:"agent_id"`
	AgentHostname   string          `json:"agent_hostname,omitempty"`
	AgentIP         string          `json:"agent_ip,omitempty"`
	AgentOS         string          `json:"agent_os,omitempty"`
	CVEID           string          `json:"cve_id"`
	CVETitle        string          `json:"cve_title,omitempty"`
	CVSSScore       float64         `json:"cvss_score"`
	Severity        string          `json:"severity"`
	CISAKEV         bool            `json:"cisa_kev"`
	EPSSProbability float64         `json:"epss_probability"`
	SoftwareID      *uuid.UUID      `json:"software_id,omitempty"`
	SoftwareName    string          `json:"software_name,omitempty"`
	Status          string          `json:"status"` // open, fixed, not_affected, accepted_risk, false_positive, suppressed
	DetectedVersion string          `json:"detected_version"`
	FixedVersion    string          `json:"fixed_version"`
	PatchAvailable  bool            `json:"patch_available"`
	PatchID         string          `json:"patch_id,omitempty"`
	Priority        string          `json:"priority"` // CRITICAL, HIGH, MEDIUM, LOW
	RebootRequired  bool            `json:"reboot_required"`
	DetectionSource string          `json:"detection_source"`
	Evidence        json.RawMessage `json:"evidence_json,omitempty"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`
	ResolvedAt      *time.Time      `json:"resolved_at,omitempty"`
}

// EndpointPatch represents a missing or installed patch on an endpoint
type EndpointPatch struct {
	ID             uuid.UUID `json:"id"`
	TenantSlug     string    `json:"tenant_slug"`
	AgentID        uuid.UUID `json:"agent_id"`
	PatchID        string    `json:"patch_id"`
	Title          string    `json:"title"`
	Vendor         string    `json:"vendor"`
	KBID           string    `json:"kb_id"`
	Severity       string    `json:"severity"`
	CVEIDs         []string  `json:"cve_ids"`
	RequiresReboot bool      `json:"requires_reboot"`
	Status         string    `json:"status"` // missing, installed, pending_reboot
	InstalledAt    *time.Time `json:"installed_at,omitempty"`
	DetectedAt     time.Time  `json:"detected_at"`
}

// EndpointDashboardSummary aggregates high-level metrics for the Endpoint Security overview
type EndpointDashboardSummary struct {
	TotalAgents          int                    `json:"total_agents"`
	OnlineAgents         int                    `json:"online_agents"`
	OfflineAgents        int                    `json:"offline_agents"`
	StaleAgents          int                    `json:"stale_agents"`
	WindowsAgents        int                    `json:"windows_agents"`
	LinuxAgents          int                    `json:"linux_agents"`
	DarwinAgents         int                    `json:"darwin_agents"`
	CriticalVulns        int                    `json:"critical_vulns"`
	HighVulns            int                    `json:"high_vulns"`
	MediumVulns          int                    `json:"medium_vulns"`
	LowVulns             int                    `json:"low_vulns"`
	CISAKEVVulns         int                    `json:"cisa_kev_vulns"`
	HighEPSSVulns        int                    `json:"high_epss_vulns"`
	EndpointsWithCrit    int                    `json:"endpoints_with_crit"`
	EndpointsNeedReboot  int                    `json:"endpoints_need_reboot"`
	PatchCompliancePct   float64                `json:"patch_compliance_pct"`
	FullyPatchedAgents   int                    `json:"fully_patched_agents"`
	MissingSecPatchAgents int                   `json:"missing_sec_patch_agents"`
	TopVulnerableAgents  []EndpointAgentSummary `json:"top_vulnerable_agents"`
	TopCVEs              []EndpointCVESummary   `json:"top_cves"`
}

type EndpointAgentSummary struct {
	AgentID       uuid.UUID `json:"agent_id"`
	Hostname      string    `json:"hostname"`
	IPAddress     string    `json:"ip_address"`
	OSType        string    `json:"os_type"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	TotalVulns    int       `json:"total_vulns"`
}

type EndpointCVESummary struct {
	CVEID         string  `json:"cve_id"`
	Title         string  `json:"title"`
	CVSSScore     float64 `json:"cvss_score"`
	Severity      string  `json:"severity"`
	CISAKEV       bool    `json:"cisa_kev"`
	EPSSScore     float64 `json:"epss_score"`
	AffectedCount int     `json:"affected_count"`
}

// Agent Protocol Payloads
type AgentEnrollRequest struct {
	EnrollmentToken string          `json:"enrollment_token"`
	AgentUUID       string          `json:"agent_uuid"`
	Hostname        string          `json:"hostname"`
	FQDN            string          `json:"fqdn"`
	OSType          string          `json:"os_type"`
	OSFamily        string          `json:"os_family"`
	OSName          string          `json:"os_name"`
	OSVersion       string          `json:"os_version"`
	OSBuild         string          `json:"os_build"`
	KernelVersion   string          `json:"kernel_version"`
	Architecture    string          `json:"architecture"`
	AgentVersion    string          `json:"agent_version"`
	IPAddress       string          `json:"ip_address"`
	MACAddress      string          `json:"mac_address"`
	DeviceFingerprint string        `json:"device_fingerprint"`
	Labels          json.RawMessage `json:"labels,omitempty"`
}

type AgentEnrollResponse struct {
	AgentID        uuid.UUID             `json:"agent_id"`
	TenantSlug     string                `json:"tenant_slug"`
	AuthToken      string                `json:"auth_token"`
	ServerTime     time.Time             `json:"server_time"`
	PolicyRevision int                   `json:"policy_revision"`
	Policy         *EndpointPolicyConfig `json:"policy"`
}

type AgentHeartbeatRequest struct {
	AgentUUID      string                 `json:"agent_uuid"`
	Hostname       string                 `json:"hostname"`
	AgentVersion   string                 `json:"agent_version"`
	Status         string                 `json:"status"`
	PolicyRevision int                    `json:"policy_revision"`
	IPAddress      string                 `json:"ip_address"`
	MACAddress     string                 `json:"mac_address"`
	RebootRequired bool                   `json:"reboot_required"`
	Metrics        AgentResourceMetrics   `json:"metrics"`
}

type AgentResourceMetrics struct {
	CPUPercent     float64 `json:"cpu_percent"`
	RAMUsedBytes   uint64  `json:"ram_used_bytes"`
	RAMTotalBytes  uint64  `json:"ram_total_bytes"`
	RAMPercent     float64 `json:"ram_percent"`
	RAMRSSBytes    uint64  `json:"ram_rss_bytes"`
	DiskUsedBytes  uint64  `json:"disk_used_bytes"`
	DiskTotalBytes uint64  `json:"disk_total_bytes"`
	DiskPercent    float64 `json:"disk_percent"`
	SpoolDiskBytes uint64  `json:"spool_disk_bytes"`
	QueueDepth     int     `json:"queue_depth"`
	EPSOut         float64 `json:"eps_out"`
	UptimeSeconds  uint64  `json:"uptime_seconds"`
}

type AgentHeartbeatResponse struct {
	Ack                   bool                  `json:"ack"`
	ServerTime            time.Time             `json:"server_time"`
	CurrentPolicyRevision int                   `json:"current_policy_revision"`
	PolicyNeedsUpdate     bool                  `json:"policy_needs_update"`
	Policy                *EndpointPolicyConfig `json:"policy,omitempty"`
	PendingTasksCount     int                   `json:"pending_tasks_count"`
	PendingTasks          []EndpointTask        `json:"pending_tasks,omitempty"`

	// Auto-Update Telemetry
	UpgradeAvailable      bool       `json:"upgrade_available,omitempty"`
	TargetVersion         string     `json:"target_version,omitempty"`
	DownloadURL           string     `json:"download_url,omitempty"`
	ChecksumSHA256        string     `json:"checksum_sha256,omitempty"`
}

// EndpointPatchItem represents an enriched patch view with host telemetry
type EndpointPatchItem struct {
	ID             uuid.UUID  `json:"id"`
	AgentID        uuid.UUID  `json:"agent_id"`
	AgentHostname  string     `json:"agent_hostname"`
	AgentIP        string     `json:"agent_ip"`
	AgentOS        string     `json:"agent_os"`
	PatchID        string     `json:"patch_id"`
	Title          string     `json:"title"`
	Vendor         string     `json:"vendor"`
	KBID           string     `json:"kb_id"`
	Severity       string     `json:"severity"`
	CVEIDs         []string   `json:"cve_ids"`
	RequiresReboot bool       `json:"requires_reboot"`
	Status         string     `json:"status"` // missing, installed, pending_reboot
	InstalledAt    *time.Time `json:"installed_at,omitempty"`
	DetectedAt     time.Time  `json:"detected_at"`
}

type PatchComplianceSummary struct {
	CompliancePct       float64 `json:"compliance_pct"`
	TotalPatches        int     `json:"total_patches"`
	InstalledCount      int     `json:"installed_count"`
	MissingCount        int     `json:"missing_count"`
	PendingRebootsCount int     `json:"pending_reboots_count"`
	EndpointsNeedReboot int     `json:"endpoints_need_reboot"`
}

// AgentInventoryRequest represents an inventory, software, and patch snapshot sent by an agent
type AgentInventoryRequest struct {
	AgentUUID     string                 `json:"agent_uuid"`
	Hostname      string                 `json:"hostname"`
	OSType        string                 `json:"os_type"`
	OSFamily      string                 `json:"os_family"`
	OSName        string                 `json:"os_name"`
	OSVersion     string                 `json:"os_version"`
	OSBuild       string                 `json:"os_build"`
	KernelVersion string                 `json:"kernel_version"`
	Architecture  string                 `json:"architecture"`
	IPAddress     string                 `json:"ip_address"`
	MACAddress    string                 `json:"mac_address"`
	SystemInfo    map[string]interface{} `json:"system_info,omitempty"`
	HardwareInfo  map[string]interface{} `json:"hardware_info,omitempty"`
	NetworkInfo   map[string]interface{} `json:"network_info,omitempty"`
	Software      []AgentSoftwareItem    `json:"software"`
	Patches       []AgentPatchItem       `json:"patches"`
}

type AgentSoftwareItem struct {
	Name            string `json:"name"`
	Vendor          string `json:"vendor"`
	Version         string `json:"version"`
	Arch            string `json:"arch"`
	PackageType     string `json:"package_type"`
	InstallLocation string `json:"install_location"`
}

type AgentPatchItem struct {
	HotFixID    string `json:"hotfix_id"`
	Description string `json:"description"`
	InstalledOn string `json:"installed_on"`
}

type AgentInventoryResponse struct {
	Ack               bool      `json:"ack"`
	ProcessedSoftware int       `json:"processed_software"`
	ProcessedPatches  int       `json:"processed_patches"`
	DetectedVulns     int       `json:"detected_vulns"`
	ServerTime        time.Time `json:"server_time"`
}

// CVESyncStatus represents the current state and schedule of the CVE intelligence database
type CVESyncStatus struct {
	TotalCVEs      int        `json:"total_cves"`
	CISAKEVCount   int        `json:"cisa_kev_count"`
	HighCritCount  int        `json:"high_crit_count"`
	ScheduleMode   string     `json:"schedule_mode"` // manual, daily, weekly, monthly
	LastSyncAt     *time.Time `json:"last_sync_at,omitempty"`
	NextSyncAt     *time.Time `json:"next_sync_at,omitempty"`
	LastSyncStatus string     `json:"last_sync_status"`
	LastError      string     `json:"last_error,omitempty"`
	IsSyncing      bool       `json:"is_syncing"`
}

// EndpointTask represents a remote remediation or maintenance job dispatched to an agent
type EndpointTask struct {
	ID                  uuid.UUID           `json:"id"`
	TenantSlug          string              `json:"tenant_slug"`
	AgentID             uuid.UUID           `json:"agent_id"`
	AgentHostname       string              `json:"agent_hostname,omitempty"`
	AgentIP             string              `json:"agent_ip,omitempty"`
	AgentOS             string              `json:"agent_os,omitempty"`
	GroupID             *uuid.UUID          `json:"group_id,omitempty"`
	TaskType            string              `json:"task_type"` // patch_install, patch_scan, system_reboot
	PayloadJSON         json.RawMessage     `json:"payload_json"`
	Status              string              `json:"status"` // pending, running, completed, failed, cancelled
	CreatedBy           string              `json:"created_by"`
	ScheduledAt         time.Time           `json:"scheduled_at"`
	StartedAt           *time.Time          `json:"started_at,omitempty"`
	CompletedAt         *time.Time          `json:"completed_at,omitempty"`
	ErrorMessage        string              `json:"error_message,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	ExecutionDurationMs int64               `json:"execution_duration_ms,omitempty"`
	Result              *EndpointTaskResult `json:"result,omitempty"`
}

// EndpointTaskResult represents the raw execution stdout/stderr and exit code from an agent
type EndpointTaskResult struct {
	TaskID              uuid.UUID `json:"task_id"`
	AgentID             uuid.UUID `json:"agent_id"`
	Status              string    `json:"status"` // completed, failed
	ExitCode            int       `json:"exit_code"`
	Stdout              string    `json:"stdout"`
	Stderr              string    `json:"stderr"`
	ExecutionDurationMs int64     `json:"execution_duration_ms"`
	CompletedAt         time.Time `json:"completed_at"`
}

// AgentTaskResultSubmission is the payload sent by the agent when completing a task
type AgentTaskResultSubmission struct {
	AgentUUID           string `json:"agent_uuid,omitempty"`
	TaskID              string `json:"task_id"`
	Status              string `json:"status"` // completed, failed
	ExitCode            int    `json:"exit_code"`
	Stdout              string `json:"stdout"`
	Stderr              string `json:"stderr"`
	ExecutionDurationMs int64  `json:"execution_duration_ms"`
	ErrorMessage        string `json:"error_message,omitempty"`
}

// PatchDeployRequest defines an administrative request to remediate a missing patch on an endpoint
type PatchDeployRequest struct {
	AgentID     string `json:"agent_id"`
	PatchID     string `json:"patch_id"`
	Title       string `json:"title,omitempty"`
	RebootAfter bool   `json:"reboot_after"`
}

// BatchPatchDeployRequest defines a fleet-wide or group-wide patch remediation dispatch
type BatchPatchDeployRequest struct {
	SeverityFilter string   `json:"severity_filter,omitempty"` // ALL, CRITICAL, HIGH
	AgentIDs       []string `json:"agent_ids,omitempty"`
	RebootAfter    bool     `json:"reboot_after"`
}

// HostIsolationRequest defines a request to isolate or un-isolate an endpoint
type HostIsolationRequest struct {
	Reason     string   `json:"reason,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// ProcessKillRequest defines an active response request to terminate a process
type ProcessKillRequest struct {
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Force       bool   `json:"force"`
}

// FileQuarantineRequest defines a request to quarantine a malicious or suspicious file
type FileQuarantineRequest struct {
	FilePath string `json:"file_path"`
	Reason   string `json:"reason,omitempty"`
}

// OSQueryRunRequest defines a remote live forensic SQL execution request
type OSQueryRunRequest struct {
	Query      string `json:"query"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

// QuarantinedFileEntry records quarantined files on an endpoint
type QuarantinedFileEntry struct {
	OriginalPath   string    `json:"original_path"`
	QuarantinePath string    `json:"quarantine_path"`
	SHA256         string    `json:"sha256"`
	SizeBytes      int64     `json:"size_bytes"`
	QuarantinedAt  time.Time `json:"quarantined_at"`
	Reason         string    `json:"reason,omitempty"`
}

// EndpointUSBDevice represents a connected or historical USB/peripheral storage device (Phase M)
type EndpointUSBDevice struct {
	ID            uuid.UUID `json:"id"`
	AgentID       uuid.UUID `json:"agent_id"`
	TenantSlug    string    `json:"tenant_slug"`
	AgentHostname string    `json:"agent_hostname,omitempty"`
	AgentIP       string    `json:"agent_ip,omitempty"`
	DeviceID      string    `json:"device_id"`       // System device identifier (e.g. \\.\PHYSICALDRIVE1 or /dev/sdb)
	VendorID      string    `json:"vendor_id"`       // 4-char hex (e.g. 0781 for SanDisk)
	ProductID     string    `json:"product_id"`      // 4-char hex (e.g. 5567 for Cruzer Blade)
	SerialNumber  string    `json:"serial_number"`
	VendorName    string    `json:"vendor_name"`
	ProductName   string    `json:"product_name"`
	DriveLetter   string    `json:"drive_letter"`    // e.g. "E:" on Windows
	MountPoint    string    `json:"mount_point"`     // e.g. "/media/usb" on Linux
	CapacityBytes int64     `json:"capacity_bytes"`
	FileSystem    string    `json:"file_system"`     // NTFS, FAT32, exFAT, ext4
	IsBlocked     bool      `json:"is_blocked"`
	IsReadOnly    bool      `json:"is_read_only"`
	IsConnected   bool      `json:"is_connected"`
	IsWhitelisted bool      `json:"is_whitelisted"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// EndpointUSBEvent represents a DLP audit event regarding USB/peripheral insertion, removal, or policy violation (Phase M)
type EndpointUSBEvent struct {
	ID             uuid.UUID `json:"id"`
	TenantSlug     string    `json:"tenant_slug"`
	AgentID        uuid.UUID `json:"agent_id"`
	AgentHostname  string    `json:"agent_hostname,omitempty"`
	AgentIP        string    `json:"agent_ip,omitempty"`
	EventType      string    `json:"event_type"` // "inserted", "removed", "blocked", "write_denied", "unauthorized_whitelist"
	VendorID       string    `json:"vendor_id"`
	ProductID      string    `json:"product_id"`
	SerialNumber   string    `json:"serial_number"`
	DeviceName     string    `json:"device_name"`
	DriveLetter    string    `json:"drive_letter"`
	MountPoint     string    `json:"mount_point"`
	ActionTaken    string    `json:"action_taken"`    // "allowed", "mounted_ro", "blocked", "unmounted"
	MitreTechnique string    `json:"mitre_technique"` // T1052.001, T1200
	Details        string    `json:"details"`
	CreatedAt      time.Time `json:"created_at"`
}

// EndpointUSBWhitelistEntry defines an authorized USB device (Phase M)
type EndpointUSBWhitelistEntry struct {
	ID           uuid.UUID `json:"id"`
	TenantSlug   string    `json:"tenant_slug"`
	Name         string    `json:"name"`
	VendorID     string    `json:"vendor_id"`
	ProductID    string    `json:"product_id"`
	SerialNumber string    `json:"serial_number"`
	Description  string    `json:"description"`
	ApprovedBy   string    `json:"approved_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// AgentUSBSubmission represents the payload sent by the agent to report attached USBs and DLP events (Phase M)
type AgentUSBSubmission struct {
	AgentUUID string              `json:"agent_uuid"`
	Devices   []EndpointUSBDevice `json:"devices"`
	Events    []EndpointUSBEvent  `json:"events"`
}

// EndpointProcessAnomaly represents a behavioral anomaly, malicious script execution, or LOLBin abuse (Phase N)
type EndpointProcessAnomaly struct {
	ID                uuid.UUID `json:"id"`
	TenantSlug        string    `json:"tenant_slug"`
	AgentID           uuid.UUID `json:"agent_id"`
	AgentHostname     string    `json:"agent_hostname,omitempty"`
	AgentIP           string    `json:"agent_ip,omitempty"`
	PID               int       `json:"pid"`
	ProcessName       string    `json:"process_name"`
	CommandLine       string    `json:"command_line"`
	ParentPID         int       `json:"parent_pid"`
	ParentName        string    `json:"parent_name"`
	ParentCommandLine string    `json:"parent_command_line"`
	Username          string    `json:"username"`
	Severity          string    `json:"severity"` // "low", "medium", "high", "critical"
	RuleID            string    `json:"rule_id"`
	RuleName          string    `json:"rule_name"`
	MitreTactic       string    `json:"mitre_tactic"`    // e.g. "Execution", "Defense Evasion", "Persistence"
	MitreTechnique    string    `json:"mitre_technique"` // e.g. "T1059.001", "T1218.011", "T1055"
	ActionTaken       string    `json:"action_taken"`    // "audited", "terminated", "blocked"
	Details           string    `json:"details"`
	Timestamp         time.Time `json:"timestamp"`
	CreatedAt         time.Time `json:"created_at"`
}

// AgentBehaviorSubmission represents the payload sent by the agent to report behavioral anomalies and script threats (Phase N)
type AgentBehaviorSubmission struct {
	AgentUUID string                   `json:"agent_uuid"`
	Anomalies []EndpointProcessAnomaly `json:"anomalies"`
}

// EDRStats represents aggregate metrics for Phase N Behavioral EDR
type EDRStats struct {
	TotalDetections      int64 `json:"total_detections"`
	CriticalThreats      int64 `json:"critical_threats"`
	SuspiciousScripts    int64 `json:"suspicious_scripts"`
	ProcessesTerminated  int64 `json:"processes_terminated"`
	MonitoredAgentsCount int64 `json:"monitored_agents_count"`
}

// EndpointNetworkConnection represents an active or observed network socket/connection on an endpoint (Phase O)
type EndpointNetworkConnection struct {
	ID             uuid.UUID `json:"id"`
	TenantSlug     string    `json:"tenant_slug"`
	AgentID        uuid.UUID `json:"agent_id"`
	AgentHostname  string    `json:"agent_hostname,omitempty"`
	AgentIP        string    `json:"agent_ip,omitempty"`
	PID            int       `json:"pid"`
	ProcessName    string    `json:"process_name"`
	Protocol       string    `json:"protocol"` // "tcp", "udp"
	LocalIP        string    `json:"local_ip"`
	LocalPort      int       `json:"local_port"`
	RemoteIP       string    `json:"remote_ip"`
	RemotePort     int       `json:"remote_port"`
	RemoteDomain   string    `json:"remote_domain,omitempty"`
	State          string    `json:"state"`     // "ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"
	Direction      string    `json:"direction"` // "outbound", "inbound", "listening"
	ThreatSeverity string    `json:"threat_severity"` // "info", "low", "medium", "high", "critical"
	ThreatReason   string    `json:"threat_reason,omitempty"` // e.g. "C2 Beaconing Pattern", "Suspicious Port 4444"
	ActionTaken    string    `json:"action_taken"`            // "allowed", "blocked", "isolated", "audited"
	Timestamp      time.Time `json:"timestamp"`
	CreatedAt      time.Time `json:"created_at"`
}

// EndpointDNSQuery represents an audited DNS request performed by a process on an endpoint (Phase O)
type EndpointDNSQuery struct {
	ID            uuid.UUID `json:"id"`
	TenantSlug    string    `json:"tenant_slug"`
	AgentID       uuid.UUID `json:"agent_id"`
	AgentHostname string    `json:"agent_hostname,omitempty"`
	AgentIP       string    `json:"agent_ip,omitempty"`
	PID           int       `json:"pid"`
	ProcessName   string    `json:"process_name"`
	QueryDomain   string    `json:"query_domain"`
	QueryType     string    `json:"query_type"`   // "A", "AAAA", "TXT", "MX", "CNAME"
	ResponseCode  string    `json:"response_code"` // "NOERROR", "NXDOMAIN", "SERVFAIL", "BLOCKED"
	ResolvedIPs   []string  `json:"resolved_ips"`
	EntropyScore  float64   `json:"entropy_score"` // Shannon entropy for DGA detection (> 3.8 = high entropy)
	IsDGA         bool      `json:"is_dga"`
	IsMalicious   bool      `json:"is_malicious"`
	ThreatReason  string    `json:"threat_reason,omitempty"` // "DGA-Domain", "High Entropy", "Known Malicious Domain"
	ActionTaken   string    `json:"action_taken"`            // "resolved", "blocked", "sinkholed"
	Timestamp     time.Time `json:"timestamp"`
	CreatedAt     time.Time `json:"created_at"`
}

// EndpointFirewallRule represents a dynamic host isolation or micro-segmentation rule enforced by the agent (Phase O)
type EndpointFirewallRule struct {
	ID         uuid.UUID  `json:"id"`
	TenantSlug string     `json:"tenant_slug"`
	AgentID    *uuid.UUID `json:"agent_id,omitempty"` // nil if tenant-wide global rule
	RuleName   string     `json:"rule_name"`
	Direction  string     `json:"direction"`  // "inbound", "outbound", "both"
	Action     string     `json:"action"`     // "block", "allow"
	Protocol   string     `json:"protocol"`   // "any", "tcp", "udp"
	RemoteIP   string     `json:"remote_ip"`  // CIDR or IP (e.g. "198.51.100.23/32")
	RemotePort string     `json:"remote_port"`// "any", "4444", "80,443"
	IsEnabled  bool       `json:"is_enabled"`
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// AgentNetworkSubmission represents the payload sent by the agent to report active network sockets, DNS queries, and C2 beacons (Phase O)
type AgentNetworkSubmission struct {
	AgentUUID   string                      `json:"agent_uuid"`
	Connections []EndpointNetworkConnection `json:"connections"`
	DNSQueries  []EndpointDNSQuery          `json:"dns_queries"`
}

// EDRNetworkStats represents aggregate metrics for Phase O Network & DNS EDR
type EDRNetworkStats struct {
	TotalConnectionsObserved int64 `json:"total_connections_observed"`
	SuspiciousOutboundConns  int64 `json:"suspicious_outbound_conns"`
	C2BeaconsDetected        int64 `json:"c2_beacons_detected"`
	DNSQueriesAudited        int64 `json:"dns_queries_audited"`
	DGADomainsBlocked        int64 `json:"dga_domains_blocked"`
	ActiveFirewallBlocks     int64 `json:"active_firewall_blocks"`
	IsolatedEndpoints        int64 `json:"isolated_endpoints"`
}

// EndpointRansomwareIncident represents an active or neutralized ransomware attack (Phase P)
type EndpointRansomwareIncident struct {
	ID                uuid.UUID `json:"id"`
	TenantSlug        string    `json:"tenant_slug"`
	AgentID           uuid.UUID `json:"agent_id"`
	AgentHostname     string    `json:"agent_hostname"`
	AgentIP           string    `json:"agent_ip"`
	ProcessName       string    `json:"process_name"`
	ProcessPID        int       `json:"process_pid"`
	ProcessPath       string    `json:"process_path"`
	CommandLine       string    `json:"command_line,omitempty"`
	TriggerType       string    `json:"trigger_type"` // "canary_tripwire", "mass_encryption", "known_ransomware_extension", "high_entropy"
	TargetFile        string    `json:"target_file"`
	ExtensionDetected string    `json:"extension_detected,omitempty"`
	EntropyScore      float64   `json:"entropy_score"`
	FilesAffected     int       `json:"files_affected"`
	ActionTaken       string    `json:"action_taken"` // "TERMINATED", "QUARANTINED", "ISOLATED", "ALERTED"
	Severity          string    `json:"severity"`     // "CRITICAL", "HIGH"
	MitreTactic       string    `json:"mitre_tactic"` // "Impact", "Inhibit System Recovery"
	MitreTechnique    string    `json:"mitre_technique"` // "T1486", "T1490"
	CreatedAt         time.Time `json:"created_at"`
}

// EndpointCanaryToken represents a deployed decoy honeypot file on an endpoint (Phase P)
type EndpointCanaryToken struct {
	ID            uuid.UUID  `json:"id"`
	TenantSlug    string     `json:"tenant_slug"`
	AgentID       uuid.UUID  `json:"agent_id"`
	AgentHostname string     `json:"agent_hostname"`
	FilePath      string     `json:"file_path"`
	FileType      string     `json:"file_type"` // "docx", "xlsx", "pdf"
	InitialHash   string     `json:"initial_hash"`
	Status        string     `json:"status"` // "ARMED", "TRIGGERED", "CLEARED"
	LastCheckedAt time.Time  `json:"last_checked_at"`
	TriggeredAt   *time.Time `json:"triggered_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// AgentRansomwareSubmission represents the telemetry sent by native agent when ransomware or canary tripwire is detected (Phase P)
type AgentRansomwareSubmission struct {
	AgentUUID string                       `json:"agent_uuid"`
	Incidents []EndpointRansomwareIncident `json:"incidents"`
	Canaries  []EndpointCanaryToken        `json:"canaries"`
}

// RansomwareStats represents aggregate metrics for Phase P Anti-Ransomware Shield
type RansomwareStats struct {
	TotalRansomwareIncidents int64 `json:"total_ransomware_incidents"`
	CanariesArmed            int64 `json:"canaries_armed"`
	CanariesTriggered        int64 `json:"canaries_triggered"`
	ProcessesTerminated      int64 `json:"processes_terminated"`
	BinariesQuarantined      int64 `json:"binaries_quarantined"`
	HostsIsolated            int64 `json:"hosts_isolated"`
}

// EndpointHoneypotConfig represents administrative honeypot and anti-ransomware shield configuration
type EndpointHoneypotConfig struct {
	TenantSlug       string    `json:"tenant_slug"`
	Enabled          bool      `json:"enabled"`
	CanariesEnabled  bool      `json:"canaries_enabled"`
	AutonomousKill   bool      `json:"autonomous_kill"`
	EntropyThreshold float64   `json:"entropy_threshold"`
	ActionMode       string    `json:"action_mode"` // "TERMINATE", "QUARANTINE_ONLY", "ALERT_ONLY"
	DecoyTypes       string    `json:"decoy_types"` // comma-separated e.g. "docx,xlsx,pdf"
	CustomPath       string    `json:"custom_path"`
	RearmIntervalSec int       `json:"rearm_interval_sec"`
	UpdatedAt        time.Time `json:"updated_at"`
}





