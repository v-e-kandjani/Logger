package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/syslog-platform/logger/internal/config"
	"github.com/syslog-platform/logger/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	pool *pgxpool.Pool
}

// NewDB creates connection pool to PostgreSQL
func NewDB(cfg config.PostgresConfig) (*DB, error) {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&pool_max_conns=%d&pool_min_conns=%d",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port, cfg.Database, cfg.SSLMode, cfg.MaxOpenConns, cfg.MaxIdleConns)

	poolCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing pgx config: %w", err)
	}
	poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating pgx pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		if cfg.Host != "127.0.0.1" && cfg.Host != "localhost" {
			log.Printf("[PostgreSQL] Host '%s' connection failed (%v), falling back to 127.0.0.1...", cfg.Host, err)
			fallbackCfg := cfg
			fallbackCfg.Host = "127.0.0.1"
			return NewDB(fallbackCfg)
		}
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	return &DB{pool: pool}, nil
}

func (db *DB) Close() {
	db.pool.Close()
}

func (db *DB) Ping(ctx context.Context) error {
	return db.pool.Ping(ctx)
}

// DeviceCache maintains lock-free in-memory lookups for active IPs to avoid querying Postgres on every syslog packet
type DeviceCache struct {
	mu      sync.RWMutex
	byIP    map[string]*models.Device
	byID    map[uuid.UUID]*models.Device
	db      *DB
	lastRef time.Time
}

func NewDeviceCache(db *DB) *DeviceCache {
	dc := &DeviceCache{
		byIP: make(map[string]*models.Device),
		byID: make(map[uuid.UUID]*models.Device),
		db:   db,
	}
	_ = dc.Refresh(context.Background())
	return dc
}

func (dc *DeviceCache) Refresh(ctx context.Context) error {
	devices, err := dc.db.ListDevices(ctx)
	if err != nil {
		return err
	}

	newByIP := make(map[string]*models.Device, len(devices))
	newByID := make(map[uuid.UUID]*models.Device, len(devices))

	for i := range devices {
		d := &devices[i]
		newByIP[d.IPAddress] = d
		newByID[d.ID] = d
	}

	dc.mu.Lock()
	dc.byIP = newByIP
	dc.byID = newByID
	dc.lastRef = time.Now()
	dc.mu.Unlock()
	return nil
}

func (dc *DeviceCache) LookupIP(ipStr string) (*models.Device, bool) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	dev, ok := dc.byIP[ipStr]
	return dev, ok
}

// --- Device Repository Methods ---

func (db *DB) ListDevices(ctx context.Context) ([]models.Device, error) {
	query := `
		SELECT d.id, d.name, host(d.ip_address), d.hostname, d.description, d.vendor,
		       d.device_type, d.group_id, COALESCE(g.name, ''), d.site_location,
		       d.expected_protocol, d.expected_port, d.is_enabled, d.retention_days,
		       d.timestamping_policy, d.last_seen_at, d.tags, d.created_at, d.updated_at
		FROM devices d
		LEFT JOIN device_groups g ON d.group_id = g.id
		ORDER BY d.name ASC`

	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.Device
	now := time.Now()

	for rows.Next() {
		var d models.Device
		var lastSeen *time.Time
		err := rows.Scan(
			&d.ID, &d.Name, &d.IPAddress, &d.Hostname, &d.Description, &d.Vendor,
			&d.DeviceType, &d.GroupID, &d.GroupName, &d.SiteLocation,
			&d.ExpectedProtocol, &d.ExpectedPort, &d.IsEnabled, &d.RetentionDays,
			&d.TimestampPolicy, &lastSeen, &d.Tags, &d.CreatedAt, &d.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		d.LastSeenAt = lastSeen

		// Calculate Syslog Activity Status
		if lastSeen == nil {
			d.SyslogStatus = "NEVER_SEEN"
		} else if now.Sub(*lastSeen) < 5*time.Minute {
			d.SyslogStatus = "HEALTHY"
		} else if now.Sub(*lastSeen) < 15*time.Minute {
			d.SyslogStatus = "WARNING"
		} else {
			d.SyslogStatus = "OFFLINE"
		}

		list = append(list, d)
	}
	return list, nil
}

func (db *DB) CreateDevice(ctx context.Context, d *models.Device) error {
	// If GroupName is provided but GroupID is nil, resolve or create the group
	if d.GroupID == nil && d.GroupName != "" {
		var gid uuid.UUID
		err := db.pool.QueryRow(ctx, `
			INSERT INTO device_groups (name, description)
			VALUES ($1, 'Auto-created group')
			ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			RETURNING id`, d.GroupName).Scan(&gid)
		if err == nil {
			d.GroupID = &gid
		}
	}

	if d.Tags == nil {
		d.Tags = []string{}
	}

	query := `
		INSERT INTO devices (name, ip_address, hostname, description, vendor, device_type,
		                     group_id, site_location, expected_protocol, expected_port,
		                     is_enabled, retention_days, timestamping_policy, tags)
		VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (ip_address) DO UPDATE
		SET name = EXCLUDED.name,
		    hostname = CASE WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname ELSE devices.hostname END,
		    description = CASE WHEN EXCLUDED.description != '' THEN EXCLUDED.description ELSE devices.description END,
		    vendor = EXCLUDED.vendor,
		    device_type = EXCLUDED.device_type,
		    group_id = COALESCE(EXCLUDED.group_id, devices.group_id),
		    is_enabled = TRUE,
		    updated_at = NOW()
		RETURNING id, created_at, updated_at`

	err := db.pool.QueryRow(ctx, query,
		d.Name, d.IPAddress, d.Hostname, d.Description, d.Vendor, d.DeviceType,
		d.GroupID, d.SiteLocation, d.ExpectedProtocol, d.ExpectedPort,
		d.IsEnabled, d.RetentionDays, d.TimestampPolicy, d.Tags,
	).Scan(&d.ID, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return err
	}

	// Purge from unregistered sources now that it is officially registered
	_ = db.DeleteUnregisteredSource(ctx, d.IPAddress)
	return nil
}

func (db *DB) UpdateDeviceLastSeen(ctx context.Context, ipStr string, seenTime time.Time) error {
	query := `UPDATE devices SET last_seen_at = $1 WHERE ip_address = $2::inet`
	_, err := db.pool.Exec(ctx, query, seenTime, ipStr)
	return err
}

// RecordUnregisteredSource upserts an auto-discovered sender
func (db *DB) RecordUnregisteredSource(ctx context.Context, u *models.UnregisteredSource) error {
	query := `
		INSERT INTO unregistered_sources (ip_address, first_seen_at, last_seen_at, packet_count, last_raw_sample, detected_facility, detected_severity)
		VALUES ($1::inet, $2, $2, 1, $3, $4, $5)
		ON CONFLICT (ip_address) DO UPDATE
		SET last_seen_at = EXCLUDED.last_seen_at,
		    packet_count = unregistered_sources.packet_count + 1,
		    last_raw_sample = EXCLUDED.last_raw_sample,
		    detected_facility = EXCLUDED.detected_facility,
		    detected_severity = EXCLUDED.detected_severity`

	_, err := db.pool.Exec(ctx, query, u.IPAddress, u.LastSeenAt, u.LastRawSample, u.DetectedFacility, u.DetectedSeverity)
	return err
}

// DeleteUnregisteredSource deletes an IP from auto-discovered sources
func (db *DB) DeleteUnregisteredSource(ctx context.Context, ipStr string) error {
	query := `DELETE FROM unregistered_sources WHERE ip_address = $1::inet`
	_, err := db.pool.Exec(ctx, query, ipStr)
	return err
}

func (db *DB) ListUnregisteredSources(ctx context.Context) ([]models.UnregisteredSource, error) {
	// Exclude any IP that has already been registered in the devices table
	query := `
		SELECT host(u.ip_address), u.first_seen_at, u.last_seen_at, u.packet_count, u.last_raw_sample, u.detected_facility, u.detected_severity
		FROM unregistered_sources u
		LEFT JOIN devices d ON u.ip_address = d.ip_address
		WHERE d.id IS NULL
		ORDER BY u.last_seen_at DESC LIMIT 100`

	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.UnregisteredSource
	for rows.Next() {
		var u models.UnregisteredSource
		if err := rows.Scan(&u.IPAddress, &u.FirstSeenAt, &u.LastSeenAt, &u.PacketCount, &u.LastRawSample, &u.DetectedFacility, &u.DetectedSeverity); err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, nil
}

// LogArchive methods
func (db *DB) CreateArchiveRecord(ctx context.Context, a *models.LogArchive) error {
	query := `
		INSERT INTO log_archives (archive_name, start_timestamp, end_timestamp, record_count,
		                          archive_path, archive_size, hash_algorithm, hash_value, timestamp_status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`

	return db.pool.QueryRow(ctx, query,
		a.ArchiveName, a.StartTimestamp, a.EndTimestamp, a.RecordCount,
		a.ArchivePath, a.ArchiveSize, a.HashAlgorithm, a.HashValue, a.TimestampStatus,
	).Scan(&a.ID, &a.CreatedAt)
}

func (db *DB) UpdateArchiveTimestamp(ctx context.Context, id uuid.UUID, status, evidencePath, lastError string) error {
	query := `
		UPDATE log_archives
		SET timestamp_status = $1::text,
		    timestamp_completion_time = CASE WHEN $1::text = 'STAMPED' THEN NOW() ELSE timestamp_completion_time END,
		    timestamp_evidence_path = $2,
		    last_error = $3,
		    retry_count = retry_count + CASE WHEN $1::text = 'FAILED' THEN 1 ELSE 0 END
		WHERE id = $4`

	_, err := db.pool.Exec(ctx, query, status, evidencePath, lastError, id)
	return err
}

func (db *DB) ListArchives(ctx context.Context, limit int) ([]models.LogArchive, error) {
	query := `
		SELECT id, archive_name, start_timestamp, end_timestamp, record_count, archive_path,
		       archive_size, hash_algorithm, hash_value, timestamp_status, timestamp_request_time,
		       timestamp_completion_time, timestamp_evidence_path, retry_count, last_error, created_at
		FROM log_archives
		ORDER BY start_timestamp DESC
		LIMIT $1`

	rows, err := db.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.LogArchive
	for rows.Next() {
		var a models.LogArchive
		err := rows.Scan(
			&a.ID, &a.ArchiveName, &a.StartTimestamp, &a.EndTimestamp, &a.RecordCount, &a.ArchivePath,
			&a.ArchiveSize, &a.HashAlgorithm, &a.HashValue, &a.TimestampStatus, &a.TimestampRequestTime,
			&a.TimestampCompletionTime, &a.TimestampEvidencePath, &a.RetryCount, &a.LastError, &a.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, nil
}

func (db *DB) GetArchive(ctx context.Context, id uuid.UUID) (*models.LogArchive, error) {
	query := `
		SELECT id, archive_name, start_timestamp, end_timestamp, record_count, archive_path,
		       archive_size, hash_algorithm, hash_value, timestamp_status, timestamp_request_time,
		       timestamp_completion_time, timestamp_evidence_path, retry_count, last_error, created_at
		FROM log_archives
		WHERE id = $1`

	var a models.LogArchive
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&a.ID, &a.ArchiveName, &a.StartTimestamp, &a.EndTimestamp, &a.RecordCount, &a.ArchivePath,
		&a.ArchiveSize, &a.HashAlgorithm, &a.HashValue, &a.TimestampStatus, &a.TimestampRequestTime,
		&a.TimestampCompletionTime, &a.TimestampEvidencePath, &a.RetryCount, &a.LastError, &a.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AuditLog recording
func (db *DB) InsertAuditLog(ctx context.Context, a *models.AuditLog) error {
	query := `
		INSERT INTO audit_logs (user_id, username, source_ip, action, resource, result, details)
		VALUES ($1, $2, $3::inet, $4, $5, $6, $7)
		RETURNING id, created_at`

	return db.pool.QueryRow(ctx, query,
		a.UserID, a.Username, a.SourceIP, a.Action, a.Resource, a.Result, a.Details,
	).Scan(&a.ID, &a.CreatedAt)
}

// System Settings methods
func (db *DB) GetSettings(ctx context.Context) (map[string]string, error) {
	rows, err := db.pool.Query(ctx, "SELECT key, value FROM system_settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			settings[k] = v
		}
	}
	return settings, nil
}

func (db *DB) SaveSetting(ctx context.Context, key, val string) error {
	query := `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE
		SET value = EXCLUDED.value, updated_at = NOW()`
	_, err := db.pool.Exec(ctx, query, key, val)
	return err
}

func (db *DB) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	_, err := db.pool.Exec(ctx, "DELETE FROM devices WHERE id = $1", id)
	return err
}

// SeedDefaultDevices populates initial default assets (such as WatchGuard Firebox) if device inventory is empty
func (db *DB) SeedDefaultDevices(ctx context.Context) error {
	var count int
	if err := db.pool.QueryRow(ctx, "SELECT count(*) FROM devices").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	query := `
		INSERT INTO devices (name, ip_address, hostname, description, vendor, device_type, site_location, expected_protocol, expected_port, is_enabled, retention_days, timestamping_policy)
		VALUES ('HQ-WatchGuard-Firebox', '10.0.1.1'::inet, 'WatchGuard-Firebox-M370', 'Primary Perimeter Firewall (Fireware OS)', 'WatchGuard', 'Firewall', 'HQ Datacenter', 'UDP', 514, true, 365, 'HOURLY')
		ON CONFLICT (ip_address) DO NOTHING`
	_, err := db.pool.Exec(ctx, query)
	return err
}

// User repository methods

func (db *DB) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, password_hash, full_name, email, role, is_enabled, last_login_at, created_at, updated_at
		FROM users
		WHERE LOWER(username) = LOWER($1)`

	var u models.User
	var lastLogin *time.Time
	err := db.pool.QueryRow(ctx, query, username).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.FullName, &u.Email,
		&u.Role, &u.IsEnabled, &lastLogin, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.LastLoginAt = lastLogin
	return &u, nil
}

func (db *DB) UpdateUserLastLogin(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1`
	_, err := db.pool.Exec(ctx, query, id)
	return err
}

func (db *DB) SeedDefaultUser(ctx context.Context, username, password string) error {
	var count int
	if err := db.pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	query := `
		INSERT INTO users (username, password_hash, full_name, email, role, is_enabled)
		VALUES ($1, $2, 'Security Administrator', 'admin@syslog.local', 'Super Administrator', true)
		ON CONFLICT (username) DO NOTHING`
	_, err = db.pool.Exec(ctx, query, username, string(hash))
	return err
}

func (db *DB) ListUsers(ctx context.Context) ([]models.User, error) {
	query := `
		SELECT id, username, full_name, email, role, is_enabled, last_login_at, created_at, updated_at
		FROM users
		ORDER BY created_at ASC`

	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.User
	for rows.Next() {
		var u models.User
		var lastLogin *time.Time
		err := rows.Scan(
			&u.ID, &u.Username, &u.FullName, &u.Email,
			&u.Role, &u.IsEnabled, &lastLogin, &u.CreatedAt, &u.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		u.LastLoginAt = lastLogin
		list = append(list, u)
	}
	return list, nil
}

func (db *DB) CreateUser(ctx context.Context, u *models.User, plainPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	query := `
		INSERT INTO users (username, password_hash, full_name, email, role, is_enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`

	return db.pool.QueryRow(ctx, query,
		u.Username, string(hash), u.FullName, u.Email, u.Role, u.IsEnabled,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
}

func (db *DB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := db.pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	return err
}

func (db *DB) ToggleUserStatus(ctx context.Context, id uuid.UUID) (bool, error) {
	var newState bool
	query := `
		UPDATE users
		SET is_enabled = NOT is_enabled, updated_at = NOW()
		WHERE id = $1
		RETURNING is_enabled`
	err := db.pool.QueryRow(ctx, query, id).Scan(&newState)
	return newState, err
}

func (db *DB) ResetUserPassword(ctx context.Context, id uuid.UUID, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	query := `
		UPDATE users
		SET password_hash = $1,
		    updated_at = NOW()
		WHERE id = $2`

	tag, err := db.pool.Exec(ctx, query, string(hash), id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// EnsureSIEMSchema creates SIEM rules, alerts, and notes tables if they don't exist
func (db *DB) EnsureSIEMSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS siem_rules (
		id VARCHAR(64) PRIMARY KEY,
		name VARCHAR(128) NOT NULL,
		description TEXT DEFAULT '',
		severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
		risk_score INT NOT NULL DEFAULT 50,
		category VARCHAR(64) NOT NULL DEFAULT 'general',
		threshold INT NOT NULL DEFAULT 5,
		timeframe_seconds INT NOT NULL DEFAULT 300,
		group_by TEXT[] DEFAULT '{}',
		mitre_tactic VARCHAR(128) DEFAULT '',
		mitre_technique VARCHAR(64) DEFAULT '',
		is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
		match_category VARCHAR(64) DEFAULT '',
		match_action VARCHAR(64) DEFAULT '',
		match_outcome VARCHAR(64) DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS siem_alerts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		rule_id VARCHAR(64) REFERENCES siem_rules(id) ON DELETE SET NULL,
		rule_name VARCHAR(128) NOT NULL,
		severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
		risk_score INT NOT NULL DEFAULT 50,
		category VARCHAR(64) NOT NULL DEFAULT 'general',
		status VARCHAR(32) NOT NULL DEFAULT 'NEW',
		source_ip VARCHAR(64) DEFAULT '',
		destination_ip VARCHAR(64) DEFAULT '',
		username VARCHAR(128) DEFAULT '',
		device_name VARCHAR(128) DEFAULT '',
		event_count INT NOT NULL DEFAULT 1,
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		mitre_tactic VARCHAR(128) DEFAULT '',
		mitre_technique VARCHAR(64) DEFAULT '',
		summary TEXT NOT NULL,
		evidence_logs JSONB DEFAULT '[]'::jsonb,
		assigned_to VARCHAR(128) DEFAULT 'Unassigned',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_siem_alerts_status ON siem_alerts(status);
	CREATE INDEX IF NOT EXISTS idx_siem_alerts_severity ON siem_alerts(severity);
	CREATE INDEX IF NOT EXISTS idx_siem_alerts_created ON siem_alerts(created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_siem_alerts_src_ip ON siem_alerts(source_ip);
	CREATE INDEX IF NOT EXISTS idx_siem_alerts_user ON siem_alerts(username);

	CREATE TABLE IF NOT EXISTS siem_incident_notes (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		alert_id UUID NOT NULL REFERENCES siem_alerts(id) ON DELETE CASCADE,
		author VARCHAR(128) NOT NULL,
		note TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_siem_notes_alert ON siem_incident_notes(alert_id);

	INSERT INTO siem_rules (id, name, description, severity, risk_score, category, threshold, timeframe_seconds, group_by, mitre_tactic, mitre_technique, is_enabled, match_category, match_action, match_outcome)
	VALUES
	('AUTH-001', 'Multiple Failed Logins (Brute Force)', 'Detects multiple failed login attempts from a single source within a short time window', 'HIGH', 75, 'authentication', 5, 180, ARRAY['source_ip'], 'Credential Access', 'T1110', TRUE, 'authentication', 'login-failed', 'failure'),
	('AUTH-002', 'Multi-Account Password Spraying', 'Detects failed authentication against multiple different user accounts from the same source IP', 'HIGH', 80, 'authentication', 3, 300, ARRAY['source_ip'], 'Credential Access', 'T1110.003', TRUE, 'authentication', 'login-failed', 'failure'),
	('NET-001', 'Horizontal Port Scan / Reconnaissance', 'Detects a single source IP probing or getting dropped across multiple connection attempts', 'MEDIUM', 55, 'network', 10, 60, ARRAY['source_ip'], 'Discovery', 'T1046', TRUE, 'network', 'connection-denied', 'blocked'),
	('NET-002', 'Perimeter Firewall Denial Flood', 'High volume of blocked packets detected across a firewall perimeter device', 'HIGH', 70, 'network', 25, 60, ARRAY['device_name'], 'Impact', 'T1499', TRUE, 'network', 'connection-denied', 'blocked'),
	('SYS-001', 'Privilege Escalation Failure (Sudo / Su)', 'Multiple failed administrative privilege escalation attempts by a user', 'HIGH', 85, 'system', 3, 300, ARRAY['username'], 'Privilege Escalation', 'T1548.003', TRUE, 'system', 'privilege-escalation', 'failure'),
	('SYS-002', 'Local Account Creation / Persistence', 'Detects creation of a new local user account', 'MEDIUM', 60, 'configuration', 1, 60, ARRAY['device_name'], 'Persistence', 'T1136.001', TRUE, 'configuration', 'account-created', 'success'),
	('THREAT-001', 'Perimeter Threat / Exploit Blocked', 'Intrusion prevention or antivirus subsystem blocked a known exploit or malware delivery attempt', 'CRITICAL', 95, 'threat', 1, 60, ARRAY['source_ip'], 'Initial Access', 'T1190', TRUE, 'threat', 'malware-blocked', 'blocked')
	ON CONFLICT (id) DO NOTHING;
	`
	_, err := db.pool.Exec(ctx, schema)
	return err
}

// ListSIEMRules returns all defined detection rules
func (db *DB) ListSIEMRules(ctx context.Context) ([]models.SIEMRule, error) {
	query := `
		SELECT id, name, description, severity, risk_score, category, threshold,
		       timeframe_seconds, group_by, mitre_tactic, mitre_technique,
		       is_enabled, match_category, match_action, match_outcome, created_at, updated_at
		FROM siem_rules
		ORDER BY id ASC`

	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.SIEMRule
	for rows.Next() {
		var r models.SIEMRule
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Severity, &r.RiskScore, &r.Category,
			&r.Threshold, &r.TimeframeSeconds, &r.GroupBy, &r.MitreTactic, &r.MitreTechnique,
			&r.IsEnabled, &r.MatchCategory, &r.MatchAction, &r.MatchOutcome, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// ToggleSIEMRule toggles an active detection rule
func (db *DB) ToggleSIEMRule(ctx context.Context, ruleID string, enabled bool) error {
	query := `UPDATE siem_rules SET is_enabled = $1, updated_at = NOW() WHERE id = $2`
	_, err := db.pool.Exec(ctx, query, enabled, ruleID)
	return err
}

// CreateOrUpdateSIEMAlert inserts a new alert or updates an existing alert in the database
func (db *DB) CreateOrUpdateSIEMAlert(ctx context.Context, alert *models.SIEMAlert) (*models.SIEMAlert, error) {
	evidenceJSON, _ := json.Marshal(alert.EvidenceLogs)

	query := `
		INSERT INTO siem_alerts (
			id, rule_id, rule_name, severity, risk_score, category, status,
			source_ip, destination_ip, username, device_name, event_count,
			first_seen, last_seen, mitre_tactic, mitre_technique, summary,
			evidence_logs, assigned_to, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
		ON CONFLICT (id) DO UPDATE SET
			event_count = EXCLUDED.event_count,
			last_seen = EXCLUDED.last_seen,
			evidence_logs = EXCLUDED.evidence_logs,
			updated_at = NOW()
		RETURNING id, created_at, updated_at`

	err := db.pool.QueryRow(ctx, query,
		alert.ID, alert.RuleID, alert.RuleName, alert.Severity, alert.RiskScore, alert.Category, alert.Status,
		alert.SourceIP, alert.DestinationIP, alert.Username, alert.DeviceName, alert.EventCount,
		alert.FirstSeen, alert.LastSeen, alert.MitreTactic, alert.MitreTechnique, alert.Summary,
		evidenceJSON, alert.AssignedTo, alert.CreatedAt, alert.UpdatedAt,
	).Scan(&alert.ID, &alert.CreatedAt, &alert.UpdatedAt)

	return alert, err
}

// ListSIEMAlerts lists alerts with optional filtering and pagination
func (db *DB) ListSIEMAlerts(ctx context.Context, status, severity, search string, limit, offset int) ([]models.SIEMAlert, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	whereClauses := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if status != "" && status != "ALL" {
		whereClauses = append(whereClauses, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}

	if severity != "" && severity != "ALL" {
		whereClauses = append(whereClauses, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, severity)
		argIdx++
	}

	if search != "" {
		like := "%" + search + "%"
		whereClauses = append(whereClauses, fmt.Sprintf("(rule_name ILIKE $%d OR source_ip ILIKE $%d OR username ILIKE $%d OR device_name ILIKE $%d OR summary ILIKE $%d)", argIdx, argIdx, argIdx, argIdx, argIdx))
		args = append(args, like)
		argIdx++
	}

	whereSQL := " WHERE " + fmt.Sprintf("%s", joinWithAND(whereClauses))

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM siem_alerts" + whereSQL
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Fetch page
	query := fmt.Sprintf(`
		SELECT id, rule_id, rule_name, severity, risk_score, category, status,
		       source_ip, destination_ip, username, device_name, event_count,
		       first_seen, last_seen, mitre_tactic, mitre_technique, summary,
		       evidence_logs, assigned_to, created_at, updated_at
		FROM siem_alerts
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereSQL, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var alerts []models.SIEMAlert
	for rows.Next() {
		var a models.SIEMAlert
		var evidenceJSON []byte
		if err := rows.Scan(
			&a.ID, &a.RuleID, &a.RuleName, &a.Severity, &a.RiskScore, &a.Category, &a.Status,
			&a.SourceIP, &a.DestinationIP, &a.Username, &a.DeviceName, &a.EventCount,
			&a.FirstSeen, &a.LastSeen, &a.MitreTactic, &a.MitreTechnique, &a.Summary,
			&evidenceJSON, &a.AssignedTo, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		if len(evidenceJSON) > 0 {
			_ = json.Unmarshal(evidenceJSON, &a.EvidenceLogs)
		}
		alerts = append(alerts, a)
	}

	return alerts, total, nil
}

// GetSIEMAlert retrieves a single alert along with its case investigation notes
func (db *DB) GetSIEMAlert(ctx context.Context, id uuid.UUID) (*models.SIEMAlert, []models.SIEMIncidentNote, error) {
	query := `
		SELECT id, rule_id, rule_name, severity, risk_score, category, status,
		       source_ip, destination_ip, username, device_name, event_count,
		       first_seen, last_seen, mitre_tactic, mitre_technique, summary,
		       evidence_logs, assigned_to, created_at, updated_at
		FROM siem_alerts
		WHERE id = $1`

	var a models.SIEMAlert
	var evidenceJSON []byte

	err := db.pool.QueryRow(ctx, query, id).Scan(
		&a.ID, &a.RuleID, &a.RuleName, &a.Severity, &a.RiskScore, &a.Category, &a.Status,
		&a.SourceIP, &a.DestinationIP, &a.Username, &a.DeviceName, &a.EventCount,
		&a.FirstSeen, &a.LastSeen, &a.MitreTactic, &a.MitreTechnique, &a.Summary,
		&evidenceJSON, &a.AssignedTo, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, nil, err
	}
	if len(evidenceJSON) > 0 {
		_ = json.Unmarshal(evidenceJSON, &a.EvidenceLogs)
	}

	// Fetch notes
	notesQuery := `
		SELECT id, alert_id, author, note, created_at
		FROM siem_incident_notes
		WHERE alert_id = $1
		ORDER BY created_at ASC`

	rows, err := db.pool.Query(ctx, notesQuery, id)
	if err != nil {
		return &a, nil, nil
	}
	defer rows.Close()

	var notes []models.SIEMIncidentNote
	for rows.Next() {
		var n models.SIEMIncidentNote
		if err := rows.Scan(&n.ID, &n.AlertID, &n.Author, &n.Note, &n.CreatedAt); err == nil {
			notes = append(notes, n)
		}
	}

	return &a, notes, nil
}

// UpdateSIEMAlertStatus changes alert triage status and assignment
func (db *DB) UpdateSIEMAlertStatus(ctx context.Context, id uuid.UUID, status, assignedTo string) error {
	query := `UPDATE siem_alerts SET status = $1, assigned_to = $2, updated_at = NOW() WHERE id = $3`
	_, err := db.pool.Exec(ctx, query, status, assignedTo, id)
	return err
}

// AddSIEMIncidentNote appends an analyst case note
func (db *DB) AddSIEMIncidentNote(ctx context.Context, alertID uuid.UUID, author, note string) error {
	query := `INSERT INTO siem_incident_notes (alert_id, author, note) VALUES ($1, $2, $3)`
	_, err := db.pool.Exec(ctx, query, alertID, author, note)
	return err
}

// GetSIEMOverviewStats computes high-level SOC dashboard metrics
func (db *DB) GetSIEMOverviewStats(ctx context.Context) (*models.SIEMOverviewStats, error) {
	stats := &models.SIEMOverviewStats{
		TopAttackers:            []models.KeyValueCount{},
		TopTargetUsers:          []models.KeyValueCount{},
		TopTargetDevices:        []models.KeyValueCount{},
		MitreTacticDistribution: []models.KeyValueCount{},
	}

	// 1. Overall counts
	countsQuery := `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_cnt,
			COUNT(*) FILTER (WHERE severity = 'HIGH') AS high_cnt,
			COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium_cnt,
			COUNT(*) FILTER (WHERE severity = 'LOW') AS low_cnt,
			COUNT(*) FILTER (WHERE status IN ('NEW', 'INVESTIGATING')) AS active_cnt,
			COUNT(*) FILTER (WHERE status = 'RESOLVED') AS resolved_cnt,
			COALESCE(AVG(risk_score), 0)::int AS avg_risk
		FROM siem_alerts`

	_ = db.pool.QueryRow(ctx, countsQuery).Scan(
		&stats.TotalAlerts, &stats.CriticalAlerts, &stats.HighAlerts,
		&stats.MediumAlerts, &stats.LowAlerts, &stats.ActiveIncidents,
		&stats.ResolvedIncidents, &stats.MeanRiskScore,
	)

	// 2. Top Attackers (Source IP)
	attackersQuery := `
		SELECT source_ip, COUNT(*) AS cnt
		FROM siem_alerts
		WHERE source_ip <> '' AND source_ip IS NOT NULL
		GROUP BY source_ip
		ORDER BY cnt DESC
		LIMIT 5`
	if rows, err := db.pool.Query(ctx, attackersQuery); err == nil {
		for rows.Next() {
			var pair models.KeyValueCount
			if err := rows.Scan(&pair.Key, &pair.Count); err == nil {
				stats.TopAttackers = append(stats.TopAttackers, pair)
			}
		}
		rows.Close()
	}

	// 3. Top Targeted Users
	usersQuery := `
		SELECT username, COUNT(*) AS cnt
		FROM siem_alerts
		WHERE username <> '' AND username IS NOT NULL
		GROUP BY username
		ORDER BY cnt DESC
		LIMIT 5`
	if rows, err := db.pool.Query(ctx, usersQuery); err == nil {
		for rows.Next() {
			var pair models.KeyValueCount
			if err := rows.Scan(&pair.Key, &pair.Count); err == nil {
				stats.TopTargetUsers = append(stats.TopTargetUsers, pair)
			}
		}
		rows.Close()
	}

	// 4. Top Targeted Devices
	devicesQuery := `
		SELECT device_name, COUNT(*) AS cnt
		FROM siem_alerts
		WHERE device_name <> '' AND device_name IS NOT NULL
		GROUP BY device_name
		ORDER BY cnt DESC
		LIMIT 5`
	if rows, err := db.pool.Query(ctx, devicesQuery); err == nil {
		for rows.Next() {
			var pair models.KeyValueCount
			if err := rows.Scan(&pair.Key, &pair.Count); err == nil {
				stats.TopTargetDevices = append(stats.TopTargetDevices, pair)
			}
		}
		rows.Close()
	}

	// 5. MITRE Tactic Distribution
	mitreQuery := `
		SELECT mitre_tactic, COUNT(*) AS cnt
		FROM siem_alerts
		WHERE mitre_tactic <> '' AND mitre_tactic IS NOT NULL
		GROUP BY mitre_tactic
		ORDER BY cnt DESC
		LIMIT 6`
	if rows, err := db.pool.Query(ctx, mitreQuery); err == nil {
		for rows.Next() {
			var pair models.KeyValueCount
			if err := rows.Scan(&pair.Key, &pair.Count); err == nil {
				stats.MitreTacticDistribution = append(stats.MitreTacticDistribution, pair)
			}
		}
		rows.Close()
	}

	return stats, nil
}

func joinWithAND(clauses []string) string {
	if len(clauses) == 0 {
		return "1=1"
	}
	res := clauses[0]
	for i := 1; i < len(clauses); i++ {
		res += " AND " + clauses[i]
	}
	return res
}
