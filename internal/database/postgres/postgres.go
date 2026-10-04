package postgres

import (
	"context"
	"fmt"
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
	query := `
		INSERT INTO devices (name, ip_address, hostname, description, vendor, device_type,
		                     group_id, site_location, expected_protocol, expected_port,
		                     is_enabled, retention_days, timestamping_policy, tags)
		VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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




