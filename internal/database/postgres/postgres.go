package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/syslog-platform/logger/internal/config"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/siem/catalog"
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

	// Ensure auto-discovery schema columns exist
	_, _ = pool.Exec(ctx, `
		ALTER TABLE unregistered_sources ADD COLUMN IF NOT EXISTS hostname VARCHAR(128) DEFAULT '';
		ALTER TABLE unregistered_sources ADD COLUMN IF NOT EXISTS detected_vendor VARCHAR(64) DEFAULT '';
		ALTER TABLE unregistered_sources ADD COLUMN IF NOT EXISTS detected_type VARCHAR(64) DEFAULT '';
		ALTER TABLE unregistered_sources ADD COLUMN IF NOT EXISTS confidence VARCHAR(16) DEFAULT 'MEDIUM';
		ALTER TABLE unregistered_sources ADD COLUMN IF NOT EXISTS tenant_slug VARCHAR(64) DEFAULT 'default';
		CREATE INDEX IF NOT EXISTS idx_unreg_tenant ON unregistered_sources(tenant_slug);

		CREATE TABLE IF NOT EXISTS support_bundles (
			id VARCHAR(64) PRIMARY KEY,
			filename VARCHAR(255) NOT NULL,
			file_path TEXT NOT NULL,
			file_size BIGINT NOT NULL DEFAULT 0,
			sha256 VARCHAR(64) NOT NULL,
			access_passcode VARCHAR(64) NOT NULL,
			access_token VARCHAR(128) NOT NULL,
			requested_by VARCHAR(128) NOT NULL,
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			issue_description TEXT DEFAULT '',
			contact_email VARCHAR(255) DEFAULT '',
			download_count INT NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_support_bundles_created ON support_bundles(created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_support_bundles_token ON support_bundles(access_token);
	`)

	return &DB{pool: pool}, nil
}

func (db *DB) Close() {
	db.pool.Close()
}

func (db *DB) Ping(ctx context.Context) error {
	return db.pool.Ping(ctx)
}

type deviceMaps struct {
	byIP           map[string]*models.Device
	byIPAndTenant  map[string]*models.Device
	byID           map[uuid.UUID]*models.Device
	tenantPolicies map[string]string
}

// DeviceCache maintains lock-free in-memory lookups for active IPs to avoid querying Postgres on every syslog packet
type DeviceCache struct {
	maps    atomic.Pointer[deviceMaps]
	mu      sync.Mutex
	db      *DB
	lastRef time.Time
}

func NewDeviceCache(db *DB) *DeviceCache {
	dc := &DeviceCache{
		db: db,
	}
	empty := &deviceMaps{
		byIP:           make(map[string]*models.Device),
		byIPAndTenant:  make(map[string]*models.Device),
		byID:           make(map[uuid.UUID]*models.Device),
		tenantPolicies: make(map[string]string),
	}
	dc.maps.Store(empty)
	_ = dc.Refresh(context.Background())
	return dc
}

func (dc *DeviceCache) Refresh(ctx context.Context) error {
	devices, err := dc.db.ListDevices(ctx)
	if err != nil {
		return err
	}

	tenants, _ := dc.db.ListTenants(ctx)
	policies := make(map[string]string)
	for _, t := range tenants {
		p := strings.ToLower(t.IngestPolicy)
		if p != "strict" {
			p = "permissive"
		}
		policies[t.Slug] = p
	}

	newByIP := make(map[string]*models.Device, len(devices))
	newByIPAndTenant := make(map[string]*models.Device, len(devices))
	newByID := make(map[uuid.UUID]*models.Device, len(devices))

	for i := range devices {
		d := &devices[i]
		newByIP[d.IPAddress] = d
		tenantKey := d.TenantSlug
		if tenantKey == "" {
			tenantKey = "default"
		}
		newByIPAndTenant[d.IPAddress+"|"+tenantKey] = d
		newByID[d.ID] = d
	}

	dc.mu.Lock()
	dc.maps.Store(&deviceMaps{
		byIP:           newByIP,
		byIPAndTenant:  newByIPAndTenant,
		byID:           newByID,
		tenantPolicies: policies,
	})
	dc.lastRef = time.Now()
	dc.mu.Unlock()
	return nil
}

func (dc *DeviceCache) LookupIP(ipStr string) (*models.Device, bool) {
	m := dc.maps.Load()
	if m == nil {
		return nil, false
	}
	dev, ok := m.byIP[ipStr]
	return dev, ok
}

// LookupIPAndTenant checks device maps with tenant isolation fallback
func (dc *DeviceCache) LookupIPAndTenant(ipStr, tenant string) (*models.Device, bool) {
	m := dc.maps.Load()
	if m == nil {
		return nil, false
	}
	if tenant != "" && tenant != "all" && tenant != "*" {
		if dev, ok := m.byIPAndTenant[ipStr+"|"+tenant]; ok {
			return dev, true
		}
	}
	dev, ok := m.byIP[ipStr]
	return dev, ok
}

// GetTenantIngestPolicy returns whether the tenant enforces 'strict' (whitelist) or 'permissive' (auto-discovery)
func (dc *DeviceCache) GetTenantIngestPolicy(tenant string) string {
	m := dc.maps.Load()
	if m == nil || m.tenantPolicies == nil {
		return "permissive"
	}
	if tenant == "" {
		tenant = "default"
	}
	if p, ok := m.tenantPolicies[tenant]; ok && p != "" {
		return p
	}
	return "permissive"
}

// --- Device Repository Methods ---

func (db *DB) ListDevices(ctx context.Context) ([]models.Device, error) {
	return db.ListDevicesByTenant(ctx, "")
}

// ListDevicesByTenant returns devices owned by the given tenant slug ("" or "all" = every tenant)
func (db *DB) ListDevicesByTenant(ctx context.Context, tenant string) ([]models.Device, error) {
	query := `
		SELECT d.id, d.name, host(d.ip_address), d.hostname, d.description, d.vendor,
		       d.device_type, d.group_id, COALESCE(g.name, ''), d.site_location,
		       d.expected_protocol, d.expected_port, d.is_enabled, d.retention_days,
		       d.timestamping_policy, d.last_seen_at, d.tags, d.created_at, d.updated_at,
		       COALESCE(d.tenant_slug, 'default')
		FROM devices d
		LEFT JOIN device_groups g ON d.group_id = g.id`
	var args []any
	if tenant != "" && tenant != "all" {
		query += ` WHERE COALESCE(d.tenant_slug, 'default') = $1`
		args = append(args, tenant)
	}
	query += ` ORDER BY d.name ASC`

	rows, err := db.pool.Query(ctx, query, args...)
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
			&d.TenantSlug,
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
	if d.TenantSlug == "" {
		d.TenantSlug = "default"
	}

	query := `
		INSERT INTO devices (name, ip_address, hostname, description, vendor, device_type,
		                     group_id, site_location, expected_protocol, expected_port,
		                     is_enabled, retention_days, timestamping_policy, tags, tenant_slug)
		VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (ip_address) DO UPDATE
		SET name = EXCLUDED.name,
		    hostname = CASE WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname ELSE devices.hostname END,
		    description = CASE WHEN EXCLUDED.description != '' THEN EXCLUDED.description ELSE devices.description END,
		    vendor = EXCLUDED.vendor,
		    device_type = EXCLUDED.device_type,
		    group_id = COALESCE(EXCLUDED.group_id, devices.group_id),
		    tenant_slug = EXCLUDED.tenant_slug,
		    is_enabled = TRUE,
		    updated_at = NOW()
		RETURNING id, created_at, updated_at`

	err := db.pool.QueryRow(ctx, query,
		d.Name, d.IPAddress, d.Hostname, d.Description, d.Vendor, d.DeviceType,
		d.GroupID, d.SiteLocation, d.ExpectedProtocol, d.ExpectedPort,
		d.IsEnabled, d.RetentionDays, d.TimestampPolicy, d.Tags, d.TenantSlug,
	).Scan(&d.ID, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return err
	}

	// Purge from unregistered sources now that it is officially registered
	_ = db.DeleteUnregisteredSource(ctx, d.IPAddress)
	return nil
}

// UpdateDevice updates an existing registered device, including reassigning its tenant
func (db *DB) UpdateDevice(ctx context.Context, d *models.Device) error {
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
	if d.TenantSlug == "" {
		d.TenantSlug = "default"
	}

	query := `
		UPDATE devices
		SET name = COALESCE(NULLIF($1, ''), name),
		    vendor = COALESCE(NULLIF($2, ''), vendor),
		    device_type = COALESCE(NULLIF($3, ''), device_type),
		    group_id = COALESCE($4, group_id),
		    tenant_slug = $5,
		    updated_at = NOW()
		WHERE id = $6
		RETURNING ip_address::text`
	var ip string
	err := db.pool.QueryRow(ctx, query, d.Name, d.Vendor, d.DeviceType, d.GroupID, d.TenantSlug, d.ID).Scan(&ip)
	if err != nil {
		return err
	}
	d.IPAddress = ip
	return nil
}

func (db *DB) UpdateDeviceLastSeen(ctx context.Context, ipStr string, seenTime time.Time) error {
	query := `UPDATE devices SET last_seen_at = $1 WHERE ip_address = $2::inet`
	_, err := db.pool.Exec(ctx, query, seenTime, ipStr)
	return err
}

// RecordUnregisteredSource upserts an auto-discovered sender
func (db *DB) RecordUnregisteredSource(ctx context.Context, u *models.UnregisteredSource) error {
	tenant := u.TenantSlug
	if tenant == "" {
		tenant = "default"
	}
	query := `
		INSERT INTO unregistered_sources (
			ip_address, first_seen_at, last_seen_at, packet_count, 
			last_raw_sample, detected_facility, detected_severity,
			hostname, detected_vendor, detected_type, confidence, tenant_slug
		)
		VALUES ($1::inet, $2, $2, 1, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (ip_address) DO UPDATE
		SET last_seen_at = EXCLUDED.last_seen_at,
		    packet_count = unregistered_sources.packet_count + 1,
		    last_raw_sample = EXCLUDED.last_raw_sample,
		    detected_facility = EXCLUDED.detected_facility,
		    detected_severity = EXCLUDED.detected_severity,
		    hostname = CASE WHEN EXCLUDED.hostname <> '' THEN EXCLUDED.hostname ELSE unregistered_sources.hostname END,
		    detected_vendor = CASE WHEN EXCLUDED.detected_vendor <> '' AND EXCLUDED.detected_vendor <> 'Generic' THEN EXCLUDED.detected_vendor ELSE unregistered_sources.detected_vendor END,
		    detected_type = CASE WHEN EXCLUDED.detected_type <> '' AND EXCLUDED.detected_type <> 'Generic Syslog' THEN EXCLUDED.detected_type ELSE unregistered_sources.detected_type END,
		    confidence = CASE WHEN EXCLUDED.confidence = 'HIGH' THEN 'HIGH' ELSE unregistered_sources.confidence END,
		    tenant_slug = CASE WHEN unregistered_sources.tenant_slug = 'default' AND EXCLUDED.tenant_slug <> 'default' THEN EXCLUDED.tenant_slug ELSE unregistered_sources.tenant_slug END`

	_, err := db.pool.Exec(ctx, query,
		u.IPAddress, u.LastSeenAt, u.LastRawSample, u.DetectedFacility, u.DetectedSeverity,
		u.Hostname, u.DetectedVendor, u.DetectedType, u.Confidence, tenant,
	)
	return err
}

// DeleteUnregisteredSource deletes an IP from auto-discovered sources
func (db *DB) DeleteUnregisteredSource(ctx context.Context, ipStr string) error {
	query := `DELETE FROM unregistered_sources WHERE ip_address = $1::inet`
	_, err := db.pool.Exec(ctx, query, ipStr)
	return err
}

func (db *DB) ListUnregisteredSources(ctx context.Context) ([]models.UnregisteredSource, error) {
	return db.ListUnregisteredSourcesByTenant(ctx, "")
}

// ListUnregisteredSourcesByTenant returns auto-discovered sources optionally filtered by tenant
func (db *DB) ListUnregisteredSourcesByTenant(ctx context.Context, tenant string) ([]models.UnregisteredSource, error) {
	whereClauses := []string{"d.id IS NULL"}
	args := []any{}
	if tenant != "" && tenant != "all" && tenant != "*" {
		whereClauses = append(whereClauses, fmt.Sprintf("(u.tenant_slug = $%d OR (u.tenant_slug = 'default' AND $%d = 'default'))", len(args)+1, len(args)+1))
		args = append(args, tenant)
	}

	query := `
		SELECT host(u.ip_address), u.first_seen_at, u.last_seen_at, u.packet_count, 
		       u.last_raw_sample, u.detected_facility, u.detected_severity,
		       coalesce(u.hostname, ''), coalesce(u.detected_vendor, 'Generic'), 
		       coalesce(u.detected_type, 'Generic Syslog'), coalesce(u.confidence, 'LOW'),
		       coalesce(u.tenant_slug, 'default')
		FROM unregistered_sources u
		LEFT JOIN devices d ON u.ip_address = d.ip_address
		WHERE ` + strings.Join(whereClauses, " AND ") + `
		ORDER BY u.last_seen_at DESC LIMIT 100`

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.UnregisteredSource
	for rows.Next() {
		var u models.UnregisteredSource
		if err := rows.Scan(
			&u.IPAddress, &u.FirstSeenAt, &u.LastSeenAt, &u.PacketCount, 
			&u.LastRawSample, &u.DetectedFacility, &u.DetectedSeverity,
			&u.Hostname, &u.DetectedVendor, &u.DetectedType, &u.Confidence,
			&u.TenantSlug,
		); err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, nil
}

// UpdateDeviceTypeAndVendor updates vendor and device_type for an asset
func (db *DB) UpdateDeviceTypeAndVendor(ctx context.Context, id uuid.UUID, vendor, deviceType string) error {
	query := `UPDATE devices SET vendor = $1, device_type = $2, updated_at = NOW() WHERE id = $3`
	_, err := db.pool.Exec(ctx, query, vendor, deviceType, id)
	return err
}

// LogArchive methods
func (db *DB) CreateArchiveRecord(ctx context.Context, a *models.LogArchive) error {
	tenant := a.Tenant
	if tenant == "" {
		tenant = "default"
	}
	query := `
		INSERT INTO log_archives (archive_name, start_timestamp, end_timestamp, record_count,
		                          archive_path, archive_size, hash_algorithm, hash_value, timestamp_status, tenant_slug)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (archive_name) DO UPDATE SET
			record_count = EXCLUDED.record_count,
			archive_path = EXCLUDED.archive_path,
			archive_size = EXCLUDED.archive_size,
			hash_value = EXCLUDED.hash_value,
			timestamp_status = EXCLUDED.timestamp_status
		RETURNING id, created_at`

	return db.pool.QueryRow(ctx, query,
		a.ArchiveName, a.StartTimestamp, a.EndTimestamp, a.RecordCount,
		a.ArchivePath, a.ArchiveSize, a.HashAlgorithm, a.HashValue, a.TimestampStatus, tenant,
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

func (db *DB) ListArchives(ctx context.Context, tenant string, limit int) ([]models.LogArchive, error) {
	if limit <= 0 {
		limit = 50
	}
	var query string
	var rows pgx.Rows
	var err error

	if tenant != "" && tenant != "all" && tenant != "*" {
		query = `
			SELECT id, archive_name, start_timestamp, end_timestamp, record_count, archive_path,
			       archive_size, hash_algorithm, hash_value, timestamp_status, timestamp_request_time,
			       timestamp_completion_time, timestamp_evidence_path, retry_count, last_error, created_at,
			       COALESCE(tenant_slug, 'default')
			FROM log_archives
			WHERE COALESCE(tenant_slug, 'default') = $1
			ORDER BY start_timestamp DESC
			LIMIT $2`
		rows, err = db.pool.Query(ctx, query, tenant, limit)
	} else {
		query = `
			SELECT id, archive_name, start_timestamp, end_timestamp, record_count, archive_path,
			       archive_size, hash_algorithm, hash_value, timestamp_status, timestamp_request_time,
			       timestamp_completion_time, timestamp_evidence_path, retry_count, last_error, created_at,
			       COALESCE(tenant_slug, 'default')
			FROM log_archives
			ORDER BY start_timestamp DESC
			LIMIT $1`
		rows, err = db.pool.Query(ctx, query, limit)
	}
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
			&a.Tenant,
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
		       timestamp_completion_time, timestamp_evidence_path, retry_count, last_error, created_at,
		       COALESCE(tenant_slug, 'default')
		FROM log_archives
		WHERE id = $1`

	var a models.LogArchive
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&a.ID, &a.ArchiveName, &a.StartTimestamp, &a.EndTimestamp, &a.RecordCount, &a.ArchivePath,
		&a.ArchiveSize, &a.HashAlgorithm, &a.HashValue, &a.TimestampStatus, &a.TimestampRequestTime,
		&a.TimestampCompletionTime, &a.TimestampEvidencePath, &a.RetryCount, &a.LastError, &a.CreatedAt,
		&a.Tenant,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ArchiveJob & Evidence methods (Law 5651 & TÜBİTAK Zamane KS Pipeline)
func (db *DB) CreateArchiveJob(ctx context.Context, job *models.ArchiveJob) error {
	tenant := job.TenantSlug
	if tenant == "" {
		tenant = "default"
	}
	query := `
		INSERT INTO archive_jobs (tenant_slug, request_type, period_start, period_end, time_basis,
		                          idempotency_key, requester, reason, state, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (idempotency_key) DO UPDATE
		SET updated_at = NOW()
		RETURNING id, created_at, updated_at, state`

	return db.pool.QueryRow(ctx, query,
		tenant, job.RequestType, job.PeriodStart, job.PeriodEnd, job.TimeBasis,
		job.IdempotencyKey, job.Requester, job.Reason, job.State,
	).Scan(&job.ID, &job.CreatedAt, &job.UpdatedAt, &job.State)
}

func (db *DB) GetArchiveJob(ctx context.Context, id uuid.UUID) (*models.ArchiveJob, error) {
	query := `
		SELECT id, tenant_slug, request_type, period_start, period_end, time_basis,
		       idempotency_key, requester, reason, lease_until, attempts, state, error_message,
		       created_at, updated_at
		FROM archive_jobs
		WHERE id = $1`

	var j models.ArchiveJob
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&j.ID, &j.TenantSlug, &j.RequestType, &j.PeriodStart, &j.PeriodEnd, &j.TimeBasis,
		&j.IdempotencyKey, &j.Requester, &j.Reason, &j.LeaseUntil, &j.Attempts, &j.State, &j.ErrorMessage,
		&j.CreatedAt, &j.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (db *DB) UpdateArchiveJobState(ctx context.Context, id uuid.UUID, state, errorMsg string) error {
	query := `
		UPDATE archive_jobs
		SET state = $1, error_message = $2, updated_at = NOW()
		WHERE id = $3`
	_, err := db.pool.Exec(ctx, query, state, errorMsg, id)
	return err
}

// ClaimNextArchiveJob atomically locks and claims the oldest pending or expired archive job using FOR UPDATE SKIP LOCKED.
func (db *DB) ClaimNextArchiveJob(ctx context.Context, workerID string, leaseDuration time.Duration) (*models.ArchiveJob, error) {
	if leaseDuration <= 0 {
		leaseDuration = 5 * time.Minute
	}

	query := `
		UPDATE archive_jobs
		SET state = 'BUILDING',
		    lease_until = NOW() + $1::interval,
		    attempts = attempts + 1,
		    updated_at = NOW()
		WHERE id = (
			SELECT id
			FROM archive_jobs
			WHERE (state = 'QUEUED' OR (state = 'BUILDING' AND lease_until < NOW()))
			ORDER BY period_start ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, tenant_slug, request_type, period_start, period_end, time_basis,
		          idempotency_key, requester, reason, lease_until, attempts, state, error_message,
		          created_at, updated_at`

	intervalStr := fmt.Sprintf("%d seconds", int(leaseDuration.Seconds()))
	var j models.ArchiveJob
	err := db.pool.QueryRow(ctx, query, intervalStr).Scan(
		&j.ID, &j.TenantSlug, &j.RequestType, &j.PeriodStart, &j.PeriodEnd, &j.TimeBasis,
		&j.IdempotencyKey, &j.Requester, &j.Reason, &j.LeaseUntil, &j.Attempts, &j.State, &j.ErrorMessage,
		&j.CreatedAt, &j.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No eligible job available
		}
		return nil, err
	}
	return &j, nil
}

func (db *DB) ListArchiveJobs(ctx context.Context, tenant string, limit int) ([]models.ArchiveJob, error) {
	if limit <= 0 {
		limit = 50
	}
	var query string
	var rows pgx.Rows
	var err error

	if tenant == "" || tenant == "all" {
		query = `
			SELECT id, tenant_slug, request_type, period_start, period_end, time_basis,
			       idempotency_key, requester, reason, lease_until, attempts, state, error_message,
			       created_at, updated_at
			FROM archive_jobs
			ORDER BY created_at DESC
			LIMIT $1`
		rows, err = db.pool.Query(ctx, query, limit)
	} else {
		query = `
			SELECT id, tenant_slug, request_type, period_start, period_end, time_basis,
			       idempotency_key, requester, reason, lease_until, attempts, state, error_message,
			       created_at, updated_at
			FROM archive_jobs
			WHERE tenant_slug = $1
			ORDER BY created_at DESC
			LIMIT $2`
		rows, err = db.pool.Query(ctx, query, tenant, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.ArchiveJob
	for rows.Next() {
		var j models.ArchiveJob
		if err := rows.Scan(
			&j.ID, &j.TenantSlug, &j.RequestType, &j.PeriodStart, &j.PeriodEnd, &j.TimeBasis,
			&j.IdempotencyKey, &j.Requester, &j.Reason, &j.LeaseUntil, &j.Attempts, &j.State, &j.ErrorMessage,
			&j.CreatedAt, &j.UpdatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, j)
	}
	return list, nil
}

func (db *DB) SaveArchiveManifest(ctx context.Context, m *models.ArchiveManifest) error {
	query := `
		INSERT INTO archive_manifests (archive_id, manifest_content, manifest_sha256, payload_sha256, schema_version, prior_manifest_sha256, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		RETURNING id, created_at`
	return db.pool.QueryRow(ctx, query,
		m.ArchiveID, m.ManifestContent, m.ManifestSHA256, m.PayloadSHA256, m.SchemaVersion, m.PriorManifestSHA256,
	).Scan(&m.ID, &m.CreatedAt)
}

func (db *DB) SaveArchiveTimestamp(ctx context.Context, ts *models.ArchiveTimestamp) error {
	query := `
		INSERT INTO archive_timestamps (manifest_id, request_id, token_bytes, tsa_identity, tsa_policy, tsa_serial, tsa_time,
		                                imprint_algorithm, signature_algorithm, verification_outcome, verification_details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		RETURNING id, created_at`
	return db.pool.QueryRow(ctx, query,
		ts.ManifestID, ts.RequestID, ts.TokenBytes, ts.TSAIdentity, ts.TSAPolicy, ts.TSASerial, ts.TSATime,
		ts.ImprintAlgorithm, ts.SignatureAlgorithm, ts.VerificationOutcome, ts.VerificationDetails,
	).Scan(&ts.ID, &ts.CreatedAt)
}

// AuditLog recording
func (db *DB) InsertAuditLog(ctx context.Context, a *models.AuditLog) error {
	ipStr := strings.TrimSpace(a.SourceIP)
	if h, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = h
	}
	if parsed := net.ParseIP(ipStr); parsed == nil {
		ipStr = "127.0.0.1"
	}
	tenant := strings.TrimSpace(a.TenantSlug)
	if tenant == "" {
		tenant = "default"
	}
	detailsJSON, _ := json.Marshal(a.Details)
	if len(detailsJSON) == 0 {
		detailsJSON = []byte("{}")
	}
	query := `
		INSERT INTO audit_logs (user_id, username, source_ip, action, resource, result, details, tenant_slug)
		VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8)
		RETURNING id, created_at`

	return db.pool.QueryRow(ctx, query,
		a.UserID, a.Username, ipStr, a.Action, a.Resource, a.Result, detailsJSON, tenant,
	).Scan(&a.ID, &a.CreatedAt)
}

// ListAuditLogs retrieves audit records with optional tenant, action, search filters and pagination
func (db *DB) ListAuditLogs(ctx context.Context, tenant, action, search string, limit, offset int) ([]models.AuditLog, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	whereClauses := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if tenant != "" && tenant != "all" && tenant != "*" {
		whereClauses = append(whereClauses, fmt.Sprintf("COALESCE(tenant_slug, 'default') = $%d", argIdx))
		args = append(args, tenant)
		argIdx++
	}

	if action != "" && action != "ALL" {
		whereClauses = append(whereClauses, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, action)
		argIdx++
	}

	if search != "" {
		like := "%" + search + "%"
		whereClauses = append(whereClauses, fmt.Sprintf("(username ILIKE $%d OR resource ILIKE $%d OR host(source_ip) ILIKE $%d OR action ILIKE $%d)", argIdx, argIdx, argIdx, argIdx))
		args = append(args, like)
		argIdx++
	}

	whereSQL := " WHERE " + joinWithAND(whereClauses)

	var total int
	countQuery := "SELECT COUNT(*) FROM audit_logs" + whereSQL
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT id, user_id, username, host(source_ip), action, resource, result, COALESCE(details, '{}'::jsonb), COALESCE(tenant_slug, 'default'), created_at
		FROM audit_logs
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereSQL, argIdx, argIdx+1)

	args = append(args, limit, offset)
	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var a models.AuditLog
		var rawDetails []byte
		if err := rows.Scan(
			&a.ID, &a.UserID, &a.Username, &a.SourceIP, &a.Action, &a.Resource, &a.Result, &rawDetails, &a.TenantSlug, &a.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		if len(rawDetails) > 0 {
			_ = json.Unmarshal(rawDetails, &a.Details)
		}
		logs = append(logs, a)
	}
	return logs, total, nil
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
		SELECT id, username, password_hash, full_name, email, role, is_enabled,
		       COALESCE(auth_source, 'local'), COALESCE(mfa_enabled, false),
		       COALESCE(mfa_secret, ''), COALESCE(mfa_recovery_codes, '{}'),
		       mfa_enrolled_at, COALESCE(mfa_provider, 'totp'),
		       last_login_at, created_at, updated_at,
		       COALESCE(tenant_slug, 'default'), COALESCE(is_tenant_admin, false)
		FROM users
		WHERE LOWER(username) = LOWER($1)`

	var u models.User
	var lastLogin *time.Time
	var enrolledAt *time.Time
	err := db.pool.QueryRow(ctx, query, username).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.FullName, &u.Email,
		&u.Role, &u.IsEnabled, &u.AuthSource, &u.MFAEnabled,
		&u.MFASecret, &u.MFARecoveryCodes, &enrolledAt, &u.MFAProvider,
		&lastLogin, &u.CreatedAt, &u.UpdatedAt,
		&u.TenantSlug, &u.IsTenantAdmin,
	)
	if err != nil {
		return nil, err
	}
	u.LastLoginAt = lastLogin
	u.MFAEnrolledAt = enrolledAt
	return &u, nil
}

func (db *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, username, password_hash, full_name, email, role, is_enabled,
		       COALESCE(auth_source, 'local'), COALESCE(mfa_enabled, false),
		       COALESCE(mfa_secret, ''), COALESCE(mfa_recovery_codes, '{}'),
		       mfa_enrolled_at, COALESCE(mfa_provider, 'totp'),
		       last_login_at, created_at, updated_at,
		       COALESCE(tenant_slug, 'default'), COALESCE(is_tenant_admin, false)
		FROM users
		WHERE id = $1`

	var u models.User
	var lastLogin *time.Time
	var enrolledAt *time.Time
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.FullName, &u.Email,
		&u.Role, &u.IsEnabled, &u.AuthSource, &u.MFAEnabled,
		&u.MFASecret, &u.MFARecoveryCodes, &enrolledAt, &u.MFAProvider,
		&lastLogin, &u.CreatedAt, &u.UpdatedAt,
		&u.TenantSlug, &u.IsTenantAdmin,
	)
	if err != nil {
		return nil, err
	}
	u.LastLoginAt = lastLogin
	u.MFAEnrolledAt = enrolledAt
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
		INSERT INTO users (username, password_hash, full_name, email, role, is_enabled, auth_source)
		VALUES ($1, $2, 'Security Administrator', 'admin@syslog.local', 'Super Administrator', true, 'local')
		ON CONFLICT (username) DO NOTHING`
	_, err = db.pool.Exec(ctx, query, username, string(hash))
	return err
}

func (db *DB) ListUsers(ctx context.Context, tenant string) ([]models.User, error) {
	query := `
		SELECT id, username, full_name, email, role, is_enabled,
		       COALESCE(auth_source, 'local'), COALESCE(mfa_enabled, false),
		       mfa_enrolled_at, COALESCE(mfa_provider, 'totp'),
		       last_login_at, created_at, updated_at,
		       COALESCE(tenant_slug, 'default'), COALESCE(is_tenant_admin, false)
		FROM users`

	var rows pgx.Rows
	var err error
	if tenant != "" && tenant != "all" && tenant != "*" {
		query += ` WHERE COALESCE(tenant_slug, 'default') = $1 ORDER BY created_at ASC`
		rows, err = db.pool.Query(ctx, query, tenant)
	} else {
		query += ` ORDER BY created_at ASC`
		rows, err = db.pool.Query(ctx, query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.User
	for rows.Next() {
		var u models.User
		var lastLogin *time.Time
		var enrolledAt *time.Time
		err := rows.Scan(
			&u.ID, &u.Username, &u.FullName, &u.Email,
			&u.Role, &u.IsEnabled, &u.AuthSource, &u.MFAEnabled,
			&enrolledAt, &u.MFAProvider,
			&lastLogin, &u.CreatedAt, &u.UpdatedAt,
			&u.TenantSlug, &u.IsTenantAdmin,
		)
		if err != nil {
			return nil, err
		}
		u.LastLoginAt = lastLogin
		u.MFAEnrolledAt = enrolledAt
		list = append(list, u)
	}
	return list, nil
}

func (db *DB) CreateUser(ctx context.Context, u *models.User, plainPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	if u.AuthSource == "" {
		u.AuthSource = "local"
	}
	if u.MFAProvider == "" {
		u.MFAProvider = "totp"
	}
	if u.TenantSlug == "" {
		u.TenantSlug = "default"
	}

	query := `
		INSERT INTO users (username, password_hash, full_name, email, role, is_enabled, auth_source, mfa_enabled, mfa_provider, tenant_slug, is_tenant_admin)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at`

	return db.pool.QueryRow(ctx, query,
		u.Username, string(hash), u.FullName, u.Email, u.Role, u.IsEnabled, u.AuthSource, u.MFAEnabled, u.MFAProvider,
		u.TenantSlug, u.IsTenantAdmin,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
}

// UpsertADUser creates or updates a synchronized Active Directory user
func (db *DB) UpsertADUser(ctx context.Context, username, fullName, email, role string) (*models.User, error) {
	if role == "" {
		role = "Security Analyst"
	}
	query := `
		INSERT INTO users (username, password_hash, full_name, email, role, is_enabled, auth_source)
		VALUES ($1, 'AD_MANAGED_ACCOUNT', $2, $3, $4, true, 'ad')
		ON CONFLICT (username) DO UPDATE
		SET full_name = EXCLUDED.full_name,
		    email = CASE WHEN EXCLUDED.email <> '' THEN EXCLUDED.email ELSE users.email END,
		    auth_source = 'ad',
		    updated_at = NOW()
		RETURNING id, username, full_name, email, role, is_enabled, auth_source, mfa_enabled, last_login_at, created_at, updated_at`

	var u models.User
	var lastLogin *time.Time
	err := db.pool.QueryRow(ctx, query, username, fullName, email, role).Scan(
		&u.ID, &u.Username, &u.FullName, &u.Email, &u.Role, &u.IsEnabled,
		&u.AuthSource, &u.MFAEnabled, &lastLogin, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.LastLoginAt = lastLogin
	return &u, nil
}

// UpdateUserMFA activates or updates MFA configuration for a user
func (db *DB) UpdateUserMFA(ctx context.Context, id uuid.UUID, enabled bool, secret string, recoveryCodes []string, provider string) error {
	if provider == "" {
		provider = "totp"
	}
	query := `
		UPDATE users
		SET mfa_enabled = $1,
		    mfa_secret = $2,
		    mfa_recovery_codes = $3,
		    mfa_provider = $4,
		    mfa_enrolled_at = CASE WHEN $1 THEN NOW() ELSE NULL END,
		    updated_at = NOW()
		WHERE id = $5`

	_, err := db.pool.Exec(ctx, query, enabled, secret, recoveryCodes, provider, id)
	return err
}

// DisableUserMFA turns off MFA and clears secrets for a user
func (db *DB) DisableUserMFA(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET mfa_enabled = false,
		    mfa_secret = '',
		    mfa_recovery_codes = '{}',
		    mfa_enrolled_at = NULL,
		    updated_at = NOW()
		WHERE id = $1`

	_, err := db.pool.Exec(ctx, query, id)
	return err
}

// ValidateAndConsumeRecoveryCode validates a one-time recovery code and removes it if valid
func (db *DB) ValidateAndConsumeRecoveryCode(ctx context.Context, id uuid.UUID, code string) (bool, error) {
	code = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if code == "" {
		return false, nil
	}

	user, err := db.GetUserByID(ctx, id)
	if err != nil {
		return false, err
	}

	remaining := make([]string, 0, len(user.MFARecoveryCodes))
	matched := false

	for _, stored := range user.MFARecoveryCodes {
		cleanStored := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(stored), "-", ""))
		if cleanStored == code && !matched {
			matched = true
			continue // Consume it
		}
		remaining = append(remaining, stored)
	}

	if !matched {
		return false, nil
	}

	// Persist remaining recovery codes
	query := `UPDATE users SET mfa_recovery_codes = $1, updated_at = NOW() WHERE id = $2`
	_, err = db.pool.Exec(ctx, query, remaining, id)
	return true, err
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

	ALTER TABLE siem_rules ADD COLUMN IF NOT EXISTS priority VARCHAR(16) DEFAULT 'P1';
	ALTER TABLE siem_rules ADD COLUMN IF NOT EXISTS source_ref TEXT DEFAULT '';

	CREATE TABLE IF NOT EXISTS mitre_catalog_cache (
		id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
		payload JSONB NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_siem_alerts_technique ON siem_alerts(mitre_technique);
	CREATE INDEX IF NOT EXISTS idx_siem_alerts_rule_status ON siem_alerts(rule_id, status);
	ALTER TABLE siem_alerts ADD COLUMN IF NOT EXISTS tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default';
	CREATE INDEX IF NOT EXISTS idx_siem_alerts_tenant ON siem_alerts(tenant_slug);

	-- Multi-Tenant Log Archives Isolation
	ALTER TABLE log_archives ADD COLUMN IF NOT EXISTS tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default';
	CREATE INDEX IF NOT EXISTS idx_log_archives_tenant ON log_archives(tenant_slug);

	-- Multi-Factor Authentication (MFA) & Active Directory (AD) Schema Migrations
	ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source VARCHAR(32) DEFAULT 'local';
	ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE;
	ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(128) DEFAULT '';
	ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_codes TEXT[] DEFAULT '{}';
	ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enrolled_at TIMESTAMPTZ;
	ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_provider VARCHAR(32) DEFAULT 'totp';
	`
	if _, err := db.pool.Exec(ctx, schema); err != nil {
		return err
	}

	// Upsert complete 72-rule detection catalog
	for _, r := range catalog.Rules() {
		upsertRule := `
			INSERT INTO siem_rules (
				id, name, description, severity, risk_score, category, priority, source_ref,
				threshold, timeframe_seconds, group_by, mitre_tactic, mitre_technique,
				is_enabled, match_category, match_action, match_outcome
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
			) ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				severity = EXCLUDED.severity,
				risk_score = EXCLUDED.risk_score,
				category = EXCLUDED.category,
				priority = EXCLUDED.priority,
				source_ref = EXCLUDED.source_ref,
				threshold = EXCLUDED.threshold,
				timeframe_seconds = EXCLUDED.timeframe_seconds,
				group_by = EXCLUDED.group_by,
				mitre_tactic = EXCLUDED.mitre_tactic,
				mitre_technique = EXCLUDED.mitre_technique,
				match_category = EXCLUDED.match_category,
				match_action = EXCLUDED.match_action,
				match_outcome = EXCLUDED.match_outcome,
				updated_at = NOW();`
		if _, err := db.pool.Exec(ctx, upsertRule,
			r.ID, r.Name, r.Description, r.Severity, r.RiskScore, r.Category, r.Priority, r.SourceRef,
			r.Threshold, r.TimeframeSeconds, r.GroupBy, r.MitreTactic, r.MitreTechnique,
			r.IsEnabled, r.MatchCategory, r.MatchAction, r.MatchOutcome,
		); err != nil {
			log.Printf("[PostgreSQL] Error seeding SIEM rule %s: %v", r.ID, err)
		}
	}

	return nil
}

// LoadMitreCatalog returns the persisted MITRE ATT&CK catalog snapshot (nil when absent)
func (db *DB) LoadMitreCatalog(ctx context.Context) ([]byte, error) {
	var payload string
	err := db.pool.QueryRow(ctx, `SELECT payload::text FROM mitre_catalog_cache WHERE id = 1`).Scan(&payload)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return []byte(payload), nil
}

// SaveMitreCatalog upserts the MITRE ATT&CK catalog snapshot
func (db *DB) SaveMitreCatalog(ctx context.Context, payload []byte) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO mitre_catalog_cache (id, payload, updated_at) VALUES (1, $1::jsonb, NOW())
		ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()`, string(payload))
	return err
}

// MitreTechniqueAlertStat aggregates alerts per MITRE technique
type MitreTechniqueAlertStat struct {
	Technique string
	Count     int64
	LastSeen  time.Time
}

// ListMitreAlertStats returns alert counters for every technique across all stored alerts
func (db *DB) ListMitreAlertStats(ctx context.Context, tenant string) ([]MitreTechniqueAlertStat, error) {
	var rows pgx.Rows
	var err error
	if tenant != "" && tenant != "all" {
		rows, err = db.pool.Query(ctx, `
			SELECT mitre_technique, COUNT(*), MAX(last_seen)
			FROM siem_alerts
			WHERE mitre_technique <> '' AND COALESCE(tenant_slug, 'default') = $1
			GROUP BY mitre_technique`, tenant)
	} else {
		rows, err = db.pool.Query(ctx, `
			SELECT mitre_technique, COUNT(*), MAX(last_seen)
			FROM siem_alerts
			WHERE mitre_technique <> ''
			GROUP BY mitre_technique`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MitreTechniqueAlertStat
	for rows.Next() {
		var s MitreTechniqueAlertStat
		if err := rows.Scan(&s.Technique, &s.Count, &s.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListSIEMRules returns all defined detection rules
func (db *DB) ListSIEMRules(ctx context.Context) ([]models.SIEMRule, error) {
	query := `
		SELECT id, name, description, severity, risk_score, category, COALESCE(priority, 'P1'), COALESCE(source_ref, ''),
		       threshold, timeframe_seconds, group_by, mitre_tactic, mitre_technique,
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
			&r.Priority, &r.SourceRef,
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

// SetSIEMRulesEnabledState atomically sets is_enabled for the given rule ID sets.
// Unlike BatchUpsertSIEMRules (which deliberately preserves operator-chosen is_enabled
// on conflict), this explicitly overwrites the enable state.
func (db *DB) SetSIEMRulesEnabledState(ctx context.Context, enableIDs, disableIDs []string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if len(enableIDs) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE siem_rules SET is_enabled = TRUE, updated_at = NOW() WHERE id = ANY($1)`, enableIDs); err != nil {
			return fmt.Errorf("enabling rules: %w", err)
		}
	}
	if len(disableIDs) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE siem_rules SET is_enabled = FALSE, updated_at = NOW() WHERE id = ANY($1)`, disableIDs); err != nil {
			return fmt.Errorf("disabling rules: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ToggleTechniqueRules enables or disables all rules associated with a MITRE technique (including sub-techniques)
func (db *DB) ToggleTechniqueRules(ctx context.Context, techniqueID string, enabled bool) (int64, error) {
	query := `UPDATE siem_rules SET is_enabled = $1, updated_at = NOW() WHERE mitre_technique = $2 OR (mitre_technique LIKE $3 AND $4 NOT LIKE '%.%')`
	tag, err := db.pool.Exec(ctx, query, enabled, techniqueID, techniqueID+".%", techniqueID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ToggleAllMitreRules enables or disables all rules with an assigned MITRE technique
func (db *DB) ToggleAllMitreRules(ctx context.Context, enabled bool) (int64, error) {
	query := `UPDATE siem_rules SET is_enabled = $1, updated_at = NOW() WHERE mitre_technique IS NOT NULL AND mitre_technique != ''`
	tag, err := db.pool.Exec(ctx, query, enabled)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// BatchUpsertSIEMRules inserts or updates multiple detection rules in a single transaction
func (db *DB) BatchUpsertSIEMRules(ctx context.Context, rules []models.SIEMRule) error {
	if len(rules) == 0 {
		return nil
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	query := `
		INSERT INTO siem_rules (
			id, name, description, severity, risk_score, category, priority, source_ref,
			threshold, timeframe_seconds, group_by, mitre_tactic, mitre_technique,
			is_enabled, match_category, match_action, match_outcome, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15, $16, $17, $18, $19
		)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			mitre_tactic = EXCLUDED.mitre_tactic,
			mitre_technique = EXCLUDED.mitre_technique,
			source_ref = EXCLUDED.source_ref,
			updated_at = NOW()`

	for _, r := range rules {
		_, err := tx.Exec(ctx, query,
			r.ID, r.Name, r.Description, r.Severity, r.RiskScore, r.Category, r.Priority, r.SourceRef,
			r.Threshold, r.TimeframeSeconds, r.GroupBy, r.MitreTactic, r.MitreTechnique,
			r.IsEnabled, r.MatchCategory, r.MatchAction, r.MatchOutcome, r.CreatedAt, r.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("upsert rule %s: %w", r.ID, err)
		}
	}

	return tx.Commit(ctx)
}

// CreateOrUpdateSIEMAlert inserts a new alert or updates an existing alert in the database
func (db *DB) CreateOrUpdateSIEMAlert(ctx context.Context, alert *models.SIEMAlert) (*models.SIEMAlert, error) {
	evidenceJSON, _ := json.Marshal(alert.EvidenceLogs)
	tenant := alert.Tenant
	if tenant == "" {
		tenant = "default"
	}

	// Ensure referenced rule exists so foreign key constraint siem_alerts_rule_id_fkey is always satisfied
	if alert.RuleID != "" {
		var exists bool
		_ = db.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM siem_rules WHERE id = $1)`, alert.RuleID).Scan(&exists)
		if !exists {
			ruleName := alert.RuleName
			if ruleName == "" {
				ruleName = alert.RuleID
			}
			_, _ = db.pool.Exec(ctx, `
				INSERT INTO siem_rules (id, name, description, severity, risk_score, category, is_enabled, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, TRUE, NOW(), NOW())
				ON CONFLICT (id) DO NOTHING`,
				alert.RuleID, ruleName, "Auto-registered detection rule for endpoint/system telemetry", alert.Severity, alert.RiskScore, alert.Category)
		}
	}

	query := `
		INSERT INTO siem_alerts (
			id, rule_id, rule_name, severity, risk_score, category, status,
			source_ip, destination_ip, username, device_name, event_count,
			first_seen, last_seen, mitre_tactic, mitre_technique, summary,
			evidence_logs, assigned_to, tenant_slug, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
		ON CONFLICT (id) DO UPDATE SET
			event_count = EXCLUDED.event_count,
			last_seen = EXCLUDED.last_seen,
			summary = EXCLUDED.summary,
			evidence_logs = EXCLUDED.evidence_logs,
			updated_at = NOW()
		RETURNING id, created_at, updated_at`

	err := db.pool.QueryRow(ctx, query,
		alert.ID, alert.RuleID, alert.RuleName, alert.Severity, alert.RiskScore, alert.Category, alert.Status,
		alert.SourceIP, alert.DestinationIP, alert.Username, alert.DeviceName, alert.EventCount,
		alert.FirstSeen, alert.LastSeen, alert.MitreTactic, alert.MitreTechnique, alert.Summary,
		evidenceJSON, alert.AssignedTo, tenant, alert.CreatedAt, alert.UpdatedAt,
	).Scan(&alert.ID, &alert.CreatedAt, &alert.UpdatedAt)

	return alert, err
}

// GetActiveSIEMAlertByRuleAndGroup finds the most recent non-resolved alert for a rule, entity, and tenant
func (db *DB) GetActiveSIEMAlertByRuleAndGroup(ctx context.Context, ruleID, groupKey, tenant string) (*models.SIEMAlert, error) {
	query := `
		SELECT id, rule_id, rule_name, severity, risk_score, category, status,
		       source_ip, destination_ip, username, device_name, event_count,
		       first_seen, last_seen, mitre_tactic, mitre_technique, summary,
		       evidence_logs, assigned_to, COALESCE(tenant_slug, 'default'), created_at, updated_at
		FROM siem_alerts
		WHERE rule_id = $1
		  AND (source_ip = $2 OR username = $2 OR device_name = $2 OR $2 = 'global')
		  AND status IN ('NEW', 'IN_PROGRESS')
		  AND last_seen > NOW() - INTERVAL '1 hour'`

	var args []interface{}
	args = append(args, ruleID, groupKey)
	if tenant != "" && tenant != "all" {
		query += " AND COALESCE(tenant_slug, 'default') = $3"
		args = append(args, tenant)
	}
	query += " ORDER BY last_seen DESC LIMIT 1"

	row := db.pool.QueryRow(ctx, query, args...)
	var a models.SIEMAlert
	var evidenceJSON []byte
	err := row.Scan(
		&a.ID, &a.RuleID, &a.RuleName, &a.Severity, &a.RiskScore, &a.Category, &a.Status,
		&a.SourceIP, &a.DestinationIP, &a.Username, &a.DeviceName, &a.EventCount,
		&a.FirstSeen, &a.LastSeen, &a.MitreTactic, &a.MitreTechnique, &a.Summary,
		&evidenceJSON, &a.AssignedTo, &a.Tenant, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if len(evidenceJSON) > 0 {
		_ = json.Unmarshal(evidenceJSON, &a.EvidenceLogs)
	}
	return &a, nil
}

// ListSIEMAlerts lists alerts with optional filtering and pagination
func (db *DB) ListSIEMAlerts(ctx context.Context, tenant, status, severity, search string, limit, offset int) ([]models.SIEMAlert, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	whereClauses := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if tenant != "" && tenant != "all" {
		whereClauses = append(whereClauses, fmt.Sprintf("COALESCE(tenant_slug, 'default') = $%d", argIdx))
		args = append(args, tenant)
		argIdx++
	}

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
		       evidence_logs, assigned_to, COALESCE(tenant_slug, 'default'), created_at, updated_at
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
			&evidenceJSON, &a.AssignedTo, &a.Tenant, &a.CreatedAt, &a.UpdatedAt,
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
		       evidence_logs, assigned_to, COALESCE(tenant_slug, 'default'), created_at, updated_at
		FROM siem_alerts
		WHERE id = $1`

	var a models.SIEMAlert
	var evidenceJSON []byte

	err := db.pool.QueryRow(ctx, query, id).Scan(
		&a.ID, &a.RuleID, &a.RuleName, &a.Severity, &a.RiskScore, &a.Category, &a.Status,
		&a.SourceIP, &a.DestinationIP, &a.Username, &a.DeviceName, &a.EventCount,
		&a.FirstSeen, &a.LastSeen, &a.MitreTactic, &a.MitreTechnique, &a.Summary,
		&evidenceJSON, &a.AssignedTo, &a.Tenant, &a.CreatedAt, &a.UpdatedAt,
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
func (db *DB) GetSIEMOverviewStats(ctx context.Context, tenant string) (*models.SIEMOverviewStats, error) {
	stats := &models.SIEMOverviewStats{
		TopAttackers:            []models.KeyValueCount{},
		TopTargetUsers:          []models.KeyValueCount{},
		TopTargetDevices:        []models.KeyValueCount{},
		MitreTacticDistribution: []models.KeyValueCount{},
	}

	filterByTenant := tenant != "" && tenant != "all"

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

	if filterByTenant {
		countsQuery += ` WHERE COALESCE(tenant_slug, 'default') = $1`
		_ = db.pool.QueryRow(ctx, countsQuery, tenant).Scan(
			&stats.TotalAlerts, &stats.CriticalAlerts, &stats.HighAlerts,
			&stats.MediumAlerts, &stats.LowAlerts, &stats.ActiveIncidents,
			&stats.ResolvedIncidents, &stats.MeanRiskScore,
		)
	} else {
		_ = db.pool.QueryRow(ctx, countsQuery).Scan(
			&stats.TotalAlerts, &stats.CriticalAlerts, &stats.HighAlerts,
			&stats.MediumAlerts, &stats.LowAlerts, &stats.ActiveIncidents,
			&stats.ResolvedIncidents, &stats.MeanRiskScore,
		)
	}

	// 2. Top Attackers (Source IP)
	attackersQuery := `
		SELECT source_ip, COUNT(*) AS cnt
		FROM siem_alerts
		WHERE source_ip <> '' AND source_ip IS NOT NULL`
	if filterByTenant {
		attackersQuery += ` AND COALESCE(tenant_slug, 'default') = $1`
	}
	attackersQuery += `
		GROUP BY source_ip
		ORDER BY cnt DESC
		LIMIT 5`

	var aRows pgx.Rows
	var aErr error
	if filterByTenant {
		aRows, aErr = db.pool.Query(ctx, attackersQuery, tenant)
	} else {
		aRows, aErr = db.pool.Query(ctx, attackersQuery)
	}
	if aErr == nil {
		for aRows.Next() {
			var pair models.KeyValueCount
			if err := aRows.Scan(&pair.Key, &pair.Count); err == nil {
				stats.TopAttackers = append(stats.TopAttackers, pair)
			}
		}
		aRows.Close()
	}

	// 3. Top Targeted Users
	usersQuery := `
		SELECT username, COUNT(*) AS cnt
		FROM siem_alerts
		WHERE username <> '' AND username IS NOT NULL`
	if filterByTenant {
		usersQuery += ` AND COALESCE(tenant_slug, 'default') = $1`
	}
	usersQuery += `
		GROUP BY username
		ORDER BY cnt DESC
		LIMIT 5`

	var uRows pgx.Rows
	var uErr error
	if filterByTenant {
		uRows, uErr = db.pool.Query(ctx, usersQuery, tenant)
	} else {
		uRows, uErr = db.pool.Query(ctx, usersQuery)
	}
	if uErr == nil {
		for uRows.Next() {
			var pair models.KeyValueCount
			if err := uRows.Scan(&pair.Key, &pair.Count); err == nil {
				stats.TopTargetUsers = append(stats.TopTargetUsers, pair)
			}
		}
		uRows.Close()
	}

	// 4. Top Targeted Devices
	devicesQuery := `
		SELECT device_name, COUNT(*) AS cnt
		FROM siem_alerts
		WHERE device_name <> '' AND device_name IS NOT NULL`
	if filterByTenant {
		devicesQuery += ` AND COALESCE(tenant_slug, 'default') = $1`
	}
	devicesQuery += `
		GROUP BY device_name
		ORDER BY cnt DESC
		LIMIT 5`

	var dRows pgx.Rows
	var dErr error
	if filterByTenant {
		dRows, dErr = db.pool.Query(ctx, devicesQuery, tenant)
	} else {
		dRows, dErr = db.pool.Query(ctx, devicesQuery)
	}
	if dErr == nil {
		for dRows.Next() {
			var pair models.KeyValueCount
			if err := dRows.Scan(&pair.Key, &pair.Count); err == nil {
				stats.TopTargetDevices = append(stats.TopTargetDevices, pair)
			}
		}
		dRows.Close()
	}

	// 5. MITRE Tactic Distribution
	mitreQuery := `
		SELECT mitre_tactic, COUNT(*) AS cnt
		FROM siem_alerts
		WHERE mitre_tactic <> '' AND mitre_tactic IS NOT NULL`
	if filterByTenant {
		mitreQuery += ` AND COALESCE(tenant_slug, 'default') = $1`
	}
	mitreQuery += `
		GROUP BY mitre_tactic
		ORDER BY cnt DESC
		LIMIT 6`

	var mRows pgx.Rows
	var mErr error
	if filterByTenant {
		mRows, mErr = db.pool.Query(ctx, mitreQuery, tenant)
	} else {
		mRows, mErr = db.pool.Query(ctx, mitreQuery)
	}
	if mErr == nil {
		for mRows.Next() {
			var pair models.KeyValueCount
			if err := mRows.Scan(&pair.Key, &pair.Count); err == nil {
				stats.MitreTacticDistribution = append(stats.MitreTacticDistribution, pair)
			}
		}
		mRows.Close()
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

// EnsureEdgeSchema ensures edge_nodes and tenants tables exist for remote proxy nodes and multi-tenancy
func (db *DB) EnsureEdgeSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS tenants (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		slug VARCHAR(64) NOT NULL UNIQUE,
		name VARCHAR(128) NOT NULL,
		description TEXT DEFAULT '',
		admin_name VARCHAR(128) DEFAULT '',
		admin_email VARCHAR(128) DEFAULT '',
		admin_username VARCHAR(128) DEFAULT '',
		status VARCHAR(32) NOT NULL DEFAULT 'active',
		ingest_policy VARCHAR(32) NOT NULL DEFAULT 'permissive',
		max_nodes INT NOT NULL DEFAULT 5,
		max_eps INT NOT NULL DEFAULT 5000,
		retention_days INT NOT NULL DEFAULT 0,
		max_storage_gb INT NOT NULL DEFAULT 0,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	ALTER TABLE tenants ADD COLUMN IF NOT EXISTS ingest_policy VARCHAR(32) NOT NULL DEFAULT 'permissive';
	ALTER TABLE tenants ADD COLUMN IF NOT EXISTS retention_days INT NOT NULL DEFAULT 0;
	ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_storage_gb INT NOT NULL DEFAULT 0;
	ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_url VARCHAR(255) NOT NULL DEFAULT '';

	INSERT INTO tenants (slug, name, description, admin_name, admin_email, admin_username, status)
	VALUES ('default', 'Default Organization (Root)', 'Primary root tenant', 'Root Super Admin', 'admin@syslog.local', 'admin', 'active')
	ON CONFLICT (slug) DO NOTHING;

	-- Root tenant is the MSSP operator: no node / EPS quota / storage quota (0 = unlimited)
	UPDATE tenants SET max_nodes = 0, max_eps = 0, max_storage_gb = 0 WHERE slug = 'default' AND (max_nodes <> 0 OR max_eps <> 0 OR max_storage_gb <> 0);

	-- Device ownership for tenant-scoped data views
	ALTER TABLE devices ADD COLUMN IF NOT EXISTS tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default';
	CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_slug);

	-- Multi-Tenant Log Archives
	ALTER TABLE log_archives ADD COLUMN IF NOT EXISTS tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default';
	CREATE INDEX IF NOT EXISTS idx_log_archives_tenant ON log_archives(tenant_slug);

	-- Multi-Tenant Audit Logs
	ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default';
	CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_slug);

	ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_slug VARCHAR(64) DEFAULT 'default';
	ALTER TABLE users ADD COLUMN IF NOT EXISTS is_tenant_admin BOOLEAN DEFAULT FALSE;

	-- Evidence Archive Tables (Law 5651 & TÜBİTAK Zamane KS Pipeline)
	CREATE TABLE IF NOT EXISTS archive_jobs (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		request_type VARCHAR(32) NOT NULL DEFAULT 'HOURLY_SCHEDULED',
		period_start TIMESTAMPTZ NOT NULL,
		period_end TIMESTAMPTZ NOT NULL,
		time_basis VARCHAR(32) NOT NULL DEFAULT 'receipt_time',
		idempotency_key VARCHAR(128) NOT NULL UNIQUE,
		requester VARCHAR(64) NOT NULL DEFAULT 'system',
		reason TEXT DEFAULT '',
		lease_until TIMESTAMPTZ,
		attempts INT NOT NULL DEFAULT 0,
		state VARCHAR(32) NOT NULL DEFAULT 'QUEUED',
		error_message TEXT DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_archive_jobs_state ON archive_jobs(state, lease_until);
	CREATE INDEX IF NOT EXISTS idx_archive_jobs_tenant ON archive_jobs(tenant_slug, period_start);

	CREATE TABLE IF NOT EXISTS archive_manifests (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		archive_id UUID NOT NULL,
		manifest_content BYTEA NOT NULL,
		manifest_sha256 VARCHAR(64) NOT NULL,
		payload_sha256 VARCHAR(64) NOT NULL,
		schema_version VARCHAR(16) NOT NULL DEFAULT '1.0',
		prior_manifest_sha256 VARCHAR(64) DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_manifest_archive ON archive_manifests(archive_id);
	CREATE INDEX IF NOT EXISTS idx_manifest_hash ON archive_manifests(manifest_sha256);

	CREATE TABLE IF NOT EXISTS archive_timestamps (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		manifest_id UUID NOT NULL REFERENCES archive_manifests(id) ON DELETE CASCADE,
		request_id VARCHAR(64) NOT NULL DEFAULT '',
		token_bytes BYTEA NOT NULL,
		tsa_identity VARCHAR(128) NOT NULL DEFAULT 'TÜBİTAK KamuSM / Zamane KS',
		tsa_policy VARCHAR(64) NOT NULL DEFAULT '',
		tsa_serial VARCHAR(64) NOT NULL DEFAULT '',
		tsa_time TIMESTAMPTZ,
		imprint_algorithm VARCHAR(32) NOT NULL DEFAULT 'SHA-256',
		signature_algorithm VARCHAR(32) NOT NULL DEFAULT 'SHA256withRSA',
		verification_outcome VARCHAR(32) NOT NULL DEFAULT 'PENDING',
		verification_details TEXT DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_ts_manifest ON archive_timestamps(manifest_id);

	CREATE TABLE IF NOT EXISTS archive_audit (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		archive_id UUID,
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		action VARCHAR(64) NOT NULL,
		operator VARCHAR(64) NOT NULL DEFAULT 'system',
		details JSONB DEFAULT '{}',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_archive_audit_tenant ON archive_audit(tenant_slug, created_at);

	-- Backfill: tenant admins provisioned before tenant_slug was persisted (never touches Super Administrators)
	UPDATE users u SET tenant_slug = t.slug, is_tenant_admin = TRUE
	FROM tenants t
	WHERE t.slug <> 'default' AND t.admin_username <> ''
	  AND LOWER(u.username) = LOWER(t.admin_username)
	  AND u.role <> 'Super Administrator'
	  AND COALESCE(u.tenant_slug, 'default') = 'default';

	CREATE TABLE IF NOT EXISTS edge_nodes (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(128) NOT NULL,
		token VARCHAR(128) NOT NULL UNIQUE,
		tenant_name VARCHAR(128) NOT NULL DEFAULT 'default',
		sync_interval VARCHAR(32) NOT NULL DEFAULT 'online',
		last_seen_at TIMESTAMPTZ,
		last_ip VARCHAR(64) DEFAULT '',
		version VARCHAR(32) DEFAULT '',
		status VARCHAR(32) NOT NULL DEFAULT 'offline',
		logs_forwarded BIGINT NOT NULL DEFAULT 0,
		admin_name VARCHAR(128) DEFAULT '',
		admin_email VARCHAR(128) DEFAULT '',
		admin_username VARCHAR(128) DEFAULT '',
		admin_initial_pass VARCHAR(128) DEFAULT '',
		activation_status VARCHAR(32) DEFAULT 'active',
		ldap_config JSONB DEFAULT '{}'::jsonb,
		min_specs JSONB DEFAULT '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS admin_name VARCHAR(128) DEFAULT '';
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS admin_email VARCHAR(128) DEFAULT '';
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS admin_username VARCHAR(128) DEFAULT '';
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS admin_initial_pass VARCHAR(128) DEFAULT '';
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS activation_status VARCHAR(32) DEFAULT 'active';
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS ldap_config JSONB DEFAULT '{}'::jsonb;
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS min_specs JSONB DEFAULT '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb;
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS token_hash VARCHAR(64) DEFAULT '';
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS token_prefix VARCHAR(16) DEFAULT '';
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS key_expires_at TIMESTAMPTZ;
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS allowed_cidrs VARCHAR(256) DEFAULT '';
	ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS last_key_rotated_at TIMESTAMPTZ DEFAULT NOW();

	CREATE INDEX IF NOT EXISTS idx_edge_nodes_token ON edge_nodes(token);
	CREATE INDEX IF NOT EXISTS idx_edge_nodes_token_hash ON edge_nodes(token_hash);
	CREATE INDEX IF NOT EXISTS idx_edge_nodes_tenant ON edge_nodes(tenant_name);
	`
	if _, err := db.pool.Exec(ctx, schema); err != nil {
		return err
	}

	// Backfill token_hash & token_prefix for legacy edge nodes
	if rows, err := db.pool.Query(ctx, "SELECT id, token FROM edge_nodes WHERE token_hash IS NULL OR token_hash = ''"); err == nil {
		type legacyNode struct {
			id    uuid.UUID
			token string
		}
		var leg []legacyNode
		for rows.Next() {
			var ln legacyNode
			if scanErr := rows.Scan(&ln.id, &ln.token); scanErr == nil {
				leg = append(leg, ln)
			}
		}
		rows.Close()
		for _, ln := range leg {
			th := HashEdgeToken(ln.token)
			tp := MaskEdgeToken(ln.token)
			_, _ = db.pool.Exec(ctx, "UPDATE edge_nodes SET token_hash = $1, token_prefix = $2 WHERE id = $3", th, tp, ln.id)
		}
	}
	return nil
}

// HashEdgeToken returns the SHA-256 hex string of a secret edge token
func HashEdgeToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// MaskEdgeToken returns a safe prefix/suffix display representation
func MaskEdgeToken(token string) string {
	if len(token) > 14 {
		return token[:10] + "..." + token[len(token)-4:]
	}
	return token
}

// ListTenants returns all customer tenant organizations
func (db *DB) ListTenants(ctx context.Context) ([]*models.Tenant, error) {
	query := `
		SELECT id, slug, name, description, admin_name, admin_email, admin_username, status, coalesce(ingest_policy, 'permissive'), max_nodes, max_eps, coalesce(retention_days, 0), coalesce(max_storage_gb, 0), coalesce(logo_url, ''), created_at, updated_at
		FROM tenants
		ORDER BY created_at ASC`
	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()

	var list []*models.Tenant
	for rows.Next() {
		var t models.Tenant
		if err := rows.Scan(
			&t.ID, &t.Slug, &t.Name, &t.Description,
			&t.AdminName, &t.AdminEmail, &t.AdminUsername,
			&t.Status, &t.IngestPolicy, &t.MaxNodes, &t.MaxEPS,
			&t.RetentionDays, &t.MaxStorageGB, &t.LogoURL,
			&t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, &t)
	}
	return list, rows.Err()
}

// GetTenantBySlug returns a tenant by its unique slug identifier
func (db *DB) GetTenantBySlug(ctx context.Context, slug string) (*models.Tenant, error) {
	query := `
		SELECT id, slug, name, description, admin_name, admin_email, admin_username, status, coalesce(ingest_policy, 'permissive'), max_nodes, max_eps, coalesce(retention_days, 0), coalesce(max_storage_gb, 0), coalesce(logo_url, ''), created_at, updated_at
		FROM tenants
		WHERE slug = $1`
	var t models.Tenant
	err := db.pool.QueryRow(ctx, query, slug).Scan(
		&t.ID, &t.Slug, &t.Name, &t.Description,
		&t.AdminName, &t.AdminEmail, &t.AdminUsername,
		&t.Status, &t.IngestPolicy, &t.MaxNodes, &t.MaxEPS,
		&t.RetentionDays, &t.MaxStorageGB, &t.LogoURL,
		&t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// CreateTenant inserts a new customer organization and provisions its admin user
func (db *DB) CreateTenant(ctx context.Context, t *models.Tenant, initialAdminPass string) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.Slug == "" {
		t.Slug = strings.ToLower(strings.ReplaceAll(t.Name, " ", "-"))
	}
	if t.Status == "" {
		t.Status = "active"
	}
	if t.IngestPolicy == "" {
		t.IngestPolicy = "permissive"
	}
	if t.MaxNodes < 0 {
		t.MaxNodes = 5
	}
	if t.MaxEPS < 0 {
		t.MaxEPS = 5000
	}
	if t.RetentionDays < 0 {
		t.RetentionDays = 0
	}
	if t.MaxStorageGB < 0 {
		t.MaxStorageGB = 0
	}
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()

	query := `
		INSERT INTO tenants (id, slug, name, description, admin_name, admin_email, admin_username, status, ingest_policy, max_nodes, max_eps, retention_days, max_storage_gb, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	_, err := db.pool.Exec(ctx, query,
		t.ID, t.Slug, t.Name, t.Description,
		t.AdminName, t.AdminEmail, t.AdminUsername,
		t.Status, t.IngestPolicy, t.MaxNodes, t.MaxEPS,
		t.RetentionDays, t.MaxStorageGB,
		t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return err
	}

	// Auto-provision Tenant Admin user if credentials provided
	if t.AdminUsername != "" && initialAdminPass != "" {
		u := &models.User{
			Username:      t.AdminUsername,
			FullName:      t.AdminName,
			Email:         t.AdminEmail,
			Role:          "Administrator",
			IsEnabled:     true,
			AuthSource:    "local",
			TenantSlug:    t.Slug,
			IsTenantAdmin: true,
		}
		if u.FullName == "" {
			u.FullName = t.Name + " Admin"
		}
		_ = db.CreateUser(ctx, u, initialAdminPass)
	}

	return nil
}

// UpdateTenantQuotas updates all operational resource constraints and retention policies for a tenant
func (db *DB) UpdateTenantQuotas(ctx context.Context, slug string, maxNodes, maxEPS, retentionDays, maxStorageGB int, ingestPolicy string) error {
	p := strings.ToLower(strings.TrimSpace(ingestPolicy))
	if p != "strict" && p != "permissive" {
		p = ""
	}
	query := `
		UPDATE tenants
		SET max_nodes = $1,
		    max_eps = $2,
		    retention_days = $3,
		    max_storage_gb = $4,
		    ingest_policy = CASE WHEN $5 <> '' THEN $5 ELSE ingest_policy END,
		    updated_at = NOW()
		WHERE slug = $6`
	tag, err := db.pool.Exec(ctx, query, maxNodes, maxEPS, retentionDays, maxStorageGB, p, slug)
	if err != nil {
		return fmt.Errorf("updating tenant quotas: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant '%s' not found", slug)
	}
	return nil
}

// UpdateTenantIngestPolicy updates the auto-discovery or whitelist-only policy for a tenant
func (db *DB) UpdateTenantIngestPolicy(ctx context.Context, slug, policy string) error {
	p := strings.ToLower(policy)
	if p != "strict" {
		p = "permissive"
	}
	query := `UPDATE tenants SET ingest_policy = $1, updated_at = NOW() WHERE slug = $2`
	_, err := db.pool.Exec(ctx, query, p, slug)
	return err
}

// UpdateTenantLogo updates the branding logo URL or relative path for a tenant
func (db *DB) UpdateTenantLogo(ctx context.Context, slug, logoURL string) error {
	query := `UPDATE tenants SET logo_url = $1, updated_at = NOW() WHERE slug = $2`
	tag, err := db.pool.Exec(ctx, query, strings.TrimSpace(logoURL), slug)
	if err != nil {
		return fmt.Errorf("updating tenant logo: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant %q not found", slug)
	}
	return nil
}

// TenantUsage summarizes resources consumed by a tenant
type TenantUsage struct {
	NodeCount   int `json:"node_count"`
	DeviceCount int `json:"device_count"`
}

// GetTenantUsage returns edge-node and device counts grouped by tenant slug
func (db *DB) GetTenantUsage(ctx context.Context) (map[string]*TenantUsage, error) {
	usage := make(map[string]*TenantUsage)
	get := func(slug string) *TenantUsage {
		if u, ok := usage[slug]; ok {
			return u
		}
		u := &TenantUsage{}
		usage[slug] = u
		return u
	}

	rows, err := db.pool.Query(ctx, `SELECT tenant_name, count(*) FROM edge_nodes GROUP BY tenant_name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var slug string
		var n int
		if err := rows.Scan(&slug, &n); err == nil {
			get(slug).NodeCount = n
		}
	}
	rows.Close()

	rows, err = db.pool.Query(ctx, `SELECT COALESCE(tenant_slug, 'default'), count(*) FROM devices GROUP BY 1`)
	if err != nil {
		return usage, nil
	}
	for rows.Next() {
		var slug string
		var n int
		if err := rows.Scan(&slug, &n); err == nil {
			get(slug).DeviceCount = n
		}
	}
	rows.Close()
	return usage, nil
}

// CountEdgeNodesByTenant returns the number of edge nodes owned by a tenant
func (db *DB) CountEdgeNodesByTenant(ctx context.Context, tenant string) (int, error) {
	var n int
	err := db.pool.QueryRow(ctx, `SELECT count(*) FROM edge_nodes WHERE tenant_name = $1`, tenant).Scan(&n)
	return n, err
}

// DeleteTenant deletes a tenant and cascades
func (db *DB) DeleteTenant(ctx context.Context, slug string) error {
	if slug == "default" {
		return fmt.Errorf("cannot delete default root tenant")
	}
	query := `DELETE FROM tenants WHERE slug = $1`
	_, err := db.pool.Exec(ctx, query, slug)
	return err
}

// ListEdgeNodes retrieves registered edge proxy nodes, optionally filtered by tenant
func (db *DB) ListEdgeNodes(ctx context.Context, tenantFilter string) ([]*models.EdgeNode, error) {
	var query string
	var args []any

	if tenantFilter != "" && tenantFilter != "all" {
		query = `
			SELECT id, name, token, tenant_name, sync_interval, last_seen_at, last_ip, version, status, logs_forwarded,
			       COALESCE(admin_name, ''), COALESCE(admin_email, ''), COALESCE(admin_username, ''),
			       COALESCE(activation_status, 'active'), COALESCE(ldap_config, '{}'::jsonb),
			       COALESCE(min_specs, '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb),
			       COALESCE(token_hash, ''), COALESCE(token_prefix, ''), key_expires_at, COALESCE(allowed_cidrs, ''), last_key_rotated_at,
			       created_at, updated_at
			FROM edge_nodes
			WHERE tenant_name = $1
			ORDER BY created_at DESC`
		args = append(args, tenantFilter)
	} else {
		query = `
			SELECT id, name, token, tenant_name, sync_interval, last_seen_at, last_ip, version, status, logs_forwarded,
			       COALESCE(admin_name, ''), COALESCE(admin_email, ''), COALESCE(admin_username, ''),
			       COALESCE(activation_status, 'active'), COALESCE(ldap_config, '{}'::jsonb),
			       COALESCE(min_specs, '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb),
			       COALESCE(token_hash, ''), COALESCE(token_prefix, ''), key_expires_at, COALESCE(allowed_cidrs, ''), last_key_rotated_at,
			       created_at, updated_at
			FROM edge_nodes
			ORDER BY created_at DESC`
	}

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing edge nodes: %w", err)
	}
	defer rows.Close()

	var nodes []*models.EdgeNode
	for rows.Next() {
		var n models.EdgeNode
		var ldapJSON []byte
		var minSpecsJSON []byte
		err := rows.Scan(
			&n.ID, &n.Name, &n.Token, &n.TenantName, &n.SyncInterval,
			&n.LastSeenAt, &n.LastIP, &n.Version, &n.Status, &n.LogsForwarded,
			&n.AdminName, &n.AdminEmail, &n.AdminUsername,
			&n.ActivationStatus, &ldapJSON, &minSpecsJSON,
			&n.TokenHash, &n.TokenPrefix, &n.KeyExpiresAt, &n.AllowedCIDRs, &n.LastKeyRotatedAt,
			&n.CreatedAt, &n.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning edge node: %w", err)
		}
		if len(ldapJSON) > 0 {
			_ = json.Unmarshal(ldapJSON, &n.LDAPConfig)
		}
		if len(minSpecsJSON) > 0 {
			_ = json.Unmarshal(minSpecsJSON, &n.MinSpecs)
		}
		if n.MinSpecs == nil {
			n.MinSpecs = map[string]string{
				"min_cpu":  "1 vCPU",
				"min_ram":  "512 MB",
				"min_disk": "2 GB",
			}
		}
		if n.TokenPrefix == "" && n.Token != "" {
			n.TokenPrefix = MaskEdgeToken(n.Token)
		}

		n.Status = computeEdgeNodeStatus(n.LastSeenAt, n.SyncInterval)
		nodes = append(nodes, &n)
	}
	return nodes, rows.Err()
}

// GetEdgeNodeByID retrieves a single edge node by UUID
func (db *DB) GetEdgeNodeByID(ctx context.Context, id uuid.UUID) (*models.EdgeNode, error) {
	query := `
		SELECT id, name, token, tenant_name, sync_interval, last_seen_at, last_ip, version, status, logs_forwarded,
		       COALESCE(admin_name, ''), COALESCE(admin_email, ''), COALESCE(admin_username, ''),
		       COALESCE(activation_status, 'active'), COALESCE(ldap_config, '{}'::jsonb),
		       COALESCE(min_specs, '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb),
		       COALESCE(token_hash, ''), COALESCE(token_prefix, ''), key_expires_at, COALESCE(allowed_cidrs, ''), last_key_rotated_at,
		       created_at, updated_at
		FROM edge_nodes
		WHERE id = $1`
	var n models.EdgeNode
	var ldapJSON []byte
	var minSpecsJSON []byte
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&n.ID, &n.Name, &n.Token, &n.TenantName, &n.SyncInterval,
		&n.LastSeenAt, &n.LastIP, &n.Version, &n.Status, &n.LogsForwarded,
		&n.AdminName, &n.AdminEmail, &n.AdminUsername,
		&n.ActivationStatus, &ldapJSON, &minSpecsJSON,
		&n.TokenHash, &n.TokenPrefix, &n.KeyExpiresAt, &n.AllowedCIDRs, &n.LastKeyRotatedAt,
		&n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying edge node by id: %w", err)
	}
	if len(ldapJSON) > 0 {
		_ = json.Unmarshal(ldapJSON, &n.LDAPConfig)
	}
	if len(minSpecsJSON) > 0 {
		_ = json.Unmarshal(minSpecsJSON, &n.MinSpecs)
	}
	if n.TokenPrefix == "" && n.Token != "" {
		n.TokenPrefix = MaskEdgeToken(n.Token)
	}
	n.Status = computeEdgeNodeStatus(n.LastSeenAt, n.SyncInterval)
	return &n, nil
}

// GetEdgeNodeByToken retrieves an edge node by its secret token using Zero-Trust hashed or raw token matching
func (db *DB) GetEdgeNodeByToken(ctx context.Context, token string) (*models.EdgeNode, error) {
	th := HashEdgeToken(token)
	query := `
		SELECT id, name, token, tenant_name, sync_interval, last_seen_at, last_ip, version, status, logs_forwarded,
		       COALESCE(admin_name, ''), COALESCE(admin_email, ''), COALESCE(admin_username, ''),
		       COALESCE(activation_status, 'active'), COALESCE(ldap_config, '{}'::jsonb),
		       COALESCE(min_specs, '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb),
		       COALESCE(token_hash, ''), COALESCE(token_prefix, ''), key_expires_at, COALESCE(allowed_cidrs, ''), last_key_rotated_at,
		       created_at, updated_at
		FROM edge_nodes
		WHERE token_hash = $1 OR token = $2`
	var n models.EdgeNode
	var ldapJSON []byte
	var minSpecsJSON []byte
	err := db.pool.QueryRow(ctx, query, th, token).Scan(
		&n.ID, &n.Name, &n.Token, &n.TenantName, &n.SyncInterval,
		&n.LastSeenAt, &n.LastIP, &n.Version, &n.Status, &n.LogsForwarded,
		&n.AdminName, &n.AdminEmail, &n.AdminUsername,
		&n.ActivationStatus, &ldapJSON, &minSpecsJSON,
		&n.TokenHash, &n.TokenPrefix, &n.KeyExpiresAt, &n.AllowedCIDRs, &n.LastKeyRotatedAt,
		&n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying edge node by token: %w", err)
	}
	if len(ldapJSON) > 0 {
		_ = json.Unmarshal(ldapJSON, &n.LDAPConfig)
	}
	if len(minSpecsJSON) > 0 {
		_ = json.Unmarshal(minSpecsJSON, &n.MinSpecs)
	}
	if n.TokenPrefix == "" && n.Token != "" {
		n.TokenPrefix = MaskEdgeToken(n.Token)
	}
	n.Status = computeEdgeNodeStatus(n.LastSeenAt, n.SyncInterval)
	return &n, nil
}

// CreateEdgeNode inserts a new edge proxy node with Zero-Trust token hashing and CIDR configuration
func (db *DB) CreateEdgeNode(ctx context.Context, node *models.EdgeNode) error {
	if node.ID == uuid.Nil {
		node.ID = uuid.New()
	}
	if node.SyncInterval == "" {
		node.SyncInterval = "online"
	}
	if node.TenantName == "" {
		node.TenantName = "default"
	}
	if node.ActivationStatus == "" {
		node.ActivationStatus = "active"
	}
	if node.TokenHash == "" {
		node.TokenHash = HashEdgeToken(node.Token)
	}
	if node.TokenPrefix == "" {
		node.TokenPrefix = MaskEdgeToken(node.Token)
	}
	if node.LastKeyRotatedAt == nil {
		now := time.Now()
		node.LastKeyRotatedAt = &now
	}
	node.Status = "pending"
	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()

	ldapBytes, _ := json.Marshal(node.LDAPConfig)
	if len(ldapBytes) == 0 {
		ldapBytes = []byte("{}")
	}

	specsBytes, _ := json.Marshal(map[string]string{
		"min_cpu":  "1 vCPU",
		"min_ram":  "512 MB",
		"min_disk": "2 GB",
	})

	query := `
		INSERT INTO edge_nodes (
			id, name, token, tenant_name, sync_interval, status,
			admin_name, admin_email, admin_username, admin_initial_pass,
			activation_status, ldap_config, min_specs,
			token_hash, token_prefix, key_expires_at, allowed_cidrs, last_key_rotated_at,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`
	_, err := db.pool.Exec(ctx, query,
		node.ID, node.Name, node.Token, node.TenantName, node.SyncInterval, node.Status,
		node.AdminName, node.AdminEmail, node.AdminUsername, node.AdminInitialPass,
		node.ActivationStatus, ldapBytes, specsBytes,
		node.TokenHash, node.TokenPrefix, node.KeyExpiresAt, node.AllowedCIDRs, node.LastKeyRotatedAt,
		node.CreatedAt, node.UpdatedAt)
	if err != nil {
		return err
	}

	// If node admin credentials were provided and active, preconfigure operator user
	if node.AdminUsername != "" && node.AdminInitialPass != "" && node.ActivationStatus == "active" {
		u := &models.User{
			Username:      node.AdminUsername,
			FullName:      node.AdminName,
			Email:         node.AdminEmail,
			Role:          "Administrator",
			IsEnabled:     true,
			AuthSource:    "local",
			TenantSlug:    node.TenantName,
			IsTenantAdmin: false,
		}
		if u.FullName == "" {
			u.FullName = node.Name + " Admin"
		}
		_ = db.CreateUser(ctx, u, node.AdminInitialPass)
	}

	return nil
}

// RotateEdgeNodeToken invalidates old token and assigns a newly generated token with updated hash and optional expiration
func (db *DB) RotateEdgeNodeToken(ctx context.Context, id uuid.UUID, newToken string, expiresAt *time.Time) (*models.EdgeNode, error) {
	tokenHash := HashEdgeToken(newToken)
	tokenPrefix := MaskEdgeToken(newToken)
	query := `
		UPDATE edge_nodes
		SET token = $1,
		    token_hash = $2,
		    token_prefix = $3,
		    last_key_rotated_at = NOW(),
		    key_expires_at = $4,
		    updated_at = NOW()
		WHERE id = $5
		RETURNING id, name, token, tenant_name, sync_interval, last_seen_at, last_ip, version, status, logs_forwarded,
		          COALESCE(admin_name, ''), COALESCE(admin_email, ''), COALESCE(admin_username, ''),
		          COALESCE(activation_status, 'active'), COALESCE(ldap_config, '{}'::jsonb),
		          COALESCE(min_specs, '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb),
		          COALESCE(token_hash, ''), COALESCE(token_prefix, ''), key_expires_at, COALESCE(allowed_cidrs, ''), last_key_rotated_at,
		          created_at, updated_at`
	var n models.EdgeNode
	var ldapJSON []byte
	var minSpecsJSON []byte
	err := db.pool.QueryRow(ctx, query, newToken, tokenHash, tokenPrefix, expiresAt, id).Scan(
		&n.ID, &n.Name, &n.Token, &n.TenantName, &n.SyncInterval,
		&n.LastSeenAt, &n.LastIP, &n.Version, &n.Status, &n.LogsForwarded,
		&n.AdminName, &n.AdminEmail, &n.AdminUsername,
		&n.ActivationStatus, &ldapJSON, &minSpecsJSON,
		&n.TokenHash, &n.TokenPrefix, &n.KeyExpiresAt, &n.AllowedCIDRs, &n.LastKeyRotatedAt,
		&n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("rotating edge node token: %w", err)
	}
	if len(ldapJSON) > 0 {
		_ = json.Unmarshal(ldapJSON, &n.LDAPConfig)
	}
	if len(minSpecsJSON) > 0 {
		_ = json.Unmarshal(minSpecsJSON, &n.MinSpecs)
	}
	n.Status = computeEdgeNodeStatus(n.LastSeenAt, n.SyncInterval)
	return &n, nil
}

// UpdateEdgeNodeCIDRs updates the Zero-Trust allowed source IP / CIDR whitelist for an edge node
func (db *DB) UpdateEdgeNodeCIDRs(ctx context.Context, id uuid.UUID, allowedCIDRs string) error {
	query := `
		UPDATE edge_nodes
		SET allowed_cidrs = $1, updated_at = NOW()
		WHERE id = $2`
	tag, err := db.pool.Exec(ctx, query, strings.TrimSpace(allowedCIDRs), id)
	if err != nil {
		return fmt.Errorf("updating allowed cidrs: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("edge node not found")
	}
	return nil
}

// ActivateEdgeNode enables a pending edge node and configures its admin user and LDAP settings
func (db *DB) ActivateEdgeNode(
	ctx context.Context,
	id uuid.UUID,
	adminName, adminEmail, adminUsername, adminPass, syncInterval string,
	ldapConfig map[string]interface{},
	allowedCIDRs string,
) error {
	ldapBytes, _ := json.Marshal(ldapConfig)
	if len(ldapBytes) == 0 {
		ldapBytes = []byte("{}")
	}

	query := `
		UPDATE edge_nodes
		SET activation_status = 'active',
		    admin_name = CASE WHEN $2 <> '' THEN $2 ELSE admin_name END,
		    admin_email = CASE WHEN $3 <> '' THEN $3 ELSE admin_email END,
		    admin_username = CASE WHEN $4 <> '' THEN $4 ELSE admin_username END,
		    sync_interval = CASE WHEN $5 <> '' THEN $5 ELSE sync_interval END,
		    ldap_config = $6,
		    allowed_cidrs = CASE WHEN $7 <> '' THEN $7 ELSE allowed_cidrs END,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING tenant_name, name`

	var tenantName, nodeName string
	err := db.pool.QueryRow(ctx, query, id, adminName, adminEmail, adminUsername, syncInterval, ldapBytes, strings.TrimSpace(allowedCIDRs)).Scan(&tenantName, &nodeName)
	if err != nil {
		return fmt.Errorf("activating edge node: %w", err)
	}

	// Preconfigure user in users table if username and password provided
	if adminUsername != "" && adminPass != "" {
		u := &models.User{
			Username:      adminUsername,
			FullName:      adminName,
			Email:         adminEmail,
			Role:          "Administrator",
			IsEnabled:     true,
			AuthSource:    "local",
			TenantSlug:    tenantName,
			IsTenantAdmin: false,
		}
		if u.FullName == "" {
			u.FullName = nodeName + " Admin"
		}
		_ = db.CreateUser(ctx, u, adminPass)
	}

	return nil
}

// UpdateEdgeNodeInterval updates the schedule on the cloud for an edge node
func (db *DB) UpdateEdgeNodeInterval(ctx context.Context, id uuid.UUID, interval string) error {
	query := `
		UPDATE edge_nodes
		SET sync_interval = $1, updated_at = NOW()
		WHERE id = $2`
	tag, err := db.pool.Exec(ctx, query, interval, id)
	if err != nil {
		return fmt.Errorf("updating edge node interval: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("edge node not found")
	}
	return nil
}

// UpdateEdgeNodeHeartbeat updates last_seen, ip, version and increments logs_forwarded
func (db *DB) UpdateEdgeNodeHeartbeat(ctx context.Context, token, ip, ver string, addLogs int64) (*models.EdgeNode, error) {
	th := HashEdgeToken(token)
	query := `
		UPDATE edge_nodes
		SET last_seen_at = NOW(),
		    last_ip = CASE WHEN $2 <> '' THEN $2 ELSE last_ip END,
		    version = CASE WHEN $3 <> '' THEN $3 ELSE version END,
		    status = 'online',
		    logs_forwarded = logs_forwarded + $4,
		    updated_at = NOW()
		WHERE token = $1 OR token_hash = $5
		RETURNING id, name, token, tenant_name, sync_interval, last_seen_at, last_ip, version, status, logs_forwarded,
		          COALESCE(admin_name, ''), COALESCE(admin_email, ''), COALESCE(admin_username, ''),
		          COALESCE(activation_status, 'active'), COALESCE(ldap_config, '{}'::jsonb),
		          COALESCE(min_specs, '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb),
		          COALESCE(token_hash, ''), COALESCE(token_prefix, ''), key_expires_at, COALESCE(allowed_cidrs, ''), last_key_rotated_at,
		          created_at, updated_at`
	var n models.EdgeNode
	var ldapJSON []byte
	var minSpecsJSON []byte
	err := db.pool.QueryRow(ctx, query, token, ip, ver, addLogs, th).Scan(
		&n.ID, &n.Name, &n.Token, &n.TenantName, &n.SyncInterval,
		&n.LastSeenAt, &n.LastIP, &n.Version, &n.Status, &n.LogsForwarded,
		&n.AdminName, &n.AdminEmail, &n.AdminUsername,
		&n.ActivationStatus, &ldapJSON, &minSpecsJSON,
		&n.TokenHash, &n.TokenPrefix, &n.KeyExpiresAt, &n.AllowedCIDRs, &n.LastKeyRotatedAt,
		&n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(ldapJSON) > 0 {
		_ = json.Unmarshal(ldapJSON, &n.LDAPConfig)
	}
	if len(minSpecsJSON) > 0 {
		_ = json.Unmarshal(minSpecsJSON, &n.MinSpecs)
	}
	if n.TokenPrefix == "" && n.Token != "" {
		n.TokenPrefix = MaskEdgeToken(n.Token)
	}
	n.Status = computeEdgeNodeStatus(n.LastSeenAt, n.SyncInterval)
	return &n, nil
}

// computeEdgeNodeStatus determines if a node is online, degraded, offline, or pending based on its heartbeat interval
func computeEdgeNodeStatus(lastSeenAt *time.Time, syncInterval string) string {
	if lastSeenAt == nil {
		return "pending"
	}
	intervalSec := 30
	switch syncInterval {
	case "online":
		intervalSec = 30
	case "every 60 second":
		intervalSec = 60
	case "every 5 min":
		intervalSec = 300
	case "every 15 min":
		intervalSec = 900
	case "every 30 min":
		intervalSec = 1800
	case "every hour":
		intervalSec = 3600
	}

	elapsed := time.Since(*lastSeenAt)
	if elapsed <= time.Duration(intervalSec*2)*time.Second {
		return "online"
	} else if elapsed <= time.Duration(intervalSec*3)*time.Second {
		return "degraded"
	}
	return "offline"
}

// CheckEdgeNodeHealth scans all active edge nodes, updates status in the database when dead,
// and returns nodes that newly transitioned to offline for Dead Man's Switch alerts.
func (db *DB) CheckEdgeNodeHealth(ctx context.Context) ([]*models.EdgeNode, error) {
	query := `
		SELECT id, name, token, tenant_name, sync_interval, last_seen_at, last_ip, version, status, logs_forwarded,
		       COALESCE(admin_name, ''), COALESCE(admin_email, ''), COALESCE(admin_username, ''),
		       COALESCE(activation_status, 'active'), COALESCE(ldap_config, '{}'::jsonb),
		       COALESCE(min_specs, '{"min_cpu":"1 vCPU","min_ram":"512 MB","min_disk":"2 GB"}'::jsonb),
		       created_at, updated_at
		FROM edge_nodes
		WHERE activation_status = 'active'`

	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var newlyDark []*models.EdgeNode
	for rows.Next() {
		var n models.EdgeNode
		var ldapJSON, minSpecsJSON []byte
		err := rows.Scan(
			&n.ID, &n.Name, &n.Token, &n.TenantName, &n.SyncInterval,
			&n.LastSeenAt, &n.LastIP, &n.Version, &n.Status, &n.LogsForwarded,
			&n.AdminName, &n.AdminEmail, &n.AdminUsername,
			&n.ActivationStatus, &ldapJSON, &minSpecsJSON,
			&n.CreatedAt, &n.UpdatedAt,
		)
		if err != nil {
			continue
		}

		currentStatus := computeEdgeNodeStatus(n.LastSeenAt, n.SyncInterval)
		if currentStatus == "offline" && n.Status != "offline" && n.LastSeenAt != nil {
			_, _ = db.pool.Exec(ctx, "UPDATE edge_nodes SET status = 'offline', updated_at = NOW() WHERE id = $1", n.ID)
			n.Status = "offline"
			newlyDark = append(newlyDark, &n)
		} else if currentStatus == "degraded" && n.Status != "degraded" && n.Status != "offline" {
			_, _ = db.pool.Exec(ctx, "UPDATE edge_nodes SET status = 'degraded', updated_at = NOW() WHERE id = $1", n.ID)
		}
	}

	return newlyDark, nil
}

// DeleteEdgeNode removes an edge node
func (db *DB) DeleteEdgeNode(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM edge_nodes WHERE id = $1`
	_, err := db.pool.Exec(ctx, query, id)
	return err
}

// CreateSupportBundle stores a generated support diagnostic bundle metadata record
func (db *DB) CreateSupportBundle(ctx context.Context, b *models.SupportBundle) error {
	if b.TenantSlug == "" {
		b.TenantSlug = "default"
	}
	query := `
		INSERT INTO support_bundles (
			id, filename, file_path, file_size, sha256,
			access_passcode, access_token, requested_by, tenant_slug,
			issue_description, contact_email, download_count, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err := db.pool.Exec(ctx, query,
		b.ID, b.Filename, b.FilePath, b.FileSize, b.SHA256,
		b.AccessPasscode, b.AccessToken, b.RequestedBy, b.TenantSlug,
		b.IssueDescription, b.ContactEmail, b.DownloadCount, b.CreatedAt, b.ExpiresAt)
	return err
}

// GetSupportBundle retrieves a support bundle by its ID or access token
func (db *DB) GetSupportBundle(ctx context.Context, idOrToken string) (*models.SupportBundle, error) {
	query := `
		SELECT id, filename, file_path, file_size, sha256,
		       access_passcode, access_token, requested_by, tenant_slug,
		       issue_description, contact_email, download_count, created_at, expires_at
		FROM support_bundles
		WHERE id = $1 OR access_token = $1`
	var b models.SupportBundle
	err := db.pool.QueryRow(ctx, query, idOrToken).Scan(
		&b.ID, &b.Filename, &b.FilePath, &b.FileSize, &b.SHA256,
		&b.AccessPasscode, &b.AccessToken, &b.RequestedBy, &b.TenantSlug,
		&b.IssueDescription, &b.ContactEmail, &b.DownloadCount, &b.CreatedAt, &b.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ListSupportBundles lists recent support bundles
func (db *DB) ListSupportBundles(ctx context.Context, tenantSlug string, limit int) ([]models.SupportBundle, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	var query string
	var rows pgx.Rows
	var err error

	if tenantSlug != "" && tenantSlug != "all" && tenantSlug != "*" {
		query = `
			SELECT id, filename, file_path, file_size, sha256,
			       access_passcode, access_token, requested_by, tenant_slug,
			       issue_description, contact_email, download_count, created_at, expires_at
			FROM support_bundles
			WHERE tenant_slug = $1
			ORDER BY created_at DESC
			LIMIT $2`
		rows, err = db.pool.Query(ctx, query, tenantSlug, limit)
	} else {
		query = `
			SELECT id, filename, file_path, file_size, sha256,
			       access_passcode, access_token, requested_by, tenant_slug,
			       issue_description, contact_email, download_count, created_at, expires_at
			FROM support_bundles
			ORDER BY created_at DESC
			LIMIT $1`
		rows, err = db.pool.Query(ctx, query, limit)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bundles []models.SupportBundle
	for rows.Next() {
		var b models.SupportBundle
		if err := rows.Scan(
			&b.ID, &b.Filename, &b.FilePath, &b.FileSize, &b.SHA256,
			&b.AccessPasscode, &b.AccessToken, &b.RequestedBy, &b.TenantSlug,
			&b.IssueDescription, &b.ContactEmail, &b.DownloadCount, &b.CreatedAt, &b.ExpiresAt,
		); err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}
	return bundles, nil
}

// IncrementBundleDownloadCount increments download counter
func (db *DB) IncrementBundleDownloadCount(ctx context.Context, id string) error {
	query := `UPDATE support_bundles SET download_count = download_count + 1 WHERE id = $1`
	_, err := db.pool.Exec(ctx, query, id)
	return err
}

// PurgeExpiredSupportBundles deletes support bundles whose expires_at < NOW() or older than 7 days, returning their file paths
func (db *DB) PurgeExpiredSupportBundles(ctx context.Context) ([]string, error) {
	querySelect := `
		SELECT file_path
		FROM support_bundles
		WHERE expires_at <= NOW() OR created_at <= NOW() - INTERVAL '7 days'`
	rows, err := db.pool.Query(ctx, querySelect)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var filePaths []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err == nil && fp != "" {
			filePaths = append(filePaths, fp)
		}
	}

	queryDelete := `
		DELETE FROM support_bundles
		WHERE expires_at <= NOW() OR created_at <= NOW() - INTERVAL '7 days'`
	_, _ = db.pool.Exec(ctx, queryDelete)

	return filePaths, nil
}

