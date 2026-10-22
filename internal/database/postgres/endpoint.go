package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/syslog-platform/logger/internal/models"
)

// EnsureEndpointSchema creates all required tables and default records for Endpoint Security
func (db *DB) EnsureEndpointSchema(ctx context.Context) error {
	schema := `
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
	CREATE EXTENSION IF NOT EXISTS "pgcrypto";

	-- 1. Endpoint Policies
	CREATE TABLE IF NOT EXISTS endpoint_policies (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		name VARCHAR(128) NOT NULL,
		description TEXT DEFAULT '',
		revision INT NOT NULL DEFAULT 1,
		config_json JSONB NOT NULL DEFAULT '{
			"heartbeat_interval_sec": 30,
			"inventory_interval_sec": 3600,
			"patch_scan_interval_sec": 14400,
			"vuln_scan_interval_sec": 14400,
			"max_cpu_percent": 10,
			"max_ram_mb": 150,
			"spool_max_disk_mb": 500,
			"spool_max_age_hours": 72,
			"log_collection_enabled": true,
			"event_channels": ["System", "Application", "Security"]
		}'::jsonb,
		is_default BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT uq_endpoint_policies_tenant_name UNIQUE (tenant_slug, name)
	);

	CREATE INDEX IF NOT EXISTS idx_endpoint_policies_tenant ON endpoint_policies(tenant_slug);

	INSERT INTO endpoint_policies (tenant_slug, name, description, revision, is_default)
	VALUES ('default', 'Default Balanced Endpoint Policy', 'Standard balanced telemetry, inventory and patch policy for workstations and servers', 1, TRUE)
	ON CONFLICT (tenant_slug, name) DO NOTHING;

	-- 2. Endpoint Agent Groups
	CREATE TABLE IF NOT EXISTS endpoint_agent_groups (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		name VARCHAR(128) NOT NULL,
		description TEXT DEFAULT '',
		query_filter TEXT DEFAULT '',
		policy_id UUID REFERENCES endpoint_policies(id) ON DELETE SET NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT uq_endpoint_groups_tenant_name UNIQUE (tenant_slug, name)
	);

	CREATE INDEX IF NOT EXISTS idx_endpoint_groups_tenant ON endpoint_agent_groups(tenant_slug);

	INSERT INTO endpoint_agent_groups (tenant_slug, name, description)
	VALUES 
		('default', 'Default Workstations', 'All desktop and laptop client endpoints'),
		('default', 'Default Servers', 'Production, staging and internal servers')
	ON CONFLICT (tenant_slug, name) DO NOTHING;

	-- 3. Endpoint Agents
	CREATE TABLE IF NOT EXISTS endpoint_agents (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		agent_uuid VARCHAR(64) NOT NULL UNIQUE,
		hostname VARCHAR(255) NOT NULL DEFAULT '',
		fqdn VARCHAR(255) NOT NULL DEFAULT '',
		os_type VARCHAR(32) NOT NULL DEFAULT 'linux',
		os_family VARCHAR(64) NOT NULL DEFAULT '',
		os_name VARCHAR(128) NOT NULL DEFAULT '',
		os_version VARCHAR(64) NOT NULL DEFAULT '',
		os_build VARCHAR(64) NOT NULL DEFAULT '',
		kernel_version VARCHAR(128) NOT NULL DEFAULT '',
		architecture VARCHAR(32) NOT NULL DEFAULT 'amd64',
		agent_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
		ip_address VARCHAR(64) NOT NULL DEFAULT '',
		mac_address VARCHAR(64) NOT NULL DEFAULT '',
		status VARCHAR(32) NOT NULL DEFAULT 'healthy',
		health_score INT NOT NULL DEFAULT 100,
		policy_id UUID REFERENCES endpoint_policies(id) ON DELETE SET NULL,
		policy_revision INT NOT NULL DEFAULT 1,
		group_id UUID REFERENCES endpoint_agent_groups(id) ON DELETE SET NULL,
		last_seen TIMESTAMPTZ,
		last_inventory TIMESTAMPTZ,
		last_patch_scan TIMESTAMPTZ,
		last_vuln_scan TIMESTAMPTZ,
		client_cert_serial VARCHAR(128) DEFAULT '',
		client_cert_fingerprint VARCHAR(128) DEFAULT '',
		auth_token_hash VARCHAR(128) DEFAULT '',
		tags TEXT[] DEFAULT '{}',
		labels JSONB DEFAULT '{}'::jsonb,
		resource_usage JSONB DEFAULT '{
			"cpu_percent": 0.0,
			"ram_rss_bytes": 0,
			"spool_disk_bytes": 0,
			"queue_depth": 0
		}'::jsonb,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_endpoint_agents_tenant ON endpoint_agents(tenant_slug);
	CREATE INDEX IF NOT EXISTS idx_endpoint_agents_uuid ON endpoint_agents(agent_uuid);
	CREATE INDEX IF NOT EXISTS idx_endpoint_agents_status ON endpoint_agents(status);
	CREATE INDEX IF NOT EXISTS idx_endpoint_agents_last_seen ON endpoint_agents(last_seen);
	CREATE INDEX IF NOT EXISTS idx_endpoint_agents_os_type ON endpoint_agents(os_type);

	-- 4. Endpoint Agent Group Members
	CREATE TABLE IF NOT EXISTS endpoint_agent_group_members (
		group_id UUID NOT NULL REFERENCES endpoint_agent_groups(id) ON DELETE CASCADE,
		agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (group_id, agent_id)
	);

	-- 5. Enrollment Tokens
	CREATE TABLE IF NOT EXISTS endpoint_enrollment_tokens (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		token_hash VARCHAR(128) NOT NULL UNIQUE,
		token_prefix VARCHAR(16) NOT NULL DEFAULT 'lp_ea_',
		name VARCHAR(128) NOT NULL DEFAULT 'Default Enrollment Token',
		group_id UUID REFERENCES endpoint_agent_groups(id) ON DELETE SET NULL,
		max_uses INT NOT NULL DEFAULT 0,
		current_uses INT NOT NULL DEFAULT 0,
		is_one_time BOOLEAN NOT NULL DEFAULT FALSE,
		allowed_os TEXT[] DEFAULT '{}',
		labels JSONB DEFAULT '{}'::jsonb,
		expires_at TIMESTAMPTZ,
		revoked_at TIMESTAMPTZ,
		created_by VARCHAR(128) DEFAULT 'admin',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_endpoint_tokens_hash ON endpoint_enrollment_tokens(token_hash);
	CREATE INDEX IF NOT EXISTS idx_endpoint_tokens_tenant ON endpoint_enrollment_tokens(tenant_slug);

	-- 6. Current Inventory Metadata
	CREATE TABLE IF NOT EXISTS endpoint_inventory_current (
		agent_id UUID PRIMARY KEY REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		system_info JSONB DEFAULT '{}'::jsonb,
		hardware_info JSONB DEFAULT '{}'::jsonb,
		network_info JSONB DEFAULT '{}'::jsonb,
		services_info JSONB DEFAULT '[]'::jsonb,
		users_info JSONB DEFAULT '[]'::jsonb,
		processes_info JSONB DEFAULT '[]'::jsonb,
		listening_ports_info JSONB DEFAULT '[]'::jsonb,
		inventory_revision INT NOT NULL DEFAULT 1,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- 7. Software Inventory
	CREATE TABLE IF NOT EXISTS endpoint_software_current (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		name VARCHAR(255) NOT NULL,
		vendor VARCHAR(255) DEFAULT '',
		version VARCHAR(128) NOT NULL,
		arch VARCHAR(32) DEFAULT '',
		package_type VARCHAR(32) DEFAULT '',
		package_name VARCHAR(255) DEFAULT '',
		install_location TEXT DEFAULT '',
		purl VARCHAR(512) DEFAULT '',
		cpe VARCHAR(512) DEFAULT '',
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT uq_endpoint_software UNIQUE (agent_id, name, version, arch)
	);

	-- 8. CVE Catalog
	CREATE TABLE IF NOT EXISTS endpoint_cve_catalog (
		cve_id VARCHAR(64) PRIMARY KEY,
		title TEXT DEFAULT '',
		description TEXT DEFAULT '',
		published_at TIMESTAMPTZ,
		modified_at TIMESTAMPTZ,
		cvss_version VARCHAR(16) DEFAULT '3.1',
		cvss_score NUMERIC(4,1) DEFAULT 0.0,
		cvss_vector VARCHAR(128) DEFAULT '',
		severity VARCHAR(32) DEFAULT 'UNKNOWN',
		cwe VARCHAR(64) DEFAULT '',
		references_json JSONB DEFAULT '[]'::jsonb,
		cpe_criteria_json JSONB DEFAULT '[]'::jsonb,
		cisa_kev BOOLEAN NOT NULL DEFAULT FALSE,
		kev_date_added TIMESTAMPTZ,
		kev_due_date TIMESTAMPTZ,
		epss_probability NUMERIC(6,5) DEFAULT 0.0,
		epss_percentile NUMERIC(6,5) DEFAULT 0.0,
		exploit_status VARCHAR(64) DEFAULT 'NONE',
		source VARCHAR(64) DEFAULT 'NVD',
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- 9. Active Vulnerability Findings
	CREATE TABLE IF NOT EXISTS endpoint_vulnerability_findings (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		cve_id VARCHAR(64) NOT NULL REFERENCES endpoint_cve_catalog(cve_id) ON DELETE CASCADE,
		software_id UUID REFERENCES endpoint_software_current(id) ON DELETE SET NULL,
		status VARCHAR(32) NOT NULL DEFAULT 'open',
		detected_version VARCHAR(128) NOT NULL DEFAULT '',
		fixed_version VARCHAR(128) DEFAULT '',
		patch_available BOOLEAN NOT NULL DEFAULT FALSE,
		patch_id VARCHAR(128) DEFAULT '',
		cvss_score NUMERIC(4,1) DEFAULT 0.0,
		epss_probability NUMERIC(6,5) DEFAULT 0.0,
		cisa_kev BOOLEAN NOT NULL DEFAULT FALSE,
		severity VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
		priority VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
		reboot_required BOOLEAN NOT NULL DEFAULT FALSE,
		detection_source VARCHAR(64) DEFAULT '',
		evidence_json JSONB DEFAULT '{}'::jsonb,
		exception_id UUID,
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		resolved_at TIMESTAMPTZ,
		CONSTRAINT uq_endpoint_vuln_finding UNIQUE (agent_id, cve_id, software_id)
	);

	-- 10. Vulnerability Exceptions
	CREATE TABLE IF NOT EXISTS endpoint_vulnerability_exceptions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		cve_id VARCHAR(64) NOT NULL,
		agent_id UUID REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		group_id UUID REFERENCES endpoint_agent_groups(id) ON DELETE CASCADE,
		reason VARCHAR(64) NOT NULL,
		justification TEXT NOT NULL DEFAULT '',
		approved_by VARCHAR(128) NOT NULL DEFAULT 'admin',
		expires_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- 11. Endpoint Patches
	CREATE TABLE IF NOT EXISTS endpoint_patches_current (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		patch_id VARCHAR(128) NOT NULL,
		title TEXT NOT NULL,
		vendor VARCHAR(128) DEFAULT '',
		kb_id VARCHAR(64) DEFAULT '',
		severity VARCHAR(32) DEFAULT 'UNKNOWN',
		cve_ids TEXT[] DEFAULT '{}',
		requires_reboot BOOLEAN NOT NULL DEFAULT FALSE,
		status VARCHAR(32) NOT NULL DEFAULT 'missing',
		installed_at TIMESTAMPTZ,
		detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT uq_endpoint_patches UNIQUE (agent_id, patch_id)
	);

	-- 12. Endpoint Remote Tasks
	CREATE TABLE IF NOT EXISTS endpoint_tasks (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		agent_id UUID REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		group_id UUID REFERENCES endpoint_agent_groups(id) ON DELETE SET NULL,
		task_type VARCHAR(64) NOT NULL,
		payload_json JSONB DEFAULT '{}'::jsonb,
		status VARCHAR(32) NOT NULL DEFAULT 'pending',
		created_by VARCHAR(128) DEFAULT 'admin',
		scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		started_at TIMESTAMPTZ,
		completed_at TIMESTAMPTZ,
		error_message TEXT DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- 13. Task Results
	CREATE TABLE IF NOT EXISTS endpoint_task_results (
		task_id UUID PRIMARY KEY REFERENCES endpoint_tasks(id) ON DELETE CASCADE,
		agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		status VARCHAR(32) NOT NULL DEFAULT 'completed',
		exit_code INT NOT NULL DEFAULT 0,
		stdout TEXT DEFAULT '',
		stderr TEXT DEFAULT '',
		execution_duration_ms BIGINT DEFAULT 0,
		completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- 14. Feed Sources
	CREATE TABLE IF NOT EXISTS endpoint_feed_sources (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(64) NOT NULL UNIQUE,
		feed_type VARCHAR(64) NOT NULL,
		url TEXT DEFAULT '',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		sync_interval_minutes INT NOT NULL DEFAULT 360,
		last_sync_at TIMESTAMPTZ,
		last_sync_status VARCHAR(32) DEFAULT 'pending',
		last_error TEXT DEFAULT '',
		records_count BIGINT DEFAULT 0,
		config_json JSONB DEFAULT '{}'::jsonb,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	INSERT INTO endpoint_feed_sources (name, feed_type, url, enabled, sync_interval_minutes)
	VALUES
		('nvd', 'cve_nvd_api', 'https://services.nvd.nist.gov/rest/json/cves/2.0', TRUE, 360),
		('cisa_kev', 'cisa_kev_json', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', TRUE, 720),
		('epss', 'first_epss_csv', 'https://epss.cyentia.com/epss_scores-current.csv.gz', TRUE, 1440),
		('osv', 'osv_ecosystems', 'https://osv.dev/docs/api', TRUE, 720)
	ON CONFLICT (name) DO NOTHING;

	ALTER TABLE endpoint_vulnerability_findings ADD COLUMN IF NOT EXISTS severity VARCHAR(32) DEFAULT 'UNKNOWN';
	CREATE INDEX IF NOT EXISTS idx_endpoint_findings_severity ON endpoint_vulnerability_findings(severity);
	`

	_, err := db.pool.Exec(ctx, schema)
	return err
}

// GenerateEnrollmentToken creates a cryptographically secure token: lp_ea_<hex>
func GenerateEnrollmentToken() (rawToken string, tokenHash string, err error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	rawToken = "lp_ea_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash = hex.EncodeToString(sum[:])
	return rawToken, tokenHash, nil
}

// HashToken computes sha256 hex string of a token
func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// CreateEnrollmentToken inserts a new enrollment token into the database
func (db *DB) CreateEnrollmentToken(ctx context.Context, tenantSlug, name string, groupID *uuid.UUID, maxUses int, isOneTime bool, allowedOS []string, expiresAt *time.Time, createdBy string) (*models.EndpointEnrollmentToken, error) {
	rawToken, tokenHash, err := GenerateEnrollmentToken()
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	allowedOSArray := allowedOS
	if allowedOSArray == nil {
		allowedOSArray = []string{}
	}

	query := `
		INSERT INTO endpoint_enrollment_tokens (
			tenant_slug, token_hash, token_prefix, name, group_id, max_uses, is_one_time, allowed_os, expires_at, created_by
		) VALUES ($1, $2, 'lp_ea_', $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at
	`

	var t models.EndpointEnrollmentToken
	t.TenantSlug = tenantSlug
	t.Token = rawToken
	t.TokenHash = tokenHash
	t.TokenPrefix = "lp_ea_"
	t.Name = name
	t.GroupID = groupID
	t.MaxUses = maxUses
	t.IsOneTime = isOneTime
	t.AllowedOS = allowedOSArray
	t.ExpiresAt = expiresAt
	t.CreatedBy = createdBy

	err = db.pool.QueryRow(ctx, query, tenantSlug, tokenHash, name, groupID, maxUses, isOneTime, allowedOSArray, expiresAt, createdBy).
		Scan(&t.ID, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting enrollment token: %w", err)
	}

	return &t, nil
}

// ListEnrollmentTokens returns tokens for a tenant (or all if empty)
func (db *DB) ListEnrollmentTokens(ctx context.Context, tenantSlug string) ([]models.EndpointEnrollmentToken, error) {
	query := `
		SELECT t.id, t.tenant_slug, t.token_hash, t.token_prefix, t.name, t.group_id, 
		       COALESCE(g.name, '') as group_name, t.max_uses, t.current_uses, t.is_one_time, 
		       t.allowed_os, t.expires_at, t.revoked_at, t.created_by, t.created_at
		FROM endpoint_enrollment_tokens t
		LEFT JOIN endpoint_agent_groups g ON t.group_id = g.id
		WHERE ($1 = '' OR $1 = 'all' OR t.tenant_slug = $1)
		ORDER BY t.created_at DESC
	`

	rows, err := db.pool.Query(ctx, query, tenantSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []models.EndpointEnrollmentToken
	for rows.Next() {
		var tok models.EndpointEnrollmentToken
		err := rows.Scan(
			&tok.ID, &tok.TenantSlug, &tok.TokenHash, &tok.TokenPrefix, &tok.Name,
			&tok.GroupID, &tok.GroupName, &tok.MaxUses, &tok.CurrentUses, &tok.IsOneTime,
			&tok.AllowedOS, &tok.ExpiresAt, &tok.RevokedAt, &tok.CreatedBy, &tok.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
	}
	return tokens, nil
}

// RevokeEnrollmentToken marks a token as revoked
func (db *DB) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, tenantSlug string) error {
	query := `
		UPDATE endpoint_enrollment_tokens
		SET revoked_at = NOW()
		WHERE id = $1 AND ($2 = '' OR $2 = 'all' OR tenant_slug = $2)
	`
	tag, err := db.pool.Exec(ctx, query, id, tenantSlug)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("token not found or unauthorized")
	}
	return nil
}

// ValidateAndConsumeEnrollmentToken checks validity, increments use count, and returns tenant & assigned group
func (db *DB) ValidateAndConsumeEnrollmentToken(ctx context.Context, rawToken, osType string) (tenantSlug string, groupID *uuid.UUID, err error) {
	tokenHash := HashToken(rawToken)

	query := `
		SELECT id, tenant_slug, group_id, max_uses, current_uses, is_one_time, allowed_os, expires_at, revoked_at
		FROM endpoint_enrollment_tokens
		WHERE token_hash = $1
	`

	var (
		id          uuid.UUID
		tSlug       string
		gID         *uuid.UUID
		maxUses     int
		currentUses int
		isOneTime   bool
		allowedOS   []string
		expiresAt   *time.Time
		revokedAt   *time.Time
	)

	err = db.pool.QueryRow(ctx, query, tokenHash).Scan(
		&id, &tSlug, &gID, &maxUses, &currentUses, &isOneTime, &allowedOS, &expiresAt, &revokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return "", nil, errors.New("invalid enrollment token")
		}
		return "", nil, fmt.Errorf("querying token: %w", err)
	}

	if revokedAt != nil {
		return "", nil, errors.New("enrollment token has been revoked")
	}
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return "", nil, errors.New("enrollment token has expired")
	}
	if isOneTime && currentUses >= 1 {
		return "", nil, errors.New("one-time enrollment token has already been used")
	}
	if maxUses > 0 && currentUses >= maxUses {
		return "", nil, errors.New("enrollment token maximum usage limit reached")
	}

	// Check platform restriction if configured
	if len(allowedOS) > 0 && osType != "" {
		allowed := false
		for _, o := range allowedOS {
			if o == osType || o == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", nil, fmt.Errorf("enrollment token restricted to platforms: %v", allowedOS)
		}
	}

	// Increment usage
	_, _ = db.pool.Exec(ctx, `UPDATE endpoint_enrollment_tokens SET current_uses = current_uses + 1 WHERE id = $1`, id)

	return tSlug, gID, nil
}

// UpsertEnrolledAgent registers a new agent or updates its connection details upon re-enrollment
func (db *DB) UpsertEnrolledAgent(ctx context.Context, req models.AgentEnrollRequest, tenantSlug string, groupID *uuid.UUID, authTokenHash string) (*models.EndpointAgent, error) {
	// Look up default policy for the tenant
	var defaultPolicyID *uuid.UUID
	var defaultPolicyRev int = 1
	_ = db.pool.QueryRow(ctx, `SELECT id, revision FROM endpoint_policies WHERE tenant_slug = $1 AND is_default = TRUE LIMIT 1`, tenantSlug).
		Scan(&defaultPolicyID, &defaultPolicyRev)

	if defaultPolicyID == nil {
		// Fallback to global default policy
		_ = db.pool.QueryRow(ctx, `SELECT id, revision FROM endpoint_policies WHERE is_default = TRUE LIMIT 1`).
			Scan(&defaultPolicyID, &defaultPolicyRev)
	}

	query := `
		INSERT INTO endpoint_agents (
			tenant_slug, agent_uuid, hostname, fqdn, os_type, os_family, os_name, os_version,
			os_build, kernel_version, architecture, agent_version, ip_address, mac_address,
			status, health_score, policy_id, policy_revision, group_id, auth_token_hash, last_seen
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14,
			'healthy', 100, $15, $16, $17, $18, NOW()
		)
		ON CONFLICT (agent_uuid) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			fqdn = EXCLUDED.fqdn,
			os_type = EXCLUDED.os_type,
			os_family = EXCLUDED.os_family,
			os_name = EXCLUDED.os_name,
			os_version = EXCLUDED.os_version,
			os_build = EXCLUDED.os_build,
			kernel_version = EXCLUDED.kernel_version,
			architecture = EXCLUDED.architecture,
			agent_version = EXCLUDED.agent_version,
			ip_address = EXCLUDED.ip_address,
			mac_address = EXCLUDED.mac_address,
			auth_token_hash = EXCLUDED.auth_token_hash,
			status = 'healthy',
			last_seen = NOW(),
			updated_at = NOW()
		RETURNING id, tenant_slug, agent_uuid, hostname, status, policy_id, policy_revision, group_id, created_at, updated_at
	`

	var a models.EndpointAgent
	err := db.pool.QueryRow(ctx, query,
		tenantSlug, req.AgentUUID, req.Hostname, req.FQDN, req.OSType, req.OSFamily, req.OSName, req.OSVersion,
		req.OSBuild, req.KernelVersion, req.Architecture, req.AgentVersion, req.IPAddress, req.MACAddress,
		defaultPolicyID, defaultPolicyRev, groupID, authTokenHash,
	).Scan(
		&a.ID, &a.TenantSlug, &a.AgentUUID, &a.Hostname, &a.Status, &a.PolicyID, &a.PolicyRevision, &a.GroupID, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upserting agent: %w", err)
	}

	return &a, nil
}

// UpdateAgentHeartbeat updates agent last_seen, metrics, and IP on heartbeat
func (db *DB) UpdateAgentHeartbeat(ctx context.Context, hb models.AgentHeartbeatRequest) (*models.AgentHeartbeatResponse, error) {
	metricsJSON, _ := json.Marshal(hb.Metrics)

	query := `
		UPDATE endpoint_agents
		SET last_seen = NOW(),
		    status = $2,
		    agent_version = $3,
		    ip_address = CASE WHEN $4 != '' THEN $4 ELSE ip_address END,
		    mac_address = CASE WHEN $5 != '' THEN $5 ELSE mac_address END,
		    resource_usage = $6,
		    updated_at = NOW()
		WHERE agent_uuid = $1
		RETURNING policy_revision
	`

	var currentRevision int
	err := db.pool.QueryRow(ctx, query,
		hb.AgentUUID, hb.Status, hb.AgentVersion, hb.IPAddress, hb.MACAddress, metricsJSON,
	).Scan(&currentRevision)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("agent not found or unenrolled")
		}
		return nil, fmt.Errorf("updating heartbeat: %w", err)
	}

	resp := &models.AgentHeartbeatResponse{
		Ack:                   true,
		ServerTime:            time.Now().UTC(),
		CurrentPolicyRevision: currentRevision,
		PolicyNeedsUpdate:     currentRevision > hb.PolicyRevision,
		PendingTasksCount:     0,
	}

	return resp, nil
}

// ListAgents returns agents filtered by tenant
func (db *DB) ListAgents(ctx context.Context, tenantSlug, status, osType, search string, limit, offset int) ([]models.EndpointAgent, int, error) {
	if limit <= 0 {
		limit = 50
	}

	countQuery := `
		SELECT COUNT(*)
		FROM endpoint_agents a
		WHERE ($1 = '' OR $1 = 'all' OR a.tenant_slug = $1)
		  AND ($2 = '' OR a.status = $2)
		  AND ($3 = '' OR a.os_type = $3)
		  AND ($4 = '' OR a.hostname ILIKE '%' || $4 || '%' OR a.ip_address ILIKE '%' || $4 || '%' OR a.agent_uuid ILIKE '%' || $4 || '%')
	`
	var total int
	err := db.pool.QueryRow(ctx, countQuery, tenantSlug, status, osType, search).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `
		SELECT a.id, a.tenant_slug, a.agent_uuid, a.hostname, a.fqdn, a.os_type, a.os_family,
		       a.os_name, a.os_version, a.os_build, a.kernel_version, a.architecture, a.agent_version,
		       a.ip_address, a.mac_address, a.status, a.health_score, a.policy_id,
		       COALESCE(p.name, '') as policy_name, a.policy_revision, a.group_id,
		       COALESCE(g.name, '') as group_name, a.last_seen, a.last_inventory, a.last_patch_scan,
		       a.last_vuln_scan, a.tags, a.labels, a.resource_usage, a.created_at, a.updated_at,
		       COALESCE((SELECT COUNT(*) FROM endpoint_vulnerability_findings vf WHERE vf.agent_id = a.id AND vf.status = 'open'), 0) as open_vulns,
		       COALESCE((SELECT COUNT(*) FROM endpoint_vulnerability_findings vf WHERE vf.agent_id = a.id AND vf.status = 'open' AND (vf.severity = 'CRITICAL' OR vf.priority = 'CRITICAL')), 0) as crit_vulns,
		       COALESCE((SELECT COUNT(*) FROM endpoint_patches_current pc WHERE pc.agent_id = a.id AND pc.status = 'missing'), 0) as missing_patches,
		       COALESCE((SELECT bool_or(pc.requires_reboot) FROM endpoint_patches_current pc WHERE pc.agent_id = a.id AND pc.status IN ('missing', 'pending_reboot')), false) as reboot_req
		FROM endpoint_agents a
		LEFT JOIN endpoint_policies p ON a.policy_id = p.id
		LEFT JOIN endpoint_agent_groups g ON a.group_id = g.id
		WHERE ($1 = '' OR $1 = 'all' OR a.tenant_slug = $1)
		  AND ($2 = '' OR a.status = $2)
		  AND ($3 = '' OR a.os_type = $3)
		  AND ($4 = '' OR a.hostname ILIKE '%' || $4 || '%' OR a.ip_address ILIKE '%' || $4 || '%' OR a.agent_uuid ILIKE '%' || $4 || '%')
		ORDER BY a.last_seen DESC NULLS LAST
		LIMIT $5 OFFSET $6
	`

	rows, err := db.pool.Query(ctx, query, tenantSlug, status, osType, search, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var agents []models.EndpointAgent
	for rows.Next() {
		var a models.EndpointAgent
		var resourceBytes []byte
		var labelBytes []byte

		err := rows.Scan(
			&a.ID, &a.TenantSlug, &a.AgentUUID, &a.Hostname, &a.FQDN, &a.OSType, &a.OSFamily,
			&a.OSName, &a.OSVersion, &a.OSBuild, &a.KernelVersion, &a.Architecture, &a.AgentVersion,
			&a.IPAddress, &a.MACAddress, &a.Status, &a.HealthScore, &a.PolicyID,
			&a.PolicyName, &a.PolicyRevision, &a.GroupID,
			&a.GroupName, &a.LastSeen, &a.LastInventory, &a.LastPatchScan,
			&a.LastVulnScan, &a.Tags, &labelBytes, &resourceBytes, &a.CreatedAt, &a.UpdatedAt,
			&a.OpenVulnsCount, &a.CriticalVulnsCount, &a.MissingPatchesCount, &a.RebootRequired,
		)
		if err != nil {
			return nil, 0, err
		}
		if len(resourceBytes) > 0 {
			a.ResourceUsage = resourceBytes
		}
		if len(labelBytes) > 0 {
			a.Labels = labelBytes
		}
		agents = append(agents, a)
	}

	return agents, total, nil
}

// GetAgentByID retrieves single agent details
func (db *DB) GetAgentByID(ctx context.Context, id uuid.UUID, tenantSlug string) (*models.EndpointAgent, error) {
	query := `
		SELECT a.id, a.tenant_slug, a.agent_uuid, a.hostname, a.fqdn, a.os_type, a.os_family,
		       a.os_name, a.os_version, a.os_build, a.kernel_version, a.architecture, a.agent_version,
		       a.ip_address, a.mac_address, a.status, a.health_score, a.policy_id,
		       COALESCE(p.name, '') as policy_name, a.policy_revision, a.group_id,
		       COALESCE(g.name, '') as group_name, a.last_seen, a.last_inventory, a.last_patch_scan,
		       a.last_vuln_scan, a.tags, a.labels, a.resource_usage, a.created_at, a.updated_at,
		       COALESCE((SELECT COUNT(*) FROM endpoint_vulnerability_findings vf WHERE vf.agent_id = a.id AND vf.status = 'open'), 0) as open_vulns,
		       COALESCE((SELECT COUNT(*) FROM endpoint_vulnerability_findings vf WHERE vf.agent_id = a.id AND vf.status = 'open' AND (vf.severity = 'CRITICAL' OR vf.priority = 'CRITICAL')), 0) as crit_vulns,
		       COALESCE((SELECT COUNT(*) FROM endpoint_patches_current pc WHERE pc.agent_id = a.id AND pc.status = 'missing'), 0) as missing_patches,
		       COALESCE((SELECT bool_or(pc.requires_reboot) FROM endpoint_patches_current pc WHERE pc.agent_id = a.id AND pc.status IN ('missing', 'pending_reboot')), false) as reboot_req
		FROM endpoint_agents a
		LEFT JOIN endpoint_policies p ON a.policy_id = p.id
		LEFT JOIN endpoint_agent_groups g ON a.group_id = g.id
		WHERE a.id = $1 AND ($2 = '' OR $2 = 'all' OR a.tenant_slug = $2)
	`

	var a models.EndpointAgent
	var resourceBytes []byte
	var labelBytes []byte

	err := db.pool.QueryRow(ctx, query, id, tenantSlug).Scan(
		&a.ID, &a.TenantSlug, &a.AgentUUID, &a.Hostname, &a.FQDN, &a.OSType, &a.OSFamily,
		&a.OSName, &a.OSVersion, &a.OSBuild, &a.KernelVersion, &a.Architecture, &a.AgentVersion,
		&a.IPAddress, &a.MACAddress, &a.Status, &a.HealthScore, &a.PolicyID,
		&a.PolicyName, &a.PolicyRevision, &a.GroupID,
		&a.GroupName, &a.LastSeen, &a.LastInventory, &a.LastPatchScan,
		&a.LastVulnScan, &a.Tags, &labelBytes, &resourceBytes, &a.CreatedAt, &a.UpdatedAt,
		&a.OpenVulnsCount, &a.CriticalVulnsCount, &a.MissingPatchesCount, &a.RebootRequired,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("agent not found")
		}
		return nil, err
	}
	if len(resourceBytes) > 0 {
		a.ResourceUsage = resourceBytes
	}
	if len(labelBytes) > 0 {
		a.Labels = labelBytes
	}

	return &a, nil
}

// GetEndpointDashboardSummary calculates dashboard statistics
func (db *DB) GetEndpointDashboardSummary(ctx context.Context, tenantSlug string) (*models.EndpointDashboardSummary, error) {
	summary := &models.EndpointDashboardSummary{
		TopVulnerableAgents: []models.EndpointAgentSummary{},
		TopCVEs:             []models.EndpointCVESummary{},
	}

	queryAgents := `
		SELECT 
			COUNT(*),
			COALESCE(COUNT(*) FILTER (WHERE status = 'healthy' AND last_seen > NOW() - INTERVAL '3 minutes'), 0) as online,
			COALESCE(COUNT(*) FILTER (WHERE status = 'offline' OR last_seen <= NOW() - INTERVAL '15 minutes'), 0) as offline,
			COALESCE(COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '15 minutes' AND last_seen <= NOW() - INTERVAL '3 minutes'), 0) as stale,
			COALESCE(COUNT(*) FILTER (WHERE os_type = 'windows'), 0) as win,
			COALESCE(COUNT(*) FILTER (WHERE os_type = 'linux'), 0) as lin,
			COALESCE(COUNT(*) FILTER (WHERE os_type = 'darwin'), 0) as mac
		FROM endpoint_agents
		WHERE ($1 = '' OR $1 = 'all' OR tenant_slug = $1)
	`
	_ = db.pool.QueryRow(ctx, queryAgents, tenantSlug).Scan(
		&summary.TotalAgents, &summary.OnlineAgents, &summary.OfflineAgents, &summary.StaleAgents,
		&summary.WindowsAgents, &summary.LinuxAgents, &summary.DarwinAgents,
	)

	queryVulns := `
		SELECT
			COALESCE(COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND status = 'open'), 0) as crit,
			COALESCE(COUNT(*) FILTER (WHERE severity = 'HIGH' AND status = 'open'), 0) as high,
			COALESCE(COUNT(*) FILTER (WHERE severity = 'MEDIUM' AND status = 'open'), 0) as med,
			COALESCE(COUNT(*) FILTER (WHERE severity = 'LOW' AND status = 'open'), 0) as low,
			COALESCE(COUNT(*) FILTER (WHERE cisa_kev = true AND status = 'open'), 0) as kev,
			COALESCE(COUNT(*) FILTER (WHERE epss_probability >= 0.1 AND status = 'open'), 0) as high_epss,
			COALESCE(COUNT(DISTINCT agent_id) FILTER (WHERE severity = 'CRITICAL' AND status = 'open'), 0) as agents_with_crit,
			COALESCE(COUNT(DISTINCT agent_id) FILTER (WHERE reboot_required = true), 0) as agents_reboot
		FROM endpoint_vulnerability_findings
		WHERE ($1 = '' OR $1 = 'all' OR tenant_slug = $1)
	`
	_ = db.pool.QueryRow(ctx, queryVulns, tenantSlug).Scan(
		&summary.CriticalVulns, &summary.HighVulns, &summary.MediumVulns, &summary.LowVulns,
		&summary.CISAKEVVulns, &summary.HighEPSSVulns, &summary.EndpointsWithCrit, &summary.EndpointsNeedReboot,
	)

	// Patch Compliance
	queryPatches := `
		SELECT
			COALESCE(COUNT(DISTINCT agent_id) FILTER (WHERE NOT EXISTS (SELECT 1 FROM endpoint_patches_current p WHERE p.agent_id = a.id AND p.status = 'missing')), 0) as fully_patched,
			COALESCE(COUNT(DISTINCT agent_id) FILTER (WHERE EXISTS (SELECT 1 FROM endpoint_patches_current p WHERE p.agent_id = a.id AND p.status = 'missing')), 0) as missing_patches
		FROM endpoint_agents a
		WHERE ($1 = '' OR $1 = 'all' OR a.tenant_slug = $1)
	`
	_ = db.pool.QueryRow(ctx, queryPatches, tenantSlug).Scan(
		&summary.FullyPatchedAgents, &summary.MissingSecPatchAgents,
	)

	if summary.TotalAgents > 0 {
		summary.PatchCompliancePct = float64(summary.FullyPatchedAgents) / float64(summary.TotalAgents) * 100.0
	} else {
		summary.PatchCompliancePct = 100.0
	}

	return summary, nil
}
