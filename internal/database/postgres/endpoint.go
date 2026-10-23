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
	"log"
	"strings"
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
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		is_isolated BOOLEAN NOT NULL DEFAULT FALSE,
		isolated_at TIMESTAMPTZ,
		isolation_reason TEXT DEFAULT ''
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

	-- Active Response & EDR Isolation migrations
	ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS is_isolated BOOLEAN DEFAULT FALSE;
	ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS isolated_at TIMESTAMPTZ;
	ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS isolation_reason TEXT DEFAULT '';
	CREATE INDEX IF NOT EXISTS idx_endpoint_agents_is_isolated ON endpoint_agents(is_isolated);

	-- Quarantined files tracking
	CREATE TABLE IF NOT EXISTS endpoint_quarantined_files (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
		original_path TEXT NOT NULL,
		quarantine_path TEXT NOT NULL,
		sha256 VARCHAR(64) NOT NULL DEFAULT '',
		size_bytes BIGINT DEFAULT 0,
		reason TEXT DEFAULT '',
		quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_quarantined_files_agent ON endpoint_quarantined_files(agent_id);
	`

	_, err := db.pool.Exec(ctx, schema)
	if err != nil {
		return err
	}
	_, _ = db.MergeDuplicateAgents(ctx, "")
	return nil
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

// DeleteEnrollmentToken permanently deletes an enrollment token
func (db *DB) DeleteEnrollmentToken(ctx context.Context, id uuid.UUID, tenantSlug string) error {
	query := `
		DELETE FROM endpoint_enrollment_tokens
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

// PurgeInactiveEnrollmentTokens deletes all revoked, expired, or fully consumed tokens
func (db *DB) PurgeInactiveEnrollmentTokens(ctx context.Context, tenantSlug string) (int64, error) {
	query := `
		DELETE FROM endpoint_enrollment_tokens
		WHERE (revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at < NOW()) OR (max_uses > 0 AND current_uses >= max_uses))
		  AND ($1 = '' OR $1 = 'all' OR tenant_slug = $1)
	`
	tag, err := db.pool.Exec(ctx, query, tenantSlug)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
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

	// Proactively merge any duplicate agents on the same host and IP
	_, _ = db.MergeDuplicateAgents(ctx, tenantSlug)

	return &a, nil
}

// MergeDuplicateAgents merges historical/inactive duplicate agents sharing the same hostname and IP
// into the most recently active agent instance, consolidating software, vulns, patches, and FIM events.
func (db *DB) MergeDuplicateAgents(ctx context.Context, tenantSlug string) (int, error) {
	groupQuery := `
		SELECT tenant_slug, LOWER(hostname) AS l_hostname, ip_address, COUNT(*) as cnt
		FROM endpoint_agents
		WHERE ($1 = '' OR tenant_slug = $1) AND ip_address != ''
		GROUP BY tenant_slug, LOWER(hostname), ip_address
		HAVING COUNT(*) > 1
	`
	rows, err := db.pool.Query(ctx, groupQuery, tenantSlug)
	if err != nil {
		return 0, fmt.Errorf("querying duplicate agent groups: %w", err)
	}
	defer rows.Close()

	type dupGroup struct {
		TenantSlug string
		Hostname   string
		IPAddress  string
	}
	var groups []dupGroup
	for rows.Next() {
		var g dupGroup
		var cnt int
		if err := rows.Scan(&g.TenantSlug, &g.Hostname, &g.IPAddress, &cnt); err == nil {
			groups = append(groups, g)
		}
	}
	rows.Close()

	totalRemoved := 0

	for _, g := range groups {
		agentRows, err := db.pool.Query(ctx, `
			SELECT id, health_score, created_at
			FROM endpoint_agents
			WHERE tenant_slug = $1 AND LOWER(hostname) = $2 AND ip_address = $3
			ORDER BY last_seen DESC NULLS LAST, created_at DESC
		`, g.TenantSlug, g.Hostname, g.IPAddress)
		if err != nil {
			continue
		}

		type agentRecord struct {
			ID          uuid.UUID
			HealthScore int
			CreatedAt   time.Time
		}
		var agents []agentRecord
		for agentRows.Next() {
			var ar agentRecord
			if err := agentRows.Scan(&ar.ID, &ar.HealthScore, &ar.CreatedAt); err == nil {
				agents = append(agents, ar)
			}
		}
		agentRows.Close()

		if len(agents) <= 1 {
			continue
		}

		winner := agents[0]
		oldAgents := agents[1:]

		for _, old := range oldAgents {
			tx, err := db.pool.Begin(ctx)
			if err != nil {
				continue
			}

			// 1. Preserve earliest creation date and lowest health score (highest risk)
			_, _ = tx.Exec(ctx, `
				UPDATE endpoint_agents 
				SET created_at = LEAST(created_at, $1),
				    health_score = LEAST(health_score, $2)
				WHERE id = $3
			`, old.CreatedAt, old.HealthScore, winner.ID)

			// 2. Inventory: If winner doesn't have inventory, take old; else delete old
			var hasWinnerInv bool
			_ = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM endpoint_inventory_current WHERE agent_id = $1)`, winner.ID).Scan(&hasWinnerInv)
			if hasWinnerInv {
				_, _ = tx.Exec(ctx, `DELETE FROM endpoint_inventory_current WHERE agent_id = $1`, old.ID)
			} else {
				_, _ = tx.Exec(ctx, `UPDATE endpoint_inventory_current SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)
			}

			// 3. Software: Delete duplicates, migrate remaining
			_, _ = tx.Exec(ctx, `
				DELETE FROM endpoint_software_current old
				WHERE old.agent_id = $1 AND EXISTS (
					SELECT 1 FROM endpoint_software_current tgt
					WHERE tgt.agent_id = $2 AND tgt.name = old.name AND tgt.version = old.version AND tgt.arch = old.arch
				)
			`, old.ID, winner.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_software_current SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 4. Vulnerabilities: Delete duplicates, migrate remaining
			_, _ = tx.Exec(ctx, `
				DELETE FROM endpoint_vulnerability_findings old
				WHERE old.agent_id = $1 AND EXISTS (
					SELECT 1 FROM endpoint_vulnerability_findings tgt
					WHERE tgt.agent_id = $2 AND tgt.cve_id = old.cve_id
					  AND (tgt.software_id = old.software_id OR (tgt.software_id IS NULL AND old.software_id IS NULL))
				)
			`, old.ID, winner.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_vulnerability_findings SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 5. Patches: Delete duplicates, migrate remaining
			_, _ = tx.Exec(ctx, `
				DELETE FROM endpoint_patches_current old
				WHERE old.agent_id = $1 AND EXISTS (
					SELECT 1 FROM endpoint_patches_current tgt
					WHERE tgt.agent_id = $2 AND tgt.patch_id = old.patch_id
				)
			`, old.ID, winner.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_patches_current SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 6. FIM Baselines: Delete duplicates, migrate remaining
			_, _ = tx.Exec(ctx, `
				DELETE FROM endpoint_fim_baselines old
				WHERE old.agent_id = $1 AND EXISTS (
					SELECT 1 FROM endpoint_fim_baselines tgt
					WHERE tgt.agent_id = $2 AND tgt.target_path = old.target_path
				)
			`, old.ID, winner.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_fim_baselines SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 7. FIM Events
			_, _ = tx.Exec(ctx, `UPDATE endpoint_fim_events SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 8. Tasks & Results
			_, _ = tx.Exec(ctx, `UPDATE endpoint_tasks SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_task_results SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 9. Groups: Delete duplicates, migrate remaining
			_, _ = tx.Exec(ctx, `
				DELETE FROM endpoint_agent_group_members old
				WHERE old.agent_id = $1 AND EXISTS (
					SELECT 1 FROM endpoint_agent_group_members tgt
					WHERE tgt.agent_id = $2 AND tgt.group_id = old.group_id
				)
			`, old.ID, winner.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_agent_group_members SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 10. Quarantined Files
			_, _ = tx.Exec(ctx, `UPDATE endpoint_quarantined_files SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 11. Vulnerability Exceptions
			_, _ = tx.Exec(ctx, `UPDATE endpoint_vulnerability_exceptions SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 12. SOAR Executions
			_, _ = tx.Exec(ctx, `UPDATE soar_executions SET target_agent_id = $1 WHERE target_agent_id = $2`, winner.ID, old.ID)

			// 13. USB Devices: Delete duplicate hardware records, migrate remaining
			_, _ = tx.Exec(ctx, `
				DELETE FROM endpoint_usb_devices old
				WHERE old.agent_id = $1 AND EXISTS (
					SELECT 1 FROM endpoint_usb_devices tgt
					WHERE tgt.agent_id = $2 AND tgt.vendor_id = old.vendor_id 
					  AND tgt.product_id = old.product_id AND tgt.serial_number = old.serial_number
					  AND tgt.device_id = old.device_id
				)
			`, old.ID, winner.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_usb_devices SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 14. USB DLP Events
			_, _ = tx.Exec(ctx, `UPDATE endpoint_usb_events SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 15. EDR Process Anomalies (Phase N)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_process_anomalies SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 16. Network & DNS EDR Connections, DNS Queries & Firewall Rules (Phase O)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_network_connections SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_dns_queries SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)
			_, _ = tx.Exec(ctx, `UPDATE endpoint_firewall_rules SET agent_id = $1 WHERE agent_id = $2`, winner.ID, old.ID)

			// 17. Delete the old inactive agent
			_, err = tx.Exec(ctx, `DELETE FROM endpoint_agents WHERE id = $1`, old.ID)
			if err != nil {
				log.Printf("[MergeDuplicateAgents] Failed to delete old agent %s: %v", old.ID, err)
				_ = tx.Rollback(ctx)
				continue
			}

			if err := tx.Commit(ctx); err == nil {
				totalRemoved++
				log.Printf("[MergeDuplicateAgents] Successfully merged agent %s into %s", old.ID, winner.ID)
			} else {
				log.Printf("[MergeDuplicateAgents] Failed to commit merge tx for %s: %v", old.ID, err)
			}
		}
	}

	return totalRemoved, nil
}

// UpdateAgentHeartbeat updates agent last_seen, metrics, and IP on heartbeat
func (db *DB) UpdateAgentHeartbeat(ctx context.Context, hb models.AgentHeartbeatRequest) (*models.AgentHeartbeatResponse, error) {
	metricsJSON, _ := json.Marshal(hb.Metrics)

	// Compute dynamic host health score (0 - 100)
	healthScore := 100
	if hb.Metrics.CPUPercent > 90 {
		healthScore -= 20
	} else if hb.Metrics.CPUPercent > 75 {
		healthScore -= 10
	}

	if hb.Metrics.RAMPercent > 90 {
		healthScore -= 25
	} else if hb.Metrics.RAMPercent > 80 {
		healthScore -= 10
	}

	if hb.Metrics.DiskPercent > 90 {
		healthScore -= 25
	} else if hb.Metrics.DiskPercent > 80 {
		healthScore -= 10
	}

	if hb.RebootRequired {
		healthScore -= 10
	}

	// Check critical vulnerability findings
	var critVulns int
	_ = db.pool.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM endpoint_vulnerability_findings vf
		JOIN endpoint_agents a ON a.id = vf.agent_id
		WHERE a.agent_uuid = $1 AND vf.status = 'open' AND (vf.severity = 'CRITICAL' OR vf.priority = 'CRITICAL')
	`, hb.AgentUUID).Scan(&critVulns)

	healthScore -= (critVulns * 10)
	if healthScore < 0 {
		healthScore = 0
	}

	query := `
		WITH updated AS (
			UPDATE endpoint_agents
			SET last_seen = NOW(),
			    status = $2,
			    agent_version = $3,
			    ip_address = CASE WHEN $4 != '' THEN $4 ELSE ip_address END,
			    mac_address = CASE WHEN $5 != '' THEN $5 ELSE mac_address END,
			    resource_usage = $6,
			    health_score = $7,
			    updated_at = NOW()
			WHERE agent_uuid = $1
			RETURNING id, policy_id, policy_revision, os_type, architecture
		)
		SELECT u.id, u.policy_revision, u.os_type, u.architecture,
		       COALESCE(p.revision, u.policy_revision, 1) as effective_revision,
		       p.config_json
		FROM updated u
		LEFT JOIN endpoint_policies p ON u.policy_id = p.id
	`

	var agentDBID uuid.UUID
	var agentRevision, effectiveRevision int
	var osType, arch string
	var policyConfigJSON []byte
	err := db.pool.QueryRow(ctx, query,
		hb.AgentUUID, hb.Status, hb.AgentVersion, hb.IPAddress, hb.MACAddress, metricsJSON, healthScore,
	).Scan(&agentDBID, &agentRevision, &osType, &arch, &effectiveRevision, &policyConfigJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("agent not found or unenrolled")
		}
		return nil, fmt.Errorf("updating heartbeat: %w", err)
	}

	var pendingTasks []models.EndpointTask
	taskRows, err := db.pool.Query(ctx, `
		UPDATE endpoint_tasks
		SET status = 'running', started_at = NOW()
		WHERE id IN (
			SELECT id FROM endpoint_tasks
			WHERE agent_id = $1 AND status = 'pending'
			ORDER BY scheduled_at ASC
			LIMIT 5
		)
		RETURNING id, tenant_slug, agent_id, task_type, payload_json, status, created_by, scheduled_at, started_at, created_at
	`, agentDBID)
	if err == nil {
		defer taskRows.Close()
		for taskRows.Next() {
			var t models.EndpointTask
			if err := taskRows.Scan(&t.ID, &t.TenantSlug, &t.AgentID, &t.TaskType, &t.PayloadJSON, &t.Status, &t.CreatedBy, &t.ScheduledAt, &t.StartedAt, &t.CreatedAt); err == nil {
				pendingTasks = append(pendingTasks, t)
			}
		}
	}

	needsUpdate := effectiveRevision > hb.PolicyRevision
	resp := &models.AgentHeartbeatResponse{
		Ack:                   true,
		ServerTime:            time.Now().UTC(),
		CurrentPolicyRevision: effectiveRevision,
		PolicyNeedsUpdate:     needsUpdate,
		PendingTasksCount:     len(pendingTasks),
		PendingTasks:          pendingTasks,
	}

	if needsUpdate && len(policyConfigJSON) > 0 {
		var pCfg models.EndpointPolicyConfig
		if err := json.Unmarshal(policyConfigJSON, &pCfg); err == nil {
			resp.Policy = &pCfg
		}
	}

	// Auto-Update check: Offer latest agent binary if connected agent is running an older build
	latestAgentVer := "v0.1.4"
	if hb.AgentVersion != "" && hb.AgentVersion != latestAgentVer {
		downloadURL := "/static/bin/logger-agent-linux-amd64"
		if strings.EqualFold(osType, "windows") {
			downloadURL = "/static/bin/logger-agent-windows-amd64.exe"
		} else if strings.EqualFold(osType, "darwin") {
			downloadURL = "/static/bin/logger-agent-darwin-universal"
		} else if strings.EqualFold(arch, "arm64") {
			downloadURL = "/static/bin/logger-agent-linux-arm64"
		}

		resp.UpgradeAvailable = true
		resp.TargetVersion = latestAgentVer
		resp.DownloadURL = downloadURL
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
		  AND ($2 = '' OR 
		       ($2 = 'healthy' AND a.status = 'healthy' AND a.last_seen > NOW() - INTERVAL '5 minutes') OR
		       ($2 = 'warning' AND (a.status = 'warning' OR (a.last_seen > NOW() - INTERVAL '15 minutes' AND a.last_seen <= NOW() - INTERVAL '5 minutes'))) OR
		       ($2 = 'offline' AND (a.status = 'offline' OR a.last_seen <= NOW() - INTERVAL '15 minutes' OR a.last_seen IS NULL)) OR
		       ($2 NOT IN ('healthy', 'warning', 'offline') AND a.status = $2))
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
		       COALESCE(a.is_isolated, FALSE) as is_isolated, a.isolated_at, COALESCE(a.isolation_reason, '') as isolation_reason,
		       COALESCE((SELECT COUNT(*) FROM endpoint_vulnerability_findings vf WHERE vf.agent_id = a.id AND vf.status = 'open'), 0) as open_vulns,
		       COALESCE((SELECT COUNT(*) FROM endpoint_vulnerability_findings vf WHERE vf.agent_id = a.id AND vf.status = 'open' AND (vf.severity = 'CRITICAL' OR vf.priority = 'CRITICAL')), 0) as crit_vulns,
		       COALESCE((SELECT COUNT(*) FROM endpoint_patches_current pc WHERE pc.agent_id = a.id AND pc.status = 'missing'), 0) as missing_patches,
		       COALESCE((SELECT bool_or(pc.requires_reboot) FROM endpoint_patches_current pc WHERE pc.agent_id = a.id AND pc.status IN ('missing', 'pending_reboot')), false) as reboot_req
		FROM endpoint_agents a
		LEFT JOIN endpoint_policies p ON a.policy_id = p.id
		LEFT JOIN endpoint_agent_groups g ON a.group_id = g.id
		WHERE ($1 = '' OR $1 = 'all' OR a.tenant_slug = $1)
		  AND ($2 = '' OR 
		       ($2 = 'healthy' AND a.status = 'healthy' AND a.last_seen > NOW() - INTERVAL '5 minutes') OR
		       ($2 = 'warning' AND (a.status = 'warning' OR (a.last_seen > NOW() - INTERVAL '15 minutes' AND a.last_seen <= NOW() - INTERVAL '5 minutes'))) OR
		       ($2 = 'offline' AND (a.status = 'offline' OR a.last_seen <= NOW() - INTERVAL '15 minutes' OR a.last_seen IS NULL)) OR
		       ($2 NOT IN ('healthy', 'warning', 'offline') AND a.status = $2))
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
			&a.IsIsolated, &a.IsolatedAt, &a.IsolationReason,
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
		       COALESCE(a.is_isolated, FALSE) as is_isolated, a.isolated_at, COALESCE(a.isolation_reason, '') as isolation_reason,
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
		&a.IsIsolated, &a.IsolatedAt, &a.IsolationReason,
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

	// 4. Query Top Risk / Vulnerable Endpoints (or enrolled endpoints with health)
	queryTopAgents := `
		SELECT 
			a.id, a.hostname, a.ip_address, a.os_type,
			COALESCE(COUNT(*) FILTER (WHERE vf.severity = 'CRITICAL' AND vf.status = 'open'), 0) as crit_cnt,
			COALESCE(COUNT(*) FILTER (WHERE vf.severity = 'HIGH' AND vf.status = 'open'), 0) as high_cnt,
			COALESCE(COUNT(*) FILTER (WHERE vf.status = 'open'), 0) as total_cnt
		FROM endpoint_agents a
		LEFT JOIN endpoint_vulnerability_findings vf ON vf.agent_id = a.id
		WHERE ($1 = '' OR $1 = 'all' OR a.tenant_slug = $1)
		GROUP BY a.id, a.hostname, a.ip_address, a.os_type, a.last_seen
		ORDER BY crit_cnt DESC, high_cnt DESC, total_cnt DESC, a.last_seen DESC NULLS LAST
		LIMIT 5
	`
	agentRows, err := db.pool.Query(ctx, queryTopAgents, tenantSlug)
	if err == nil {
		defer agentRows.Close()
		for agentRows.Next() {
			var sa models.EndpointAgentSummary
			if err := agentRows.Scan(&sa.AgentID, &sa.Hostname, &sa.IPAddress, &sa.OSType, &sa.CriticalCount, &sa.HighCount, &sa.TotalVulns); err == nil {
				summary.TopVulnerableAgents = append(summary.TopVulnerableAgents, sa)
			}
		}
	}

	// 5. Query Top Exploited & Critical CVEs
	queryTopCVEs := `
		SELECT 
			vf.cve_id,
			COALESCE(c.title, vf.cve_id) as title,
			COALESCE(MAX(vf.cvss_score), 0) as cvss,
			COALESCE(MAX(vf.severity), 'HIGH') as sev,
			BOOL_OR(COALESCE(vf.cisa_kev, false)) as is_kev,
			COALESCE(MAX(vf.epss_probability), 0) as epss,
			COUNT(DISTINCT vf.agent_id) as affected_count
		FROM endpoint_vulnerability_findings vf
		LEFT JOIN endpoint_cve_catalog c ON c.cve_id = vf.cve_id
		WHERE ($1 = '' OR $1 = 'all' OR vf.tenant_slug = $1) AND vf.status = 'open'
		GROUP BY vf.cve_id, c.title
		ORDER BY is_kev DESC, cvss DESC, affected_count DESC
		LIMIT 5
	`
	cveRows, err := db.pool.Query(ctx, queryTopCVEs, tenantSlug)
	if err == nil {
		defer cveRows.Close()
		for cveRows.Next() {
			var sc models.EndpointCVESummary
			if err := cveRows.Scan(&sc.CVEID, &sc.Title, &sc.CVSSScore, &sc.Severity, &sc.CISAKEV, &sc.EPSSScore, &sc.AffectedCount); err == nil {
				summary.TopCVEs = append(summary.TopCVEs, sc)
			}
		}
	}

	return summary, nil
}

// ListEndpointPolicies lists all policies configured for a tenant
func (db *DB) ListEndpointPolicies(ctx context.Context, tenantSlug string) ([]models.EndpointPolicy, error) {
	query := `
		SELECT 
			p.id, p.tenant_slug, p.name, p.description, p.revision, p.config_json, p.is_default,
			p.created_at, p.updated_at,
			COALESCE(COUNT(a.id), 0) AS agent_count
		FROM endpoint_policies p
		LEFT JOIN endpoint_agents a ON a.policy_id = p.id
		WHERE ($1 = '' OR $1 = 'all' OR p.tenant_slug = $1)
		GROUP BY p.id, p.tenant_slug, p.name, p.description, p.revision, p.config_json, p.is_default, p.created_at, p.updated_at
		ORDER BY p.is_default DESC, p.name ASC
	`
	rows, err := db.pool.Query(ctx, query, tenantSlug)
	if err != nil {
		return nil, fmt.Errorf("querying endpoint policies: %w", err)
	}
	defer rows.Close()

	var policies []models.EndpointPolicy
	for rows.Next() {
		var p models.EndpointPolicy
		var cfgJSON []byte
		if err := rows.Scan(
			&p.ID, &p.TenantSlug, &p.Name, &p.Description, &p.Revision, &cfgJSON, &p.IsDefault,
			&p.CreatedAt, &p.UpdatedAt, &p.AgentCount,
		); err != nil {
			return nil, fmt.Errorf("scanning policy row: %w", err)
		}
		p.Config = cfgJSON
		if len(cfgJSON) > 0 {
			var pCfg models.EndpointPolicyConfig
			if err := json.Unmarshal(cfgJSON, &pCfg); err == nil {
				p.PolicyConfig = &pCfg
			}
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []models.EndpointPolicy{}
	}
	return policies, nil
}

// GetEndpointPolicy retrieves a specific policy by ID
func (db *DB) GetEndpointPolicy(ctx context.Context, policyID uuid.UUID) (*models.EndpointPolicy, error) {
	query := `
		SELECT 
			p.id, p.tenant_slug, p.name, p.description, p.revision, p.config_json, p.is_default,
			p.created_at, p.updated_at,
			COALESCE(COUNT(a.id), 0) AS agent_count
		FROM endpoint_policies p
		LEFT JOIN endpoint_agents a ON a.policy_id = p.id
		WHERE p.id = $1
		GROUP BY p.id, p.tenant_slug, p.name, p.description, p.revision, p.config_json, p.is_default, p.created_at, p.updated_at
	`
	var p models.EndpointPolicy
	var cfgJSON []byte
	err := db.pool.QueryRow(ctx, query, policyID).Scan(
		&p.ID, &p.TenantSlug, &p.Name, &p.Description, &p.Revision, &cfgJSON, &p.IsDefault,
		&p.CreatedAt, &p.UpdatedAt, &p.AgentCount,
	)
	if err != nil {
		return nil, err
	}
	p.Config = cfgJSON
	if len(cfgJSON) > 0 {
		var pCfg models.EndpointPolicyConfig
		if err := json.Unmarshal(cfgJSON, &pCfg); err == nil {
			p.PolicyConfig = &pCfg
		}
	}
	return &p, nil
}

// CreateEndpointPolicy creates a new policy with revision 1
func (db *DB) CreateEndpointPolicy(ctx context.Context, tenantSlug, name, description string, cfg models.EndpointPolicyConfig, isDefault bool) (*models.EndpointPolicy, error) {
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling policy config: %w", err)
	}

	if isDefault {
		_, _ = db.pool.Exec(ctx, `UPDATE endpoint_policies SET is_default = FALSE WHERE tenant_slug = $1`, tenantSlug)
	}

	var p models.EndpointPolicy
	query := `
		INSERT INTO endpoint_policies (tenant_slug, name, description, revision, config_json, is_default, created_at, updated_at)
		VALUES ($1, $2, $3, 1, $4, $5, NOW(), NOW())
		RETURNING id, tenant_slug, name, description, revision, config_json, is_default, created_at, updated_at
	`
	var retCfgJSON []byte
	err = db.pool.QueryRow(ctx, query, tenantSlug, name, description, cfgJSON, isDefault).Scan(
		&p.ID, &p.TenantSlug, &p.Name, &p.Description, &p.Revision, &retCfgJSON, &p.IsDefault, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting policy: %w", err)
	}
	p.Config = retCfgJSON
	p.PolicyConfig = &cfg
	return &p, nil
}

// UpdateEndpointPolicy updates a policy's configuration and increments its revision
func (db *DB) UpdateEndpointPolicy(ctx context.Context, policyID uuid.UUID, tenantSlug, name, description string, cfg models.EndpointPolicyConfig, isDefault bool) (*models.EndpointPolicy, error) {
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling policy config: %w", err)
	}

	if isDefault {
		_, _ = db.pool.Exec(ctx, `UPDATE endpoint_policies SET is_default = FALSE WHERE tenant_slug = $1 AND id != $2`, tenantSlug, policyID)
	}

	query := `
		UPDATE endpoint_policies
		SET name = $2,
		    description = $3,
		    revision = revision + 1,
		    config_json = $4,
		    is_default = $5,
		    updated_at = NOW()
		WHERE id = $1 AND ($6 = '' OR $6 = 'all' OR tenant_slug = $6)
		RETURNING id, tenant_slug, name, description, revision, config_json, is_default, created_at, updated_at
	`
	var p models.EndpointPolicy
	var retCfgJSON []byte
	err = db.pool.QueryRow(ctx, query, policyID, name, description, cfgJSON, isDefault, tenantSlug).Scan(
		&p.ID, &p.TenantSlug, &p.Name, &p.Description, &p.Revision, &retCfgJSON, &p.IsDefault, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("updating policy: %w", err)
	}
	p.Config = retCfgJSON
	p.PolicyConfig = &cfg

	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_agents WHERE policy_id = $1`, policyID).Scan(&p.AgentCount)
	return &p, nil
}

// DeleteEndpointPolicy deletes a non-default policy and reassigns agents to default
func (db *DB) DeleteEndpointPolicy(ctx context.Context, policyID uuid.UUID, tenantSlug string) error {
	var isDefault bool
	err := db.pool.QueryRow(ctx, `SELECT is_default FROM endpoint_policies WHERE id = $1`, policyID).Scan(&isDefault)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}
	if isDefault {
		return errors.New("cannot delete default policy")
	}

	var defaultPolicyID *uuid.UUID
	_ = db.pool.QueryRow(ctx, `SELECT id FROM endpoint_policies WHERE tenant_slug = $1 AND is_default = TRUE LIMIT 1`, tenantSlug).Scan(&defaultPolicyID)
	if defaultPolicyID == nil {
		_ = db.pool.QueryRow(ctx, `SELECT id FROM endpoint_policies WHERE is_default = TRUE LIMIT 1`).Scan(&defaultPolicyID)
	}

	_, _ = db.pool.Exec(ctx, `UPDATE endpoint_agents SET policy_id = $1, policy_revision = 0 WHERE policy_id = $2`, defaultPolicyID, policyID)
	_, err = db.pool.Exec(ctx, `DELETE FROM endpoint_policies WHERE id = $1`, policyID)
	return err
}

// AssignAgentPolicy assigns a specific policy to an agent
func (db *DB) AssignAgentPolicy(ctx context.Context, agentUUID string, policyID uuid.UUID) error {
	res, err := db.pool.Exec(ctx, `
		UPDATE endpoint_agents
		SET policy_id = $2, policy_revision = 0, updated_at = NOW()
		WHERE agent_uuid = $1
	`, agentUUID, policyID)
	if err != nil {
		return fmt.Errorf("assigning policy: %w", err)
	}
	if res.RowsAffected() == 0 {
		return errors.New("agent not found")
	}
	return nil
}

// GetAgentPolicyConfig retrieves the effective policy config for an agent
func (db *DB) GetAgentPolicyConfig(ctx context.Context, agentUUID string) (*models.EndpointPolicyConfig, int, error) {
	query := `
		SELECT COALESCE(p.revision, 1), p.config_json
		FROM endpoint_agents a
		LEFT JOIN endpoint_policies p ON a.policy_id = p.id
		WHERE a.agent_uuid = $1
	`
	var rev int
	var cfgJSON []byte
	err := db.pool.QueryRow(ctx, query, agentUUID).Scan(&rev, &cfgJSON)
	if err != nil {
		err = db.pool.QueryRow(ctx, `SELECT revision, config_json FROM endpoint_policies WHERE is_default = TRUE LIMIT 1`).Scan(&rev, &cfgJSON)
		if err != nil {
			return nil, 1, err
		}
	}
	var cfg models.EndpointPolicyConfig
	if len(cfgJSON) > 0 {
		_ = json.Unmarshal(cfgJSON, &cfg)
	}
	return &cfg, rev, nil
}

// CreateEndpointTask queues a new remote task for an agent
func (db *DB) CreateEndpointTask(ctx context.Context, task *models.EndpointTask) (*models.EndpointTask, error) {
	if task.ID == uuid.Nil {
		task.ID = uuid.New()
	}
	if task.Status == "" {
		task.Status = "pending"
	}
	if task.ScheduledAt.IsZero() {
		task.ScheduledAt = time.Now().UTC()
	}

	query := `
		INSERT INTO endpoint_tasks (id, tenant_slug, agent_id, group_id, task_type, payload_json, status, created_by, scheduled_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		RETURNING created_at
	`
	err := db.pool.QueryRow(ctx, query,
		task.ID, task.TenantSlug, task.AgentID, task.GroupID, task.TaskType, task.PayloadJSON, task.Status, task.CreatedBy, task.ScheduledAt,
	).Scan(&task.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating endpoint task: %w", err)
	}
	return task, nil
}

// ListEndpointTasks lists recent tasks with agent details and execution results
func (db *DB) ListEndpointTasks(ctx context.Context, tenantSlug, status, taskType string, limit, offset int) ([]models.EndpointTask, int, error) {
	if limit <= 0 {
		limit = 50
	}
	whereConditions := []string{"($1 = '' OR $1 = 'all' OR t.tenant_slug = $1)"}
	args := []interface{}{tenantSlug}
	argIdx := 2

	if status != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("t.status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}
	if taskType != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("t.task_type = $%d", argIdx))
		args = append(args, taskType)
		argIdx++
	}

	whereClause := strings.Join(whereConditions, " AND ")

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM endpoint_tasks t WHERE %s`, whereClause)
	var total int
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT 
			t.id, t.tenant_slug, t.agent_id, COALESCE(a.hostname, ''), COALESCE(a.ip_address, ''), COALESCE(a.os_type, ''),
			t.group_id, t.task_type, t.payload_json, t.status, t.created_by,
			t.scheduled_at, t.started_at, t.completed_at, COALESCE(t.error_message, ''),
			t.created_at,
			COALESCE(r.exit_code, 0), COALESCE(r.stdout, ''), COALESCE(r.stderr, ''),
			COALESCE(r.execution_duration_ms, 0), r.completed_at
		FROM endpoint_tasks t
		LEFT JOIN endpoint_agents a ON a.id = t.agent_id
		LEFT JOIN endpoint_task_results r ON r.task_id = t.id
		WHERE %s
		ORDER BY t.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)
	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var tasks []models.EndpointTask
	for rows.Next() {
		var item models.EndpointTask
		var host, ip, os string
		var exitCode int
		var stdout, stderr string
		var durationMs int64
		var resCompletedAt *time.Time

		err := rows.Scan(
			&item.ID, &item.TenantSlug, &item.AgentID, &host, &ip, &os,
			&item.GroupID, &item.TaskType, &item.PayloadJSON, &item.Status, &item.CreatedBy,
			&item.ScheduledAt, &item.StartedAt, &item.CompletedAt, &item.ErrorMessage,
			&item.CreatedAt,
			&exitCode, &stdout, &stderr, &durationMs, &resCompletedAt,
		)
		if err == nil {
			item.AgentHostname = host
			item.AgentIP = ip
			item.AgentOS = os
			item.ExecutionDurationMs = durationMs
			if resCompletedAt != nil {
				item.Result = &models.EndpointTaskResult{
					TaskID:              item.ID,
					AgentID:             item.AgentID,
					Status:              item.Status,
					ExitCode:            exitCode,
					Stdout:              stdout,
					Stderr:              stderr,
					ExecutionDurationMs: durationMs,
					CompletedAt:         *resCompletedAt,
				}
			}
			tasks = append(tasks, item)
		}
	}
	return tasks, total, nil
}

// GetEndpointTask returns single task details including stdout/stderr result
func (db *DB) GetEndpointTask(ctx context.Context, tenantSlug string, taskID uuid.UUID) (*models.EndpointTask, error) {
	query := `
		SELECT 
			t.id, t.tenant_slug, t.agent_id, COALESCE(a.hostname, ''), COALESCE(a.ip_address, ''), COALESCE(a.os_type, ''),
			t.group_id, t.task_type, t.payload_json, t.status, t.created_by,
			t.scheduled_at, t.started_at, t.completed_at, COALESCE(t.error_message, ''),
			t.created_at,
			COALESCE(r.exit_code, 0), COALESCE(r.stdout, ''), COALESCE(r.stderr, ''),
			COALESCE(r.execution_duration_ms, 0), r.completed_at
		FROM endpoint_tasks t
		LEFT JOIN endpoint_agents a ON a.id = t.agent_id
		LEFT JOIN endpoint_task_results r ON r.task_id = t.id
		WHERE t.id = $1 AND ($2 = '' OR $2 = 'all' OR t.tenant_slug = $2)
	`
	var item models.EndpointTask
	var host, ip, os string
	var exitCode int
	var stdout, stderr string
	var durationMs int64
	var resCompletedAt *time.Time

	err := db.pool.QueryRow(ctx, query, taskID, tenantSlug).Scan(
		&item.ID, &item.TenantSlug, &item.AgentID, &host, &ip, &os,
		&item.GroupID, &item.TaskType, &item.PayloadJSON, &item.Status, &item.CreatedBy,
		&item.ScheduledAt, &item.StartedAt, &item.CompletedAt, &item.ErrorMessage,
		&item.CreatedAt,
		&exitCode, &stdout, &stderr, &durationMs, &resCompletedAt,
	)
	if err != nil {
		return nil, err
	}
	item.AgentHostname = host
	item.AgentIP = ip
	item.AgentOS = os
	item.ExecutionDurationMs = durationMs
	if resCompletedAt != nil {
		item.Result = &models.EndpointTaskResult{
			TaskID:              item.ID,
			AgentID:             item.AgentID,
			Status:              item.Status,
			ExitCode:            exitCode,
			Stdout:              stdout,
			Stderr:              stderr,
			ExecutionDurationMs: durationMs,
			CompletedAt:         *resCompletedAt,
		}
	}
	return &item, nil
}

// SaveTaskResult records execution results from an agent
func (db *DB) SaveTaskResult(ctx context.Context, agentUUID string, sub *models.AgentTaskResultSubmission) error {
	taskUUID, err := uuid.Parse(sub.TaskID)
	if err != nil {
		return fmt.Errorf("invalid task id: %w", err)
	}

	var agentID uuid.UUID
	var taskType string
	var payloadBytes []byte
	err = db.pool.QueryRow(ctx, `
		SELECT t.agent_id, t.task_type, t.payload_json
		FROM endpoint_tasks t
		JOIN endpoint_agents a ON a.id = t.agent_id
		WHERE t.id = $1 AND a.agent_uuid = $2
	`, taskUUID, agentUUID).Scan(&agentID, &taskType, &payloadBytes)
	if err != nil {
		return fmt.Errorf("verifying task ownership: %w", err)
	}

	status := sub.Status
	if status == "" {
		if sub.ExitCode == 0 {
			status = "completed"
		} else {
			status = "failed"
		}
	}

	// 1. Update task status
	_, err = db.pool.Exec(ctx, `
		UPDATE endpoint_tasks
		SET status = $2,
		    completed_at = NOW(),
		    error_message = $3
		WHERE id = $1
	`, taskUUID, status, sub.ErrorMessage)
	if err != nil {
		return fmt.Errorf("updating task: %w", err)
	}

	// 2. Insert or update task result
	_, err = db.pool.Exec(ctx, `
		INSERT INTO endpoint_task_results (task_id, agent_id, status, exit_code, stdout, stderr, execution_duration_ms, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (task_id) DO UPDATE SET
			status = EXCLUDED.status,
			exit_code = EXCLUDED.exit_code,
			stdout = EXCLUDED.stdout,
			stderr = EXCLUDED.stderr,
			execution_duration_ms = EXCLUDED.execution_duration_ms,
			completed_at = NOW()
	`, taskUUID, agentID, status, sub.ExitCode, sub.Stdout, sub.Stderr, sub.ExecutionDurationMs)
	if err != nil {
		return fmt.Errorf("saving task result: %w", err)
	}

	// 3. If task was patch_install and succeeded, update patch record in endpoint_patches_current
	if taskType == "patch_install" && status == "completed" {
		var payload struct {
			PatchID     string `json:"patch_id"`
			RebootAfter bool   `json:"reboot_after"`
		}
		if err := json.Unmarshal(payloadBytes, &payload); err == nil && payload.PatchID != "" {
			if payload.RebootAfter {
				_, _ = db.pool.Exec(ctx, `
					UPDATE endpoint_patches_current
					SET status = 'pending_reboot', requires_reboot = TRUE, installed_at = NOW()
					WHERE agent_id = $1 AND patch_id = $2
				`, agentID, payload.PatchID)
			} else {
				_, _ = db.pool.Exec(ctx, `
					UPDATE endpoint_patches_current
					SET status = 'installed', requires_reboot = FALSE, installed_at = NOW()
					WHERE agent_id = $1 AND patch_id = $2
				`, agentID, payload.PatchID)
			}
		}
	}

	// 4. Active Response task hooks
	if taskType == "isolate_host" && status == "completed" {
		var payload struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(payloadBytes, &payload)
		reason := payload.Reason
		if reason == "" {
			reason = "Manual containment initiated by security operator"
		}
		_, _ = db.pool.Exec(ctx, `
			UPDATE endpoint_agents
			SET is_isolated = TRUE, isolated_at = NOW(), isolation_reason = $2
			WHERE id = $1
		`, agentID, reason)
	}

	if taskType == "unisolate_host" && status == "completed" {
		_, _ = db.pool.Exec(ctx, `
			UPDATE endpoint_agents
			SET is_isolated = FALSE, isolated_at = NULL, isolation_reason = ''
			WHERE id = $1
		`, agentID)
	}

	if taskType == "file_quarantine" && status == "completed" {
		var qMeta struct {
			OriginalPath   string `json:"original_path"`
			QuarantinePath string `json:"quarantine_path"`
			SHA256         string `json:"sha256"`
			SizeBytes      int64  `json:"size_bytes"`
			Reason         string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(sub.Stdout), &qMeta); err == nil && qMeta.OriginalPath != "" {
			var tSlug string
			_ = db.pool.QueryRow(ctx, `SELECT tenant_slug FROM endpoint_agents WHERE id = $1`, agentID).Scan(&tSlug)
			_, _ = db.pool.Exec(ctx, `
				INSERT INTO endpoint_quarantined_files (tenant_slug, agent_id, original_path, quarantine_path, sha256, size_bytes, reason, quarantined_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
			`, tSlug, agentID, qMeta.OriginalPath, qMeta.QuarantinePath, qMeta.SHA256, qMeta.SizeBytes, qMeta.Reason)
		}
	}

	return nil
}

// DeployPatch dispatches a remediation task to install a missing patch on an agent
func (db *DB) DeployPatch(ctx context.Context, tenantSlug string, req *models.PatchDeployRequest, user string) (*models.EndpointTask, error) {
	agentUUID, err := uuid.Parse(req.AgentID)
	if err != nil {
		return nil, fmt.Errorf("invalid agent id: %w", err)
	}

	var agentTenant string
	err = db.pool.QueryRow(ctx, `SELECT tenant_slug FROM endpoint_agents WHERE id = $1`, agentUUID).Scan(&agentTenant)
	if err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}
	if tenantSlug != "" && tenantSlug != "all" && agentTenant != tenantSlug {
		return nil, errors.New("unauthorized: agent belongs to another tenant")
	}

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"patch_id":     req.PatchID,
		"title":        req.Title,
		"reboot_after": req.RebootAfter,
	})

	task := &models.EndpointTask{
		ID:          uuid.New(),
		TenantSlug:  agentTenant,
		AgentID:     agentUUID,
		TaskType:    "patch_install",
		PayloadJSON: payloadJSON,
		Status:      "pending",
		CreatedBy:   user,
		ScheduledAt: time.Now().UTC(),
	}

	return db.CreateEndpointTask(ctx, task)
}

// BatchDeployPatches queues remediation tasks for all missing patches matching the criteria
func (db *DB) BatchDeployPatches(ctx context.Context, tenantSlug string, req *models.BatchPatchDeployRequest, user string) (int, error) {
	whereConditions := []string{"p.status = 'missing'"}
	args := []interface{}{}
	argIdx := 1

	if tenantSlug != "" && tenantSlug != "all" {
		whereConditions = append(whereConditions, fmt.Sprintf("p.tenant_slug = $%d", argIdx))
		args = append(args, tenantSlug)
		argIdx++
	}

	if req.SeverityFilter != "" && req.SeverityFilter != "ALL" {
		if req.SeverityFilter == "CRITICAL" {
			whereConditions = append(whereConditions, "p.severity = 'CRITICAL'")
		} else if req.SeverityFilter == "HIGH" || req.SeverityFilter == "CRITICAL_HIGH" {
			whereConditions = append(whereConditions, "p.severity IN ('CRITICAL', 'HIGH')")
		}
	}

	whereClause := strings.Join(whereConditions, " AND ")
	query := fmt.Sprintf(`
		SELECT p.agent_id, p.patch_id, p.title, p.tenant_slug
		FROM endpoint_patches_current p
		JOIN endpoint_agents a ON a.id = p.agent_id
		WHERE %s
		LIMIT 200
	`, whereClause)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type item struct {
		agentID    uuid.UUID
		patchID    string
		title      string
		tenantSlug string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.agentID, &it.patchID, &it.title, &it.tenantSlug); err == nil {
			items = append(items, it)
		}
	}

	queued := 0
	for _, it := range items {
		payloadJSON, _ := json.Marshal(map[string]interface{}{
			"patch_id":     it.patchID,
			"title":        it.title,
			"reboot_after": req.RebootAfter,
		})
		task := &models.EndpointTask{
			ID:          uuid.New(),
			TenantSlug:  it.tenantSlug,
			AgentID:     it.agentID,
			TaskType:    "patch_install",
			PayloadJSON: payloadJSON,
			Status:      "pending",
			CreatedBy:   user,
			ScheduledAt: time.Now().UTC(),
		}
		if _, err := db.CreateEndpointTask(ctx, task); err == nil {
			queued++
		}
	}

	return queued, nil
}

// RebootEndpointAgent dispatches a system reboot task to an agent
func (db *DB) RebootEndpointAgent(ctx context.Context, tenantSlug string, agentID uuid.UUID, user string) (*models.EndpointTask, error) {
	var agentTenant string
	err := db.pool.QueryRow(ctx, `SELECT tenant_slug FROM endpoint_agents WHERE id = $1`, agentID).Scan(&agentTenant)
	if err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}
	if tenantSlug != "" && tenantSlug != "all" && agentTenant != tenantSlug {
		return nil, errors.New("unauthorized: agent belongs to another tenant")
	}

	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"delay_seconds": 30,
		"reason":        "LogSeal Security Patch Remediation Reboot requested by " + user,
	})

	task := &models.EndpointTask{
		ID:          uuid.New(),
		TenantSlug:  agentTenant,
		AgentID:     agentID,
		TaskType:    "system_reboot",
		PayloadJSON: payloadJSON,
		Status:      "pending",
		CreatedBy:   user,
		ScheduledAt: time.Now().UTC(),
	}

	return db.CreateEndpointTask(ctx, task)
}

// DispatchActiveResponseTask dispatches an EDR active response task (isolate_host, unisolate_host, process_kill, file_quarantine, osquery_run)
func (db *DB) DispatchActiveResponseTask(ctx context.Context, tenantSlug string, agentID uuid.UUID, taskType string, payload map[string]interface{}, user string) (*models.EndpointTask, error) {
	var agentTenant string
	err := db.pool.QueryRow(ctx, `SELECT tenant_slug FROM endpoint_agents WHERE id = $1`, agentID).Scan(&agentTenant)
	if err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}
	if tenantSlug != "" && tenantSlug != "all" && agentTenant != tenantSlug {
		return nil, errors.New("unauthorized: agent belongs to another tenant")
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshalling task payload: %w", err)
	}

	task := &models.EndpointTask{
		ID:          uuid.New(),
		TenantSlug:  agentTenant,
		AgentID:     agentID,
		TaskType:    taskType,
		PayloadJSON: payloadJSON,
		Status:      "pending",
		CreatedBy:   user,
		ScheduledAt: time.Now().UTC(),
	}

	return db.CreateEndpointTask(ctx, task)
}

// ListQuarantinedFiles returns all quarantined files for an agent or tenant
func (db *DB) ListQuarantinedFiles(ctx context.Context, tenantSlug string, agentID *uuid.UUID) ([]models.QuarantinedFileEntry, error) {
	var query string
	var rows pgx.Rows
	var err error

	if agentID != nil {
		query = `
			SELECT original_path, quarantine_path, sha256, size_bytes, quarantined_at, reason
			FROM endpoint_quarantined_files
			WHERE agent_id = $1 AND ($2 = '' OR $2 = 'all' OR tenant_slug = $2)
			ORDER BY quarantined_at DESC
		`
		rows, err = db.pool.Query(ctx, query, *agentID, tenantSlug)
	} else {
		query = `
			SELECT original_path, quarantine_path, sha256, size_bytes, quarantined_at, reason
			FROM endpoint_quarantined_files
			WHERE ($1 = '' OR $1 = 'all' OR tenant_slug = $1)
			ORDER BY quarantined_at DESC
			LIMIT 100
		`
		rows, err = db.pool.Query(ctx, query, tenantSlug)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.QuarantinedFileEntry
	for rows.Next() {
		var q models.QuarantinedFileEntry
		if err := rows.Scan(&q.OriginalPath, &q.QuarantinePath, &q.SHA256, &q.SizeBytes, &q.QuarantinedAt, &q.Reason); err != nil {
			return nil, err
		}
		entries = append(entries, q)
	}
	if entries == nil {
		entries = []models.QuarantinedFileEntry{}
	}
	return entries, nil
}

