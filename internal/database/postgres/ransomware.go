package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/syslog-platform/logger/internal/models"
)

// EnsureRansomwareSchema initializes tables and indexes for Anti-Ransomware Shield & Decoy Canary Defense (Phase P)
func (db *DB) EnsureRansomwareSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS endpoint_ransomware_incidents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			agent_hostname VARCHAR(255) NOT NULL DEFAULT '',
			agent_ip VARCHAR(64) NOT NULL DEFAULT '',
			process_name VARCHAR(255) NOT NULL DEFAULT '',
			process_pid INT NOT NULL DEFAULT 0,
			process_path TEXT NOT NULL DEFAULT '',
			command_line TEXT NOT NULL DEFAULT '',
			trigger_type VARCHAR(64) NOT NULL DEFAULT 'canary_tripwire',
			target_file TEXT NOT NULL DEFAULT '',
			extension_detected VARCHAR(64) NOT NULL DEFAULT '',
			entropy_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
			files_affected INT NOT NULL DEFAULT 1,
			action_taken VARCHAR(64) NOT NULL DEFAULT 'TERMINATED',
			severity VARCHAR(32) NOT NULL DEFAULT 'CRITICAL',
			mitre_tactic VARCHAR(64) NOT NULL DEFAULT 'Impact',
			mitre_technique VARCHAR(64) NOT NULL DEFAULT 'T1486',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS endpoint_canary_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			agent_hostname VARCHAR(255) NOT NULL DEFAULT '',
			file_path TEXT NOT NULL,
			file_type VARCHAR(32) NOT NULL DEFAULT 'docx',
			initial_hash VARCHAR(128) NOT NULL DEFAULT '',
			status VARCHAR(32) NOT NULL DEFAULT 'ARMED',
			last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			triggered_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_canary_agent_path UNIQUE (agent_id, file_path)
		);`,
		`CREATE TABLE IF NOT EXISTS endpoint_honeypot_config (
			tenant_slug VARCHAR(64) PRIMARY KEY,
			enabled BOOLEAN NOT NULL DEFAULT true,
			canaries_enabled BOOLEAN NOT NULL DEFAULT true,
			autonomous_kill BOOLEAN NOT NULL DEFAULT true,
			entropy_threshold DOUBLE PRECISION NOT NULL DEFAULT 7.5,
			action_mode VARCHAR(32) NOT NULL DEFAULT 'TERMINATE',
			decoy_types TEXT NOT NULL DEFAULT 'docx,xlsx,pdf',
			custom_path TEXT NOT NULL DEFAULT '',
			rearm_interval_sec INT NOT NULL DEFAULT 60,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ransomware_incidents_tenant_time ON endpoint_ransomware_incidents(tenant_slug, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_ransomware_incidents_agent ON endpoint_ransomware_incidents(agent_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_ransomware_incidents_trigger ON endpoint_ransomware_incidents(trigger_type);`,
		`CREATE INDEX IF NOT EXISTS idx_canary_tokens_tenant ON endpoint_canary_tokens(tenant_slug, status);`,
		`CREATE INDEX IF NOT EXISTS idx_canary_tokens_agent ON endpoint_canary_tokens(agent_id);`,
	}

	for _, q := range queries {
		if _, err := db.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("failed executing ransomware schema query: %w", err)
		}
	}
	return nil
}

// RecordRansomwareIncidents persists newly detected ransomware and canary tripwire violations
func (db *DB) RecordRansomwareIncidents(ctx context.Context, incidents []models.EndpointRansomwareIncident) error {
	if len(incidents) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, inc := range incidents {
		id := inc.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		createdAt := inc.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}

		batch.Queue(`
			INSERT INTO endpoint_ransomware_incidents (
				id, tenant_slug, agent_id, agent_hostname, agent_ip,
				process_name, process_pid, process_path, command_line,
				trigger_type, target_file, extension_detected, entropy_score,
				files_affected, action_taken, severity, mitre_tactic,
				mitre_technique, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		`,
			id, inc.TenantSlug, inc.AgentID, inc.AgentHostname, inc.AgentIP,
			inc.ProcessName, inc.ProcessPID, inc.ProcessPath, inc.CommandLine,
			inc.TriggerType, inc.TargetFile, inc.ExtensionDetected, inc.EntropyScore,
			inc.FilesAffected, inc.ActionTaken, inc.Severity, inc.MitreTactic,
			inc.MitreTechnique, createdAt,
		)
	}

	br := db.pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(incidents); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("failed executing ransomware incident insert batch [%d]: %w", i, err)
		}
	}

	return nil
}

// ListRansomwareIncidents retrieves ransomware incident history scoped by tenant and optional agent
func (db *DB) ListRansomwareIncidents(ctx context.Context, tenantSlug, agentID string, limit, offset int) ([]models.EndpointRansomwareIncident, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	var conditions []string
	var args []any
	argIdx := 1

	if tenantSlug != "" && tenantSlug != "all" && tenantSlug != "default" {
		conditions = append(conditions, fmt.Sprintf("tenant_slug = $%d", argIdx))
		args = append(args, tenantSlug)
		argIdx++
	}

	if agentID != "" && agentID != "all" {
		if parsed, err := uuid.Parse(agentID); err == nil {
			conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argIdx))
			args = append(args, parsed)
			argIdx++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM endpoint_ransomware_incidents %s", whereClause)
	var total int64
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_slug, agent_id, agent_hostname, agent_ip,
		       process_name, process_pid, process_path, command_line,
		       trigger_type, target_file, extension_detected, entropy_score,
		       files_affected, action_taken, severity, mitre_tactic,
		       mitre_technique, created_at
		FROM endpoint_ransomware_incidents
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var incidents []models.EndpointRansomwareIncident
	for rows.Next() {
		var inc models.EndpointRansomwareIncident
		err := rows.Scan(
			&inc.ID, &inc.TenantSlug, &inc.AgentID, &inc.AgentHostname, &inc.AgentIP,
			&inc.ProcessName, &inc.ProcessPID, &inc.ProcessPath, &inc.CommandLine,
			&inc.TriggerType, &inc.TargetFile, &inc.ExtensionDetected, &inc.EntropyScore,
			&inc.FilesAffected, &inc.ActionTaken, &inc.Severity, &inc.MitreTactic,
			&inc.MitreTechnique, &inc.CreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		incidents = append(incidents, inc)
	}

	return incidents, total, nil
}

// UpsertCanaryTokens registers or updates decoy honeypot files deployed on an agent
func (db *DB) UpsertCanaryTokens(ctx context.Context, canaries []models.EndpointCanaryToken) error {
	if len(canaries) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, c := range canaries {
		id := c.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		now := time.Now().UTC()
		batch.Queue(`
			INSERT INTO endpoint_canary_tokens (
				id, tenant_slug, agent_id, agent_hostname, file_path,
				file_type, initial_hash, status, last_checked_at, triggered_at, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (agent_id, file_path) DO UPDATE SET
				status = EXCLUDED.status,
				last_checked_at = EXCLUDED.last_checked_at,
				triggered_at = COALESCE(EXCLUDED.triggered_at, endpoint_canary_tokens.triggered_at)
		`,
			id, c.TenantSlug, c.AgentID, c.AgentHostname, c.FilePath,
			c.FileType, c.InitialHash, c.Status, now, c.TriggeredAt, now,
		)
	}

	br := db.pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(canaries); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("failed executing canary upsert batch [%d]: %w", i, err)
		}
	}

	return nil
}

// ListCanaryTokens retrieves all honeypot canaries scoped by tenant and optional agent
func (db *DB) ListCanaryTokens(ctx context.Context, tenantSlug, agentID string) ([]models.EndpointCanaryToken, error) {
	var conditions []string
	var args []any
	argIdx := 1

	if tenantSlug != "" && tenantSlug != "all" && tenantSlug != "default" {
		conditions = append(conditions, fmt.Sprintf("tenant_slug = $%d", argIdx))
		args = append(args, tenantSlug)
		argIdx++
	}

	if agentID != "" && agentID != "all" {
		if parsed, err := uuid.Parse(agentID); err == nil {
			conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argIdx))
			args = append(args, parsed)
			argIdx++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_slug, agent_id, agent_hostname, file_path,
		       file_type, initial_hash, status, last_checked_at, triggered_at, created_at
		FROM endpoint_canary_tokens
		%s
		ORDER BY created_at DESC
		LIMIT 100
	`, whereClause)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var canaries []models.EndpointCanaryToken
	for rows.Next() {
		var c models.EndpointCanaryToken
		err := rows.Scan(
			&c.ID, &c.TenantSlug, &c.AgentID, &c.AgentHostname, &c.FilePath,
			&c.FileType, &c.InitialHash, &c.Status, &c.LastCheckedAt, &c.TriggeredAt, &c.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		canaries = append(canaries, c)
	}

	return canaries, nil
}

// GetRansomwareStats aggregates fleet-wide or tenant-scoped ransomware metrics
func (db *DB) GetRansomwareStats(ctx context.Context, tenantSlug string) (*models.RansomwareStats, error) {
	var whereInc, whereCanary string
	var args []any

	if tenantSlug != "" && tenantSlug != "all" && tenantSlug != "default" {
		whereInc = "WHERE tenant_slug = $1"
		whereCanary = "WHERE tenant_slug = $1"
		args = append(args, tenantSlug)
	}

	stats := &models.RansomwareStats{}

	// Total incidents
	qInc := fmt.Sprintf(`
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN action_taken LIKE '%%TERMINATED%%' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action_taken LIKE '%%QUARANTINED%%' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action_taken LIKE '%%ISOLATED%%' THEN 1 ELSE 0 END), 0)
		FROM endpoint_ransomware_incidents %s
	`, whereInc)
	_ = db.pool.QueryRow(ctx, qInc, args...).Scan(
		&stats.TotalRansomwareIncidents,
		&stats.ProcessesTerminated,
		&stats.BinariesQuarantined,
		&stats.HostsIsolated,
	)

	// Canaries
	qCanary := fmt.Sprintf(`
		SELECT COALESCE(SUM(CASE WHEN status = 'ARMED' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status = 'TRIGGERED' THEN 1 ELSE 0 END), 0)
		FROM endpoint_canary_tokens %s
	`, whereCanary)
	_ = db.pool.QueryRow(ctx, qCanary, args...).Scan(
		&stats.CanariesArmed,
		&stats.CanariesTriggered,
	)

	return stats, nil
}

// GetHoneypotConfig returns honeypot & shield parameters for a tenant (or global default)
func (db *DB) GetHoneypotConfig(ctx context.Context, tenantSlug string) (*models.EndpointHoneypotConfig, error) {
	if tenantSlug == "" || tenantSlug == "all" {
		tenantSlug = "default"
	}

	cfg := &models.EndpointHoneypotConfig{
		TenantSlug:       tenantSlug,
		Enabled:          true,
		CanariesEnabled:  true,
		AutonomousKill:   true,
		EntropyThreshold: 7.5,
		ActionMode:       "TERMINATE",
		DecoyTypes:       "docx,xlsx,pdf",
		CustomPath:       "",
		RearmIntervalSec: 60,
		UpdatedAt:        time.Now().UTC(),
	}

	query := `
		SELECT enabled, canaries_enabled, autonomous_kill, entropy_threshold,
		       action_mode, decoy_types, custom_path, rearm_interval_sec, updated_at
		FROM endpoint_honeypot_config
		WHERE tenant_slug = $1
	`
	err := db.pool.QueryRow(ctx, query, tenantSlug).Scan(
		&cfg.Enabled,
		&cfg.CanariesEnabled,
		&cfg.AutonomousKill,
		&cfg.EntropyThreshold,
		&cfg.ActionMode,
		&cfg.DecoyTypes,
		&cfg.CustomPath,
		&cfg.RearmIntervalSec,
		&cfg.UpdatedAt,
	)
	if err != nil && err != pgx.ErrNoRows {
		return nil, fmt.Errorf("failed querying honeypot config: %w", err)
	}

	return cfg, nil
}

// SaveHoneypotConfig upserts honeypot configuration for a tenant
func (db *DB) SaveHoneypotConfig(ctx context.Context, cfg *models.EndpointHoneypotConfig) error {
	if cfg.TenantSlug == "" || cfg.TenantSlug == "all" {
		cfg.TenantSlug = "default"
	}
	if cfg.EntropyThreshold <= 0 {
		cfg.EntropyThreshold = 7.5
	}
	if cfg.ActionMode == "" {
		cfg.ActionMode = "TERMINATE"
	}
	if cfg.DecoyTypes == "" {
		cfg.DecoyTypes = "docx,xlsx,pdf"
	}
	if cfg.RearmIntervalSec <= 0 {
		cfg.RearmIntervalSec = 60
	}
	cfg.UpdatedAt = time.Now().UTC()

	query := `
		INSERT INTO endpoint_honeypot_config (
			tenant_slug, enabled, canaries_enabled, autonomous_kill,
			entropy_threshold, action_mode, decoy_types, custom_path,
			rearm_interval_sec, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_slug) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			canaries_enabled = EXCLUDED.canaries_enabled,
			autonomous_kill = EXCLUDED.autonomous_kill,
			entropy_threshold = EXCLUDED.entropy_threshold,
			action_mode = EXCLUDED.action_mode,
			decoy_types = EXCLUDED.decoy_types,
			custom_path = EXCLUDED.custom_path,
			rearm_interval_sec = EXCLUDED.rearm_interval_sec,
			updated_at = EXCLUDED.updated_at
	`

	_, err := db.pool.Exec(ctx, query,
		cfg.TenantSlug,
		cfg.Enabled,
		cfg.CanariesEnabled,
		cfg.AutonomousKill,
		cfg.EntropyThreshold,
		cfg.ActionMode,
		cfg.DecoyTypes,
		cfg.CustomPath,
		cfg.RearmIntervalSec,
		cfg.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed saving honeypot config: %w", err)
	}

	return nil
}

