package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/syslog-platform/logger/internal/models"
)

// EnsureFIMSchema initializes tables and indexes for File & Registry Integrity Monitoring (Phase L)
func (db *DB) EnsureFIMSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS endpoint_fim_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			event_type VARCHAR(32) NOT NULL,
			target_type VARCHAR(32) NOT NULL DEFAULT 'file',
			target_path TEXT NOT NULL,
			previous_hash VARCHAR(128),
			current_hash VARCHAR(128),
			file_size_bytes BIGINT DEFAULT 0,
			permissions VARCHAR(64) DEFAULT '',
			process_name VARCHAR(255) DEFAULT '',
			process_pid INT DEFAULT 0,
			user_name VARCHAR(128) DEFAULT '',
			severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
			mitre_tactic VARCHAR(128) DEFAULT '',
			mitre_technique VARCHAR(128) DEFAULT '',
			details TEXT DEFAULT '',
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fim_events_tenant_time ON endpoint_fim_events(tenant_slug, timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_fim_events_agent ON endpoint_fim_events(agent_id, timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_fim_events_severity ON endpoint_fim_events(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_fim_events_path ON endpoint_fim_events(target_path);`,

		`CREATE TABLE IF NOT EXISTS endpoint_fim_baselines (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			target_path TEXT NOT NULL,
			target_type VARCHAR(32) NOT NULL DEFAULT 'file',
			sha256_hash VARCHAR(128) NOT NULL,
			file_size_bytes BIGINT DEFAULT 0,
			permissions VARCHAR(64) DEFAULT '',
			last_checked TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_fim_baseline_agent_path UNIQUE(agent_id, target_path)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fim_baselines_agent ON endpoint_fim_baselines(agent_id);`,
	}

	for _, q := range queries {
		if _, err := db.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("executing FIM schema migration: %w", err)
		}
	}

	return nil
}

// ResolveAgentByUUID retrieves agent ID, tenant slug, hostname, IP, and OS by agent UUID
func (db *DB) ResolveAgentByUUID(ctx context.Context, agentUUID string) (id uuid.UUID, tenantSlug, hostname, ipAddress, osType string, err error) {
	err = db.pool.QueryRow(ctx, `
		SELECT id, tenant_slug, hostname, ip_address, os_type
		FROM endpoint_agents
		WHERE agent_uuid = $1
	`, agentUUID).Scan(&id, &tenantSlug, &hostname, &ipAddress, &osType)
	return
}

// SaveFIMEvents inserts a batch of FIM events
func (db *DB) SaveFIMEvents(ctx context.Context, tenantSlug string, agentID uuid.UUID, events []models.FIMEvent) error {
	if len(events) == 0 {
		return nil
	}

	query := `
		INSERT INTO endpoint_fim_events (
			tenant_slug, agent_id, event_type, target_type, target_path,
			previous_hash, current_hash, file_size_bytes, permissions,
			process_name, process_pid, user_name, severity, mitre_tactic,
			mitre_technique, details, timestamp
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`

	for _, e := range events {
		ts := e.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		sev := e.Severity
		if sev == "" {
			sev = "MEDIUM"
		}
		tt := e.TargetType
		if tt == "" {
			tt = "file"
		}

		_, err := db.pool.Exec(ctx, query,
			tenantSlug, agentID, e.EventType, tt, e.TargetPath,
			e.PreviousHash, e.CurrentHash, e.FileSizeBytes, e.Permissions,
			e.ProcessName, e.ProcessPID, e.UserName, sev, e.MITRETactic,
			e.MITRETechnique, e.Details, ts,
		)
		if err != nil {
			return fmt.Errorf("inserting fim event: %w", err)
		}
	}

	return nil
}

// SaveFIMBaselines updates or inserts cryptographic hash baselines for an agent
func (db *DB) SaveFIMBaselines(ctx context.Context, tenantSlug string, agentID uuid.UUID, baselines []models.FIMBaselineItem) error {
	if len(baselines) == 0 {
		return nil
	}

	query := `
		INSERT INTO endpoint_fim_baselines (
			tenant_slug, agent_id, target_path, target_type,
			sha256_hash, file_size_bytes, permissions, last_checked
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (agent_id, target_path) DO UPDATE SET
			sha256_hash = EXCLUDED.sha256_hash,
			file_size_bytes = EXCLUDED.file_size_bytes,
			permissions = EXCLUDED.permissions,
			last_checked = NOW()
	`

	for _, b := range baselines {
		tt := b.TargetType
		if tt == "" {
			tt = "file"
		}
		_, err := db.pool.Exec(ctx, query,
			tenantSlug, agentID, b.TargetPath, tt,
			b.SHA256Hash, b.FileSizeBytes, b.Permissions,
		)
		if err != nil {
			return fmt.Errorf("upserting fim baseline: %w", err)
		}
	}

	return nil
}

// ListFIMEvents queries FIM deviation events with filters
func (db *DB) ListFIMEvents(ctx context.Context, tenantSlug, agentIDStr, severity, eventType, search string, limit, offset int) ([]models.FIMEvent, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	where := []string{"($1 = '' OR $1 = 'all' OR e.tenant_slug = $1)"}
	args := []interface{}{tenantSlug}
	argIdx := 2

	if agentIDStr != "" {
		if parsed, err := uuid.Parse(agentIDStr); err == nil {
			where = append(where, fmt.Sprintf("e.agent_id = $%d", argIdx))
			args = append(args, parsed)
			argIdx++
		}
	}

	if severity != "" && severity != "all" {
		where = append(where, fmt.Sprintf("e.severity = $%d", argIdx))
		args = append(args, strings.ToUpper(severity))
		argIdx++
	}

	if eventType != "" && eventType != "all" {
		where = append(where, fmt.Sprintf("e.event_type = $%d", argIdx))
		args = append(args, strings.ToLower(eventType))
		argIdx++
	}

	if search != "" {
		where = append(where, fmt.Sprintf("(e.target_path ILIKE $%d OR a.hostname ILIKE $%d OR e.process_name ILIKE $%d OR e.user_name ILIKE $%d)", argIdx, argIdx, argIdx, argIdx))
		args = append(args, "%"+search+"%")
		argIdx++
	}

	whereClause := strings.Join(where, " AND ")

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_fim_events e
		JOIN endpoint_agents a ON a.id = e.agent_id
		WHERE %s
	`, whereClause)

	var total int
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT 
			e.id, e.tenant_slug, e.agent_id, a.hostname, a.ip_address, a.os_type,
			e.event_type, e.target_type, e.target_path, COALESCE(e.previous_hash, ''),
			COALESCE(e.current_hash, ''), e.file_size_bytes, COALESCE(e.permissions, ''),
			COALESCE(e.process_name, ''), COALESCE(e.process_pid, 0), COALESCE(e.user_name, ''),
			e.severity, COALESCE(e.mitre_tactic, ''), COALESCE(e.mitre_technique, ''),
			COALESCE(e.details, ''), e.timestamp
		FROM endpoint_fim_events e
		JOIN endpoint_agents a ON a.id = e.agent_id
		WHERE %s
		ORDER BY e.timestamp DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []models.FIMEvent
	for rows.Next() {
		var e models.FIMEvent
		err := rows.Scan(
			&e.ID, &e.TenantSlug, &e.AgentID, &e.AgentHostname, &e.AgentIP, &e.AgentOS,
			&e.EventType, &e.TargetType, &e.TargetPath, &e.PreviousHash,
			&e.CurrentHash, &e.FileSizeBytes, &e.Permissions,
			&e.ProcessName, &e.ProcessPID, &e.UserName,
			&e.Severity, &e.MITRETactic, &e.MITRETechnique,
			&e.Details, &e.Timestamp,
		)
		if err == nil {
			events = append(events, e)
		}
	}

	return events, total, nil
}

// GetFIMEventByID retrieves a single FIM deviation event
func (db *DB) GetFIMEventByID(ctx context.Context, id uuid.UUID, tenantSlug string) (*models.FIMEvent, error) {
	query := `
		SELECT 
			e.id, e.tenant_slug, e.agent_id, a.hostname, a.ip_address, a.os_type,
			e.event_type, e.target_type, e.target_path, COALESCE(e.previous_hash, ''),
			COALESCE(e.current_hash, ''), e.file_size_bytes, COALESCE(e.permissions, ''),
			COALESCE(e.process_name, ''), COALESCE(e.process_pid, 0), COALESCE(e.user_name, ''),
			e.severity, COALESCE(e.mitre_tactic, ''), COALESCE(e.mitre_technique, ''),
			COALESCE(e.details, ''), e.timestamp
		FROM endpoint_fim_events e
		JOIN endpoint_agents a ON a.id = e.agent_id
		WHERE e.id = $1 AND ($2 = '' OR $2 = 'all' OR e.tenant_slug = $2)
	`

	var e models.FIMEvent
	err := db.pool.QueryRow(ctx, query, id, tenantSlug).Scan(
		&e.ID, &e.TenantSlug, &e.AgentID, &e.AgentHostname, &e.AgentIP, &e.AgentOS,
		&e.EventType, &e.TargetType, &e.TargetPath, &e.PreviousHash,
		&e.CurrentHash, &e.FileSizeBytes, &e.Permissions,
		&e.ProcessName, &e.ProcessPID, &e.UserName,
		&e.Severity, &e.MITRETactic, &e.MITRETechnique,
		&e.Details, &e.Timestamp,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("fim event not found")
		}
		return nil, err
	}

	return &e, nil
}

// GetFIMSummary calculates aggregated KPIs for File Integrity Monitoring
func (db *DB) GetFIMSummary(ctx context.Context, tenantSlug string) (*models.FIMSummary, error) {
	summary := &models.FIMSummary{
		RecentEvents: []models.FIMEvent{},
	}

	query := `
		SELECT 
			COUNT(*),
			COALESCE(COUNT(*) FILTER (WHERE severity = 'CRITICAL'), 0) as crit,
			COALESCE(COUNT(*) FILTER (WHERE severity = 'HIGH'), 0) as high,
			COALESCE(COUNT(DISTINCT agent_id), 0) as impacted_agents
		FROM endpoint_fim_events
		WHERE ($1 = '' OR $1 = 'all' OR tenant_slug = $1)
	`
	_ = db.pool.QueryRow(ctx, query, tenantSlug).Scan(
		&summary.TotalEvents, &summary.CriticalDeviations, &summary.HighDeviations, &summary.ImpactedAgentsCount,
	)

	// Monitored baselines count
	_ = db.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM endpoint_fim_baselines
		WHERE ($1 = '' OR $1 = 'all' OR tenant_slug = $1)
	`, tenantSlug).Scan(&summary.MonitoredPathsCount)

	// Recent 5 events
	recentEvents, _, err := db.ListFIMEvents(ctx, tenantSlug, "", "", "", "", 5, 0)
	if err == nil && recentEvents != nil {
		summary.RecentEvents = recentEvents
	}

	return summary, nil
}

// ListFIMBaselines returns current hash baselines for an endpoint
func (db *DB) ListFIMBaselines(ctx context.Context, tenantSlug string, agentID uuid.UUID) ([]models.FIMBaselineItem, error) {
	query := `
		SELECT id, tenant_slug, agent_id, target_path, target_type, sha256_hash, file_size_bytes, permissions, last_checked
		FROM endpoint_fim_baselines
		WHERE agent_id = $1 AND ($2 = '' OR $2 = 'all' OR tenant_slug = $2)
		ORDER BY target_path ASC
		LIMIT 200
	`

	rows, err := db.pool.Query(ctx, query, agentID, tenantSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.FIMBaselineItem
	for rows.Next() {
		var item models.FIMBaselineItem
		if err := rows.Scan(
			&item.ID, &item.TenantSlug, &item.AgentID, &item.TargetPath, &item.TargetType,
			&item.SHA256Hash, &item.FileSizeBytes, &item.Permissions, &item.LastChecked,
		); err == nil {
			list = append(list, item)
		}
	}

	return list, nil
}
