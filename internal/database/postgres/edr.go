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

// EnsureEDRSchema initializes tables and indexes for Behavioral Anomaly & Script-Based Attack Prevention EDR (Phase N)
func (db *DB) EnsureEDRSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS endpoint_process_anomalies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			pid INT NOT NULL DEFAULT 0,
			process_name VARCHAR(255) NOT NULL DEFAULT '',
			command_line TEXT NOT NULL DEFAULT '',
			parent_pid INT NOT NULL DEFAULT 0,
			parent_name VARCHAR(255) NOT NULL DEFAULT '',
			parent_command_line TEXT NOT NULL DEFAULT '',
			username VARCHAR(128) NOT NULL DEFAULT '',
			severity VARCHAR(32) NOT NULL DEFAULT 'medium',
			rule_id VARCHAR(64) NOT NULL DEFAULT '',
			rule_name VARCHAR(255) NOT NULL DEFAULT '',
			mitre_tactic VARCHAR(64) NOT NULL DEFAULT '',
			mitre_technique VARCHAR(64) NOT NULL DEFAULT '',
			action_taken VARCHAR(64) NOT NULL DEFAULT 'audited',
			details TEXT NOT NULL DEFAULT '',
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_edr_anomalies_tenant_time ON endpoint_process_anomalies(tenant_slug, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_edr_anomalies_agent_time ON endpoint_process_anomalies(agent_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_edr_anomalies_severity ON endpoint_process_anomalies(tenant_slug, severity, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_edr_anomalies_rule ON endpoint_process_anomalies(rule_id);`,
	}

	for _, q := range queries {
		if _, err := db.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("failed executing EDR schema query: %w", err)
		}
	}
	return nil
}

// RecordProcessAnomalies persists newly detected behavioral anomalies and malicious scripts
func (db *DB) RecordProcessAnomalies(ctx context.Context, anomalies []models.EndpointProcessAnomaly) error {
	if len(anomalies) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, a := range anomalies {
		id := a.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		tenant := a.TenantSlug
		if tenant == "" {
			tenant = "default"
		}
		sev := strings.ToLower(a.Severity)
		if sev == "" {
			sev = "medium"
		}
		action := a.ActionTaken
		if action == "" {
			action = "audited"
		}
		t := a.Timestamp
		if t.IsZero() {
			t = time.Now().UTC()
		}
		c := a.CreatedAt
		if c.IsZero() {
			c = time.Now().UTC()
		}

		batch.Queue(`
			INSERT INTO endpoint_process_anomalies (
				id, tenant_slug, agent_id, pid, process_name, command_line,
				parent_pid, parent_name, parent_command_line, username,
				severity, rule_id, rule_name, mitre_tactic, mitre_technique,
				action_taken, details, timestamp, created_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10,
				$11, $12, $13, $14, $15,
				$16, $17, $18, $19
			)`,
			id, tenant, a.AgentID, a.PID, a.ProcessName, a.CommandLine,
			a.ParentPID, a.ParentName, a.ParentCommandLine, a.Username,
			sev, a.RuleID, a.RuleName, a.MitreTactic, a.MitreTechnique,
			action, a.Details, t, c,
		)
	}

	br := db.pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(anomalies); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("failed inserting process anomaly batch item %d: %w", i, err)
		}
	}
	return nil
}

// ListProcessAnomalies retrieves filtered behavioral anomaly events with agent metadata
func (db *DB) ListProcessAnomalies(ctx context.Context, tenant string, agentID *uuid.UUID, severity, search string, limit, offset int) ([]models.EndpointProcessAnomaly, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var where []string
	var args []interface{}
	argIdx := 1

	if tenant != "" && tenant != "all" {
		where = append(where, fmt.Sprintf("e.tenant_slug = $%d", argIdx))
		args = append(args, tenant)
		argIdx++
	}

	if agentID != nil && *agentID != uuid.Nil {
		where = append(where, fmt.Sprintf("e.agent_id = $%d", argIdx))
		args = append(args, *agentID)
		argIdx++
	}

	if severity != "" && severity != "all" {
		where = append(where, fmt.Sprintf("LOWER(e.severity) = LOWER($%d)", argIdx))
		args = append(args, severity)
		argIdx++
	}

	if search = strings.TrimSpace(search); search != "" {
		like := "%" + search + "%"
		where = append(where, fmt.Sprintf(`(
			e.process_name ILIKE $%d OR
			e.command_line ILIKE $%d OR
			e.parent_name ILIKE $%d OR
			e.rule_name ILIKE $%d OR
			e.details ILIKE $%d OR
			a.hostname ILIKE $%d OR
			a.ip_address ILIKE $%d
		)`, argIdx, argIdx, argIdx, argIdx, argIdx, argIdx, argIdx))
		args = append(args, like)
		argIdx++
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_process_anomalies e
		LEFT JOIN endpoint_agents a ON e.agent_id = a.id
		%s
	`, whereClause)

	var total int64
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed counting process anomalies: %w", err)
	}

	selectQuery := fmt.Sprintf(`
		SELECT
			e.id, e.tenant_slug, e.agent_id,
			COALESCE(a.hostname, 'unknown') AS agent_hostname,
			COALESCE(a.ip_address, '') AS agent_ip,
			e.pid, e.process_name, e.command_line,
			e.parent_pid, e.parent_name, e.parent_command_line,
			e.username, e.severity, e.rule_id, e.rule_name,
			e.mitre_tactic, e.mitre_technique, e.action_taken,
			e.details, e.timestamp, e.created_at
		FROM endpoint_process_anomalies e
		LEFT JOIN endpoint_agents a ON e.agent_id = a.id
		%s
		ORDER BY e.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed querying process anomalies: %w", err)
	}
	defer rows.Close()

	var list []models.EndpointProcessAnomaly
	for rows.Next() {
		var a models.EndpointProcessAnomaly
		err := rows.Scan(
			&a.ID, &a.TenantSlug, &a.AgentID,
			&a.AgentHostname, &a.AgentIP,
			&a.PID, &a.ProcessName, &a.CommandLine,
			&a.ParentPID, &a.ParentName, &a.ParentCommandLine,
			&a.Username, &a.Severity, &a.RuleID, &a.RuleName,
			&a.MitreTactic, &a.MitreTechnique, &a.ActionTaken,
			&a.Details, &a.Timestamp, &a.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed scanning process anomaly row: %w", err)
		}
		list = append(list, a)
	}

	return list, total, nil
}

// GetEDRStats computes summary metrics for Phase N Behavioral EDR
func (db *DB) GetEDRStats(ctx context.Context, tenant string) (*models.EDRStats, error) {
	stats := &models.EDRStats{}

	var tenantFilter string
	var args []interface{}
	if tenant != "" && tenant != "all" {
		tenantFilter = "WHERE tenant_slug = $1"
		args = append(args, tenant)
	}

	query := fmt.Sprintf(`
		SELECT
			COUNT(*) AS total_detections,
			COALESCE(COUNT(*) FILTER (WHERE LOWER(severity) IN ('critical', 'high')), 0) AS critical_threats,
			COALESCE(COUNT(*) FILTER (WHERE LOWER(rule_id) LIKE '%%script%%' OR LOWER(process_name) IN ('powershell.exe', 'cmd.exe', 'bash', 'sh', 'cscript.exe', 'wscript.exe', 'mshta.exe')), 0) AS suspicious_scripts,
			COALESCE(COUNT(*) FILTER (WHERE LOWER(action_taken) = 'terminated'), 0) AS processes_terminated,
			COUNT(DISTINCT agent_id) AS monitored_agents_count
		FROM endpoint_process_anomalies
		%s
	`, tenantFilter)

	err := db.pool.QueryRow(ctx, query, args...).Scan(
		&stats.TotalDetections,
		&stats.CriticalThreats,
		&stats.SuspiciousScripts,
		&stats.ProcessesTerminated,
		&stats.MonitoredAgentsCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed computing EDR stats: %w", err)
	}

	return stats, nil
}
