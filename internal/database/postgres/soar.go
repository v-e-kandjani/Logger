package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/syslog-platform/logger/internal/models"
)

// EnsureSOARSchema creates all required tables and default records for SOAR Playbooks
func (db *DB) EnsureSOARSchema(ctx context.Context) error {
	schema := `
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

	-- 1. SOAR Playbooks
	CREATE TABLE IF NOT EXISTS soar_playbooks (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		name VARCHAR(128) NOT NULL,
		description TEXT DEFAULT '',
		is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
		execution_mode VARCHAR(32) NOT NULL DEFAULT 'autonomous',
		trigger_conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
		actions JSONB NOT NULL DEFAULT '[]'::jsonb,
		cooldown_minutes INT NOT NULL DEFAULT 5,
		total_executions INT NOT NULL DEFAULT 0,
		last_executed_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_soar_pb_tenant ON soar_playbooks(tenant_slug);
	CREATE INDEX IF NOT EXISTS idx_soar_pb_enabled ON soar_playbooks(is_enabled);
	CREATE INDEX IF NOT EXISTS idx_soar_pb_created ON soar_playbooks(created_at DESC);

	-- 2. SOAR Playbook Executions
	CREATE TABLE IF NOT EXISTS soar_executions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		playbook_id UUID REFERENCES soar_playbooks(id) ON DELETE SET NULL,
		playbook_name VARCHAR(128) NOT NULL,
		alert_id UUID REFERENCES siem_alerts(id) ON DELETE SET NULL,
		tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
		triggered_by VARCHAR(255) NOT NULL,
		target_agent_id UUID REFERENCES endpoint_agents(id) ON DELETE SET NULL,
		target_host VARCHAR(128) DEFAULT '',
		status VARCHAR(32) NOT NULL DEFAULT 'PENDING_APPROVAL',
		execution_log JSONB NOT NULL DEFAULT '[]'::jsonb,
		actions_executed INT NOT NULL DEFAULT 0,
		error_msg TEXT DEFAULT '',
		approved_by VARCHAR(128) DEFAULT '',
		approved_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		completed_at TIMESTAMPTZ
	);
	CREATE INDEX IF NOT EXISTS idx_soar_exec_tenant ON soar_executions(tenant_slug);
	CREATE INDEX IF NOT EXISTS idx_soar_exec_status ON soar_executions(status);
	CREATE INDEX IF NOT EXISTS idx_soar_exec_playbook ON soar_executions(playbook_id);
	CREATE INDEX IF NOT EXISTS idx_soar_exec_created ON soar_executions(created_at DESC);
	`

	if _, err := db.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("failed creating SOAR schema: %w", err)
	}

	// Seed Default Playbooks if empty
	var count int
	err := db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM soar_playbooks WHERE tenant_slug = 'default'`).Scan(&count)
	if err == nil && count == 0 {
		db.seedDefaultPlaybooks(ctx)
	}

	return nil
}

func (db *DB) seedDefaultPlaybooks(ctx context.Context) {
	// Playbook 1: Ransomware Rapid Network Containment
	pb1Triggers, _ := json.Marshal(models.SOARTriggerConditions{
		Severities:   []string{"CRITICAL"},
		Categories:   []string{"threat", "defense_evasion"},
		MitreTactics: []string{"Impact", "Defense Evasion"},
		MinRiskScore: 80,
	})
	pb1Actions, _ := json.Marshal([]models.SOARAction{
		{
			ID:   "act-1",
			Type: "isolate_host",
			Parameters: map[string]interface{}{
				"reason": "Automated SOAR: Critical Ransomware / Host Tampering Containment",
			},
		},
		{
			ID:   "act-2",
			Type: "osquery_run",
			Parameters: map[string]interface{}{
				"query": "SELECT pid, name, path, cmdline FROM processes ORDER BY pid LIMIT 50;",
			},
		},
		{
			ID:   "act-3",
			Type: "webhook_notify",
			Parameters: map[string]interface{}{
				"message": "Automated SOAR: Endpoint successfully isolated following critical threat detection.",
			},
		},
	})

	// Playbook 2: Critical Brute-Force & Privilege Escalation Triage
	pb2Triggers, _ := json.Marshal(models.SOARTriggerConditions{
		Severities:   []string{"CRITICAL", "HIGH"},
		Categories:   []string{"authentication", "privilege"},
		MitreTactics: []string{"Credential Access", "Privilege Escalation"},
		MinRiskScore: 75,
	})
	pb2Actions, _ := json.Marshal([]models.SOARAction{
		{
			ID:   "act-1",
			Type: "osquery_run",
			Parameters: map[string]interface{}{
				"query": "SELECT port, address, protocol, pid FROM listening_ports;",
			},
		},
		{
			ID:   "act-2",
			Type: "osquery_run",
			Parameters: map[string]interface{}{
				"query": "SELECT user, tty, host, time FROM logged_in_users;",
			},
		},
	})

	// Playbook 3: Suspicious Lateral Movement Host Containment (Manual Approval)
	pb3Triggers, _ := json.Marshal(models.SOARTriggerConditions{
		Severities:   []string{"HIGH", "CRITICAL"},
		MitreTactics: []string{"Lateral Movement"},
		MinRiskScore: 70,
	})
	pb3Actions, _ := json.Marshal([]models.SOARAction{
		{
			ID:   "act-1",
			Type: "isolate_host",
			Parameters: map[string]interface{}{
				"reason": "Analyst Approved SOAR: Lateral Movement Containment",
			},
		},
		{
			ID:   "act-2",
			Type: "osquery_run",
			Parameters: map[string]interface{}{
				"query": "SELECT pid, name, path, cmdline FROM processes WHERE name LIKE '%cmd%' OR name LIKE '%powershell%' OR name LIKE '%bash%';",
			},
		},
	})

	query := `
	INSERT INTO soar_playbooks (id, tenant_slug, name, description, is_enabled, execution_mode, trigger_conditions, actions, cooldown_minutes)
	VALUES 
	($1, 'default', 'Ransomware Rapid Network Containment', 'Automatically cuts off host network interfaces upon detection of critical ransomware or mass file modification behaviors, while preserving LogSeal SOC connectivity and taking a running process snapshot.', true, 'autonomous', $2, $3, 15),
	($4, 'default', 'Critical Brute-Force & Sockets Forensic Snapshot', 'Automated live forensic OSQuery investigation gathering active listening sockets and logged-in user sessions upon critical authentication attacks or credential stuffing.', true, 'autonomous', $5, $6, 10),
	($7, 'default', 'Suspicious Lateral Movement Host Containment', 'Requires analyst confirmation to isolate the endpoint and capture command-line activity upon detection of lateral movement tools (PsExec, WMI, WinRM).', true, 'manual_approval', $8, $9, 30)
	ON CONFLICT (id) DO NOTHING;
	`
	_, _ = db.pool.Exec(ctx, query,
		uuid.New(), pb1Triggers, pb1Actions,
		uuid.New(), pb2Triggers, pb2Actions,
		uuid.New(), pb3Triggers, pb3Actions,
	)
}

// ListPlaybooks retrieves all playbooks for a tenant (including root default playbooks if non-default)
func (db *DB) ListPlaybooks(ctx context.Context, tenantSlug string) ([]*models.SOARPlaybook, error) {
	var query string
	var args []interface{}
	if tenantSlug == "" || tenantSlug == "all" {
		query = `SELECT id, tenant_slug, name, description, is_enabled, execution_mode, trigger_conditions, actions, cooldown_minutes, total_executions, last_executed_at, created_at, updated_at FROM soar_playbooks ORDER BY created_at ASC`
	} else if tenantSlug == "default" {
		query = `SELECT id, tenant_slug, name, description, is_enabled, execution_mode, trigger_conditions, actions, cooldown_minutes, total_executions, last_executed_at, created_at, updated_at FROM soar_playbooks WHERE tenant_slug = 'default' ORDER BY created_at ASC`
	} else {
		query = `SELECT id, tenant_slug, name, description, is_enabled, execution_mode, trigger_conditions, actions, cooldown_minutes, total_executions, last_executed_at, created_at, updated_at FROM soar_playbooks WHERE tenant_slug = $1 OR tenant_slug = 'default' ORDER BY created_at ASC`
		args = append(args, tenantSlug)
	}

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var playbooks []*models.SOARPlaybook
	for rows.Next() {
		var pb models.SOARPlaybook
		var tcBytes, actBytes []byte
		var lastExec sql.NullTime

		if err := rows.Scan(
			&pb.ID, &pb.TenantSlug, &pb.Name, &pb.Description, &pb.IsEnabled,
			&pb.ExecutionMode, &tcBytes, &actBytes, &pb.CooldownMinutes,
			&pb.TotalExecutions, &lastExec, &pb.CreatedAt, &pb.UpdatedAt,
		); err != nil {
			return nil, err
		}

		_ = json.Unmarshal(tcBytes, &pb.TriggerConditions)
		_ = json.Unmarshal(actBytes, &pb.Actions)
		if lastExec.Valid {
			t := lastExec.Time
			pb.LastExecutedAt = &t
		}
		playbooks = append(playbooks, &pb)
	}
	return playbooks, nil
}

// GetPlaybookByID retrieves a single playbook by UUID
func (db *DB) GetPlaybookByID(ctx context.Context, tenantSlug string, id uuid.UUID) (*models.SOARPlaybook, error) {
	query := `SELECT id, tenant_slug, name, description, is_enabled, execution_mode, trigger_conditions, actions, cooldown_minutes, total_executions, last_executed_at, created_at, updated_at FROM soar_playbooks WHERE id = $1`
	var pb models.SOARPlaybook
	var tcBytes, actBytes []byte
	var lastExec sql.NullTime

	err := db.pool.QueryRow(ctx, query, id).Scan(
		&pb.ID, &pb.TenantSlug, &pb.Name, &pb.Description, &pb.IsEnabled,
		&pb.ExecutionMode, &tcBytes, &actBytes, &pb.CooldownMinutes,
		&pb.TotalExecutions, &lastExec, &pb.CreatedAt, &pb.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	_ = json.Unmarshal(tcBytes, &pb.TriggerConditions)
	_ = json.Unmarshal(actBytes, &pb.Actions)
	if lastExec.Valid {
		t := lastExec.Time
		pb.LastExecutedAt = &t
	}
	return &pb, nil
}

// CreatePlaybook persists a new playbook
func (db *DB) CreatePlaybook(ctx context.Context, pb *models.SOARPlaybook) error {
	if pb.ID == uuid.Nil {
		pb.ID = uuid.New()
	}
	now := time.Now().UTC()
	pb.CreatedAt = now
	pb.UpdatedAt = now

	tcBytes, _ := json.Marshal(pb.TriggerConditions)
	actBytes, _ := json.Marshal(pb.Actions)

	query := `
	INSERT INTO soar_playbooks (id, tenant_slug, name, description, is_enabled, execution_mode, trigger_conditions, actions, cooldown_minutes, total_executions, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, $10, $11)
	`
	_, err := db.pool.Exec(ctx, query,
		pb.ID, pb.TenantSlug, pb.Name, pb.Description, pb.IsEnabled,
		pb.ExecutionMode, tcBytes, actBytes, pb.CooldownMinutes, pb.CreatedAt, pb.UpdatedAt,
	)
	return err
}

// UpdatePlaybook updates an existing playbook
func (db *DB) UpdatePlaybook(ctx context.Context, pb *models.SOARPlaybook) error {
	pb.UpdatedAt = time.Now().UTC()
	tcBytes, _ := json.Marshal(pb.TriggerConditions)
	actBytes, _ := json.Marshal(pb.Actions)

	query := `
	UPDATE soar_playbooks
	SET name = $1, description = $2, is_enabled = $3, execution_mode = $4,
	    trigger_conditions = $5, actions = $6, cooldown_minutes = $7, updated_at = $8
	WHERE id = $9
	`
	_, err := db.pool.Exec(ctx, query,
		pb.Name, pb.Description, pb.IsEnabled, pb.ExecutionMode,
		tcBytes, actBytes, pb.CooldownMinutes, pb.UpdatedAt, pb.ID,
	)
	return err
}

// TogglePlaybook inverts the is_enabled status of a playbook
func (db *DB) TogglePlaybook(ctx context.Context, tenantSlug string, id uuid.UUID) (bool, error) {
	query := `UPDATE soar_playbooks SET is_enabled = NOT is_enabled, updated_at = NOW() WHERE id = $1 RETURNING is_enabled`
	var isEnabled bool
	err := db.pool.QueryRow(ctx, query, id).Scan(&isEnabled)
	return isEnabled, err
}

// DeletePlaybook deletes a playbook by ID
func (db *DB) DeletePlaybook(ctx context.Context, tenantSlug string, id uuid.UUID) error {
	query := `DELETE FROM soar_playbooks WHERE id = $1`
	_, err := db.pool.Exec(ctx, query, id)
	return err
}

// RecordPlaybookExecutionStats increments executions count and sets last_executed_at
func (db *DB) RecordPlaybookExecutionStats(ctx context.Context, playbookID uuid.UUID) error {
	query := `UPDATE soar_playbooks SET total_executions = total_executions + 1, last_executed_at = NOW(), updated_at = NOW() WHERE id = $1`
	_, err := db.pool.Exec(ctx, query, playbookID)
	return err
}

// CreateExecution saves an initial playbook execution record
func (db *DB) CreateExecution(ctx context.Context, exec *models.SOARPlaybookExecution) error {
	if exec.ID == uuid.Nil {
		exec.ID = uuid.New()
	}
	now := time.Now().UTC()
	exec.CreatedAt = now

	logBytes, _ := json.Marshal(exec.ExecutionLog)

	query := `
	INSERT INTO soar_executions (id, playbook_id, playbook_name, alert_id, tenant_slug, triggered_by, target_agent_id, target_host, status, execution_log, actions_executed, error_msg, approved_by, approved_at, created_at, completed_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`
	_, err := db.pool.Exec(ctx, query,
		exec.ID, exec.PlaybookID, exec.PlaybookName, exec.AlertID, exec.TenantSlug,
		exec.TriggeredBy, exec.TargetAgentID, exec.TargetHost, exec.Status,
		logBytes, exec.ActionsExecuted, exec.ErrorMsg, exec.ApprovedBy, exec.ApprovedAt,
		exec.CreatedAt, exec.CompletedAt,
	)
	return err
}

// UpdateExecution updates an execution record with final status and logs
func (db *DB) UpdateExecution(ctx context.Context, exec *models.SOARPlaybookExecution) error {
	logBytes, _ := json.Marshal(exec.ExecutionLog)

	query := `
	UPDATE soar_executions
	SET status = $1, execution_log = $2, actions_executed = $3, error_msg = $4,
	    approved_by = $5, approved_at = $6, completed_at = $7
	WHERE id = $8
	`
	_, err := db.pool.Exec(ctx, query,
		exec.Status, logBytes, exec.ActionsExecuted, exec.ErrorMsg,
		exec.ApprovedBy, exec.ApprovedAt, exec.CompletedAt, exec.ID,
	)
	return err
}

// ListExecutions retrieves playbook execution history
func (db *DB) ListExecutions(ctx context.Context, tenantSlug string, limit int, statusFilter string) ([]*models.SOARPlaybookExecution, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var sb strings.Builder
	sb.WriteString(`SELECT id, playbook_id, playbook_name, alert_id, tenant_slug, triggered_by, target_agent_id, target_host, status, execution_log, actions_executed, error_msg, approved_by, approved_at, created_at, completed_at FROM soar_executions`)

	var conditions []string
	var args []interface{}
	idx := 1

	if tenantSlug != "" && tenantSlug != "all" {
		conditions = append(conditions, fmt.Sprintf("tenant_slug = $%d", idx))
		args = append(args, tenantSlug)
		idx++
	}

	if statusFilter != "" && statusFilter != "ALL" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", idx))
		args = append(args, statusFilter)
		idx++
	}

	if len(conditions) > 0 {
		sb.WriteString(" WHERE ")
		sb.WriteString(strings.Join(conditions, " AND "))
	}

	sb.WriteString(fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", idx))
	args = append(args, limit)

	rows, err := db.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.SOARPlaybookExecution
	for rows.Next() {
		var e models.SOARPlaybookExecution
		var alertID, agentID *uuid.UUID
		var logBytes []byte
		var appAt, compAt sql.NullTime

		if err := rows.Scan(
			&e.ID, &e.PlaybookID, &e.PlaybookName, &alertID, &e.TenantSlug,
			&e.TriggeredBy, &agentID, &e.TargetHost, &e.Status, &logBytes,
			&e.ActionsExecuted, &e.ErrorMsg, &e.ApprovedBy, &appAt, &e.CreatedAt, &compAt,
		); err != nil {
			return nil, err
		}

		e.AlertID = alertID
		e.TargetAgentID = agentID
		_ = json.Unmarshal(logBytes, &e.ExecutionLog)
		if appAt.Valid {
			t := appAt.Time
			e.ApprovedAt = &t
		}
		if compAt.Valid {
			t := compAt.Time
			e.CompletedAt = &t
		}
		list = append(list, &e)
	}
	return list, nil
}

// GetExecutionByID retrieves a single execution record
func (db *DB) GetExecutionByID(ctx context.Context, tenantSlug string, id uuid.UUID) (*models.SOARPlaybookExecution, error) {
	query := `SELECT id, playbook_id, playbook_name, alert_id, tenant_slug, triggered_by, target_agent_id, target_host, status, execution_log, actions_executed, error_msg, approved_by, approved_at, created_at, completed_at FROM soar_executions WHERE id = $1`

	var e models.SOARPlaybookExecution
	var alertID, agentID *uuid.UUID
	var logBytes []byte
	var appAt, compAt sql.NullTime

	err := db.pool.QueryRow(ctx, query, id).Scan(
		&e.ID, &e.PlaybookID, &e.PlaybookName, &alertID, &e.TenantSlug,
		&e.TriggeredBy, &agentID, &e.TargetHost, &e.Status, &logBytes,
		&e.ActionsExecuted, &e.ErrorMsg, &e.ApprovedBy, &appAt, &e.CreatedAt, &compAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	e.AlertID = alertID
	e.TargetAgentID = agentID
	_ = json.Unmarshal(logBytes, &e.ExecutionLog)
	if appAt.Valid {
		t := appAt.Time
		e.ApprovedAt = &t
	}
	if compAt.Valid {
		t := compAt.Time
		e.CompletedAt = &t
	}
	return &e, nil
}

// GetSOARStats aggregates telemetry cards
func (db *DB) GetSOARStats(ctx context.Context, tenantSlug string) (*models.SOARStats, error) {
	stats := &models.SOARStats{}

	filter := ""
	var args []interface{}
	if tenantSlug != "" && tenantSlug != "all" {
		filter = " WHERE tenant_slug = $1"
		args = append(args, tenantSlug)
	}

	// 1. Playbooks
	q1 := fmt.Sprintf(`SELECT COUNT(*), COUNT(*) FILTER (WHERE is_enabled = true) FROM soar_playbooks%s`, filter)
	_ = db.pool.QueryRow(ctx, q1, args...).Scan(&stats.TotalPlaybooks, &stats.ActivePlaybooks)

	// 2. Executions
	q2 := fmt.Sprintf(`SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'PENDING_APPROVAL') FROM soar_executions%s`, filter)
	_ = db.pool.QueryRow(ctx, q2, args...).Scan(&stats.TotalExecutions, &stats.PendingApprovals)

	// 3. Contained Hosts
	q3 := fmt.Sprintf(`SELECT COUNT(*) FROM endpoint_agents WHERE is_isolated = true%s`, filter)
	_ = db.pool.QueryRow(ctx, q3, args...).Scan(&stats.ContainedHosts)

	return stats, nil
}

// FindAgentForAlert identifies an active endpoint agent matching an alert's host, source IP, or destination IP
func (db *DB) FindAgentForAlert(ctx context.Context, tenantSlug string, deviceName string, sourceIP string, destIP string) (*models.EndpointAgent, error) {
	var conditions []string
	var args []interface{}
	idx := 1

	if tenantSlug != "" && tenantSlug != "all" {
		conditions = append(conditions, fmt.Sprintf("(tenant_slug = $%d OR tenant_slug = 'default')", idx))
		args = append(args, tenantSlug)
		idx++
	}

	var matchClauses []string
	if deviceName != "" {
		matchClauses = append(matchClauses, fmt.Sprintf("LOWER(hostname) = LOWER($%d)", idx))
		args = append(args, deviceName)
		idx++
	}
	if sourceIP != "" && sourceIP != "127.0.0.1" && sourceIP != "0.0.0.0" {
		matchClauses = append(matchClauses, fmt.Sprintf("ip_address = $%d", idx))
		args = append(args, sourceIP)
		idx++
	}
	if destIP != "" && destIP != "127.0.0.1" && destIP != "0.0.0.0" {
		matchClauses = append(matchClauses, fmt.Sprintf("ip_address = $%d", idx))
		args = append(args, destIP)
		idx++
	}

	if len(matchClauses) == 0 {
		return nil, nil
	}

	conditions = append(conditions, "("+strings.Join(matchClauses, " OR ")+")")
	query := fmt.Sprintf(`SELECT id, tenant_slug, hostname, os_type, os_family, os_version, ip_address, agent_version, is_isolated, isolation_reason, status FROM endpoint_agents WHERE %s ORDER BY last_seen DESC NULLS LAST LIMIT 1`, strings.Join(conditions, " AND "))

	var ag models.EndpointAgent
	var reason sql.NullString
	err := db.pool.QueryRow(ctx, query, args...).Scan(
		&ag.ID, &ag.TenantSlug, &ag.Hostname, &ag.OSType, &ag.OSFamily, &ag.OSVersion,
		&ag.IPAddress, &ag.AgentVersion, &ag.IsIsolated, &reason, &ag.Status,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if reason.Valid {
		ag.IsolationReason = reason.String
	}
	return &ag, nil
}
