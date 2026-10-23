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

// EnsureNetworkEDRSchema initializes tables and indexes for Network & DNS Protection / Micro-Segmentation (Phase O)
func (db *DB) EnsureNetworkEDRSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS endpoint_network_connections (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			pid INT NOT NULL DEFAULT 0,
			process_name VARCHAR(255) NOT NULL DEFAULT '',
			protocol VARCHAR(16) NOT NULL DEFAULT 'tcp',
			local_ip VARCHAR(64) NOT NULL DEFAULT '',
			local_port INT NOT NULL DEFAULT 0,
			remote_ip VARCHAR(64) NOT NULL DEFAULT '',
			remote_port INT NOT NULL DEFAULT 0,
			remote_domain VARCHAR(255) NOT NULL DEFAULT '',
			state VARCHAR(32) NOT NULL DEFAULT '',
			direction VARCHAR(16) NOT NULL DEFAULT 'outbound',
			threat_severity VARCHAR(32) NOT NULL DEFAULT 'info',
			threat_reason TEXT NOT NULL DEFAULT '',
			action_taken VARCHAR(64) NOT NULL DEFAULT 'allowed',
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_net_conn_tenant_time ON endpoint_network_connections(tenant_slug, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_net_conn_agent_time ON endpoint_network_connections(agent_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_net_conn_threat ON endpoint_network_connections(tenant_slug, threat_severity, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_net_conn_remote ON endpoint_network_connections(remote_ip, remote_port);`,

		`CREATE TABLE IF NOT EXISTS endpoint_dns_queries (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			pid INT NOT NULL DEFAULT 0,
			process_name VARCHAR(255) NOT NULL DEFAULT '',
			query_domain VARCHAR(255) NOT NULL DEFAULT '',
			query_type VARCHAR(16) NOT NULL DEFAULT 'A',
			response_code VARCHAR(32) NOT NULL DEFAULT 'NOERROR',
			resolved_ips TEXT[] NOT NULL DEFAULT '{}',
			entropy_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
			is_dga BOOLEAN NOT NULL DEFAULT FALSE,
			is_malicious BOOLEAN NOT NULL DEFAULT FALSE,
			threat_reason TEXT NOT NULL DEFAULT '',
			action_taken VARCHAR(64) NOT NULL DEFAULT 'resolved',
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_dns_queries_tenant_time ON endpoint_dns_queries(tenant_slug, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_dns_queries_agent_time ON endpoint_dns_queries(agent_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_dns_queries_dga ON endpoint_dns_queries(tenant_slug, is_dga, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON endpoint_dns_queries(query_domain);`,

		`CREATE TABLE IF NOT EXISTS endpoint_firewall_rules (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			rule_name VARCHAR(255) NOT NULL DEFAULT '',
			direction VARCHAR(16) NOT NULL DEFAULT 'outbound',
			action VARCHAR(16) NOT NULL DEFAULT 'block',
			protocol VARCHAR(16) NOT NULL DEFAULT 'any',
			remote_ip VARCHAR(64) NOT NULL DEFAULT '',
			remote_port VARCHAR(64) NOT NULL DEFAULT 'any',
			is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
			reason TEXT NOT NULL DEFAULT '',
			created_by VARCHAR(128) NOT NULL DEFAULT 'admin',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fw_rules_tenant ON endpoint_firewall_rules(tenant_slug);`,
		`CREATE INDEX IF NOT EXISTS idx_fw_rules_agent ON endpoint_firewall_rules(agent_id);`,

		`INSERT INTO siem_rules (id, name, description, severity, risk_score, category, is_enabled, created_at, updated_at)
		 VALUES 
		   ('EDR-NET-THREAT', 'Suspicious Endpoint Network Connection', 'Detects anomalous or malicious outbound socket connections originating from monitored endpoints', 'HIGH', 85, 'network', TRUE, NOW(), NOW()),
		   ('EDR-DGA-DNS', 'High Entropy DGA / Malicious DNS Resolution', 'Detects high Shannon entropy algorithmically generated domains (DGA) or queries to blacklisted domains', 'HIGH', 85, 'network', TRUE, NOW(), NOW()),
		   ('EDR-C2-BEACON-SIM', 'Simulated C2 Periodic Beaconing', 'Detects periodic command & control socket callback beacons with low jitter variance', 'CRITICAL', 95, 'network', TRUE, NOW(), NOW()),
		   ('EDR-DGA-DNS-SIM', 'Simulated DGA Domain Exfiltration', 'Simulated suspicious DNS exfiltration query with pseudo-random high entropy hostname', 'HIGH', 85, 'network', TRUE, NOW(), NOW()),
		   ('EDR-SUSPICIOUS-PORT-SIM', 'Simulated Suspicious Port Connection', 'Detects outbound connections to commonly exploited remote reconnaissance or back-connect ports', 'HIGH', 80, 'network', TRUE, NOW(), NOW()),
		   ('EDR-RULE-WEBSHELL', 'Web Shell / Malicious Persistence Execution', 'Detects web server child process spawning interactive shells or cmd interpreters', 'CRITICAL', 95, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-OFFICE-SPAWN', 'Office Document Spawning Shell or Script Host', 'Detects productivity suite applications spawning PowerShell, cmd, or wscript', 'HIGH', 85, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-LOLBIN-CERTUTIL', 'Living Off the Land: Certutil Ingress Tool Transfer', 'Detects certutil.exe used with urlcache or split flags for remote binary retrieval', 'HIGH', 80, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-LOLBIN-MSHTA', 'Living Off the Land: Mshta Execution', 'Detects execution of Microsoft HTML Application host (mshta.exe)', 'HIGH', 80, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-LOLBIN-REGSVR32', 'Living Off the Land: Regsvr32 Squiblydoo', 'Detects regsvr32.exe executing remote scriptlets', 'HIGH', 85, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-LOLBIN-RUNDLL32', 'Living Off the Land: Rundll32 Suspicious Invocation', 'Detects rundll32.exe executing scripts or undocumented exports', 'MEDIUM', 65, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-LOLBIN-BITSADMIN', 'Living Off the Land: Bitsadmin Ingress Download', 'Detects bitsadmin.exe utilized to create background transfer jobs for remote payloads', 'MEDIUM', 65, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-RANSOMWARE-INHIBIT', 'Ransomware: Shadow Copy Deletion / Recovery Invalidation', 'Detects vssadmin or wmic commands attempting to delete volume shadow copies', 'CRITICAL', 95, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-SCRIPT-OBFUSCATION', 'Suspicious Script Obfuscation & Encoded Payload', 'Detects PowerShell with Base64 encoded commands or bypassed execution policies', 'HIGH', 80, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-SCRIPT-STEALTH', 'Stealth Execution Arguments Detected', 'Detects script execution with flags designed to evade interactive command line auditing', 'MEDIUM', 65, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-DOWNLOAD-CRADLE', 'In-Memory Download Cradle Execution', 'Detects Net.WebClient or Invoke-WebRequest piping directly into IEX', 'CRITICAL', 95, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDR-RULE-PIPE-TO-SHELL', 'Curl / Wget Pipe to Shell Execution', 'Detects curl or wget command directly piped to shell', 'HIGH', 85, 'endpoint', TRUE, NOW(), NOW()),
		   ('FIM-INTEGRITY-BREACH', 'Critical File Integrity Modification Detected', 'Alerts on unauthorized modification, creation, or deletion of monitored critical system files', 'HIGH', 85, 'endpoint', TRUE, NOW(), NOW()),
		   ('DLP-USB-VIOLATION', 'Unauthorized USB Mass Storage Device Connection', 'Detects connection of unapproved USB storage devices', 'MEDIUM', 60, 'endpoint', TRUE, NOW(), NOW()),
		   ('EDG-DEAD-MAN-001', 'Edge Node Heartbeat Dead Man Switch', 'Triggers when an enrolled Edge collector fails to send periodic telemetry', 'HIGH', 75, 'health', TRUE, NOW(), NOW())
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name,
		   description = EXCLUDED.description,
		   severity = EXCLUDED.severity,
		   risk_score = EXCLUDED.risk_score,
		   category = EXCLUDED.category,
		   updated_at = NOW();`,
	}

	for _, q := range queries {
		if _, err := db.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("failed executing network EDR schema query: %w", err)
		}
	}
	return nil
}

// RecordNetworkConnections persists active and observed socket flows from endpoints
func (db *DB) RecordNetworkConnections(ctx context.Context, conns []models.EndpointNetworkConnection) error {
	if len(conns) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, c := range conns {
		id := c.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		tenant := c.TenantSlug
		if tenant == "" {
			tenant = "default"
		}
		sev := strings.ToLower(c.ThreatSeverity)
		if sev == "" {
			sev = "info"
		}
		action := c.ActionTaken
		if action == "" {
			action = "allowed"
		}
		dir := c.Direction
		if dir == "" {
			dir = "outbound"
		}
		t := c.Timestamp
		if t.IsZero() {
			t = time.Now().UTC()
		}
		now := c.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}

		batch.Queue(`
			INSERT INTO endpoint_network_connections (
				id, tenant_slug, agent_id, pid, process_name, protocol,
				local_ip, local_port, remote_ip, remote_port, remote_domain,
				state, direction, threat_severity, threat_reason, action_taken,
				timestamp, created_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10, $11,
				$12, $13, $14, $15, $16,
				$17, $18
			)`,
			id, tenant, c.AgentID, c.PID, c.ProcessName, strings.ToLower(c.Protocol),
			c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.RemoteDomain,
			c.State, dir, sev, c.ThreatReason, action,
			t, now,
		)
	}

	br := db.pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(conns); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("failed inserting network connection batch item %d: %w", i, err)
		}
	}
	return nil
}

// ListNetworkConnections retrieves filtered network connections with agent metadata
func (db *DB) ListNetworkConnections(ctx context.Context, tenant string, agentID *uuid.UUID, severity, search string, limit, offset int) ([]models.EndpointNetworkConnection, int64, error) {
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
		where = append(where, fmt.Sprintf("n.tenant_slug = $%d", argIdx))
		args = append(args, tenant)
		argIdx++
	}

	if agentID != nil && *agentID != uuid.Nil {
		where = append(where, fmt.Sprintf("n.agent_id = $%d", argIdx))
		args = append(args, *agentID)
		argIdx++
	}

	if severity != "" && severity != "all" {
		where = append(where, fmt.Sprintf("LOWER(n.threat_severity) = LOWER($%d)", argIdx))
		args = append(args, severity)
		argIdx++
	}

	if search = strings.TrimSpace(search); search != "" {
		like := "%" + search + "%"
		where = append(where, fmt.Sprintf(`(
			n.process_name ILIKE $%d OR
			n.remote_ip ILIKE $%d OR
			n.remote_domain ILIKE $%d OR
			n.threat_reason ILIKE $%d OR
			a.hostname ILIKE $%d OR
			a.ip_address ILIKE $%d
		)`, argIdx, argIdx, argIdx, argIdx, argIdx, argIdx))
		args = append(args, like)
		argIdx++
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_network_connections n
		LEFT JOIN endpoint_agents a ON n.agent_id = a.id
		%s
	`, whereClause)

	var total int64
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed counting network connections: %w", err)
	}

	selectQuery := fmt.Sprintf(`
		SELECT
			n.id, n.tenant_slug, n.agent_id,
			COALESCE(a.hostname, 'unknown') AS agent_hostname,
			COALESCE(a.ip_address, '') AS agent_ip,
			n.pid, n.process_name, n.protocol,
			n.local_ip, n.local_port, n.remote_ip, n.remote_port, n.remote_domain,
			n.state, n.direction, n.threat_severity, n.threat_reason, n.action_taken,
			n.timestamp, n.created_at
		FROM endpoint_network_connections n
		LEFT JOIN endpoint_agents a ON n.agent_id = a.id
		%s
		ORDER BY n.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed querying network connections: %w", err)
	}
	defer rows.Close()

	var list []models.EndpointNetworkConnection
	for rows.Next() {
		var c models.EndpointNetworkConnection
		err := rows.Scan(
			&c.ID, &c.TenantSlug, &c.AgentID,
			&c.AgentHostname, &c.AgentIP,
			&c.PID, &c.ProcessName, &c.Protocol,
			&c.LocalIP, &c.LocalPort, &c.RemoteIP, &c.RemotePort, &c.RemoteDomain,
			&c.State, &c.Direction, &c.ThreatSeverity, &c.ThreatReason, &c.ActionTaken,
			&c.Timestamp, &c.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed scanning network connection row: %w", err)
		}
		list = append(list, c)
	}

	return list, total, nil
}

// RecordDNSQueries persists audited DNS queries with entropy/DGA scoring
func (db *DB) RecordDNSQueries(ctx context.Context, queries []models.EndpointDNSQuery) error {
	if len(queries) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, q := range queries {
		id := q.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		tenant := q.TenantSlug
		if tenant == "" {
			tenant = "default"
		}
		qType := q.QueryType
		if qType == "" {
			qType = "A"
		}
		resp := q.ResponseCode
		if resp == "" {
			resp = "NOERROR"
		}
		action := q.ActionTaken
		if action == "" {
			action = "resolved"
		}
		t := q.Timestamp
		if t.IsZero() {
			t = time.Now().UTC()
		}
		now := q.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}
		resolved := q.ResolvedIPs
		if resolved == nil {
			resolved = []string{}
		}

		batch.Queue(`
			INSERT INTO endpoint_dns_queries (
				id, tenant_slug, agent_id, pid, process_name,
				query_domain, query_type, response_code, resolved_ips,
				entropy_score, is_dga, is_malicious, threat_reason,
				action_taken, timestamp, created_at
			) VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9,
				$10, $11, $12, $13,
				$14, $15, $16
			)`,
			id, tenant, q.AgentID, q.PID, q.ProcessName,
			q.QueryDomain, qType, resp, resolved,
			q.EntropyScore, q.IsDGA, q.IsMalicious, q.ThreatReason,
			action, t, now,
		)
	}

	br := db.pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(queries); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("failed inserting DNS query batch item %d: %w", i, err)
		}
	}
	return nil
}

// ListDNSQueries retrieves filtered DNS query logs with agent metadata
func (db *DB) ListDNSQueries(ctx context.Context, tenant string, agentID *uuid.UUID, dgaOnly bool, search string, limit, offset int) ([]models.EndpointDNSQuery, int64, error) {
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
		where = append(where, fmt.Sprintf("d.tenant_slug = $%d", argIdx))
		args = append(args, tenant)
		argIdx++
	}

	if agentID != nil && *agentID != uuid.Nil {
		where = append(where, fmt.Sprintf("d.agent_id = $%d", argIdx))
		args = append(args, *agentID)
		argIdx++
	}

	if dgaOnly {
		where = append(where, "(d.is_dga = TRUE OR d.is_malicious = TRUE)")
	}

	if search = strings.TrimSpace(search); search != "" {
		like := "%" + search + "%"
		where = append(where, fmt.Sprintf(`(
			d.query_domain ILIKE $%d OR
			d.process_name ILIKE $%d OR
			d.threat_reason ILIKE $%d OR
			a.hostname ILIKE $%d OR
			a.ip_address ILIKE $%d
		)`, argIdx, argIdx, argIdx, argIdx, argIdx))
		args = append(args, like)
		argIdx++
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_dns_queries d
		LEFT JOIN endpoint_agents a ON d.agent_id = a.id
		%s
	`, whereClause)

	var total int64
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed counting DNS queries: %w", err)
	}

	selectQuery := fmt.Sprintf(`
		SELECT
			d.id, d.tenant_slug, d.agent_id,
			COALESCE(a.hostname, 'unknown') AS agent_hostname,
			COALESCE(a.ip_address, '') AS agent_ip,
			d.pid, d.process_name, d.query_domain, d.query_type, d.response_code,
			d.resolved_ips, d.entropy_score, d.is_dga, d.is_malicious,
			d.threat_reason, d.action_taken, d.timestamp, d.created_at
		FROM endpoint_dns_queries d
		LEFT JOIN endpoint_agents a ON d.agent_id = a.id
		%s
		ORDER BY d.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed querying DNS queries: %w", err)
	}
	defer rows.Close()

	var list []models.EndpointDNSQuery
	for rows.Next() {
		var q models.EndpointDNSQuery
		err := rows.Scan(
			&q.ID, &q.TenantSlug, &q.AgentID,
			&q.AgentHostname, &q.AgentIP,
			&q.PID, &q.ProcessName, &q.QueryDomain, &q.QueryType, &q.ResponseCode,
			&q.ResolvedIPs, &q.EntropyScore, &q.IsDGA, &q.IsMalicious,
			&q.ThreatReason, &q.ActionTaken, &q.Timestamp, &q.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed scanning DNS query row: %w", err)
		}
		list = append(list, q)
	}

	return list, total, nil
}

// GetEDRNetworkStats computes summary metrics for Phase O Network & DNS EDR
func (db *DB) GetEDRNetworkStats(ctx context.Context, tenant string) (*models.EDRNetworkStats, error) {
	stats := &models.EDRNetworkStats{}

	var connTenantFilter string
	var dnsTenantFilter string
	var fwTenantFilter string
	var agentTenantFilter string
	var args []interface{}

	if tenant != "" && tenant != "all" {
		connTenantFilter = "WHERE tenant_slug = $1"
		dnsTenantFilter = "WHERE tenant_slug = $1"
		fwTenantFilter = "WHERE tenant_slug = $1"
		agentTenantFilter = "WHERE tenant_slug = $1"
		args = append(args, tenant)
	}

	// 1. Connection stats
	connQuery := fmt.Sprintf(`
		SELECT
			COUNT(*) AS total_conns,
			COALESCE(COUNT(*) FILTER (WHERE LOWER(threat_severity) IN ('high', 'critical')), 0) AS suspicious_conns,
			COALESCE(COUNT(*) FILTER (WHERE LOWER(threat_reason) LIKE '%%beacon%%'), 0) AS c2_beacons
		FROM endpoint_network_connections
		%s
	`, connTenantFilter)

	_ = db.pool.QueryRow(ctx, connQuery, args...).Scan(
		&stats.TotalConnectionsObserved,
		&stats.SuspiciousOutboundConns,
		&stats.C2BeaconsDetected,
	)

	// 2. DNS stats
	dnsQuery := fmt.Sprintf(`
		SELECT
			COUNT(*) AS total_dns,
			COALESCE(COUNT(*) FILTER (WHERE is_dga = TRUE OR is_malicious = TRUE), 0) AS dga_blocked
		FROM endpoint_dns_queries
		%s
	`, dnsTenantFilter)

	_ = db.pool.QueryRow(ctx, dnsQuery, args...).Scan(
		&stats.DNSQueriesAudited,
		&stats.DGADomainsBlocked,
	)

	// 3. Firewall blocks
	fwQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_firewall_rules
		%s
	`, fwTenantFilter)

	_ = db.pool.QueryRow(ctx, fwQuery, args...).Scan(&stats.ActiveFirewallBlocks)

	// 4. Isolated Endpoints
	var isolatedWhere string
	if agentTenantFilter != "" {
		isolatedWhere = agentTenantFilter + " AND is_isolated = TRUE"
	} else {
		isolatedWhere = "WHERE is_isolated = TRUE"
	}
	isoQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_agents
		%s
	`, isolatedWhere)

	_ = db.pool.QueryRow(ctx, isoQuery, args...).Scan(&stats.IsolatedEndpoints)

	return stats, nil
}

// CreateFirewallRule registers a micro-isolation or network blocking rule
func (db *DB) CreateFirewallRule(ctx context.Context, rule *models.EndpointFirewallRule) error {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	if rule.TenantSlug == "" {
		rule.TenantSlug = "default"
	}
	now := time.Now().UTC()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	query := `
		INSERT INTO endpoint_firewall_rules (
			id, tenant_slug, agent_id, rule_name, direction,
			action, protocol, remote_ip, remote_port, is_enabled,
			reason, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14
		)
	`
	_, err := db.pool.Exec(ctx, query,
		rule.ID, rule.TenantSlug, rule.AgentID, rule.RuleName, rule.Direction,
		rule.Action, rule.Protocol, rule.RemoteIP, rule.RemotePort, rule.IsEnabled,
		rule.Reason, rule.CreatedBy, rule.CreatedAt, rule.UpdatedAt,
	)
	return err
}

// ListFirewallRules retrieves all active firewall rules for a tenant or specific agent
func (db *DB) ListFirewallRules(ctx context.Context, tenant string, agentID *uuid.UUID) ([]models.EndpointFirewallRule, error) {
	var where []string
	var args []interface{}
	argIdx := 1

	if tenant != "" && tenant != "all" {
		where = append(where, fmt.Sprintf("tenant_slug = $%d", argIdx))
		args = append(args, tenant)
		argIdx++
	}

	if agentID != nil && *agentID != uuid.Nil {
		where = append(where, fmt.Sprintf("(agent_id = $%d OR agent_id IS NULL)", argIdx))
		args = append(args, *agentID)
		argIdx++
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT
			id, tenant_slug, agent_id, rule_name, direction,
			action, protocol, remote_ip, remote_port, is_enabled,
			reason, created_by, created_at, updated_at
		FROM endpoint_firewall_rules
		%s
		ORDER BY created_at DESC
	`, whereClause)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.EndpointFirewallRule
	for rows.Next() {
		var r models.EndpointFirewallRule
		err := rows.Scan(
			&r.ID, &r.TenantSlug, &r.AgentID, &r.RuleName, &r.Direction,
			&r.Action, &r.Protocol, &r.RemoteIP, &r.RemotePort, &r.IsEnabled,
			&r.Reason, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// DeleteFirewallRule deletes a firewall block rule by ID
func (db *DB) DeleteFirewallRule(ctx context.Context, tenant string, ruleID uuid.UUID) error {
	var query string
	var args []interface{}

	if tenant != "" && tenant != "all" {
		query = "DELETE FROM endpoint_firewall_rules WHERE id = $1 AND tenant_slug = $2"
		args = append(args, ruleID, tenant)
	} else {
		query = "DELETE FROM endpoint_firewall_rules WHERE id = $1"
		args = append(args, ruleID)
	}

	_, err := db.pool.Exec(ctx, query, args...)
	return err
}
