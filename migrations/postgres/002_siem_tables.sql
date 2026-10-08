-- PostgreSQL Migration: 002_siem_tables.sql
-- SIEM Detection Rules, Alerts/Incidents, and Forensic Notes

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

-- Pre-seed standard SIEM detection rules
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
