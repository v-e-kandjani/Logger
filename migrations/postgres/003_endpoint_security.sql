-- PostgreSQL Migration: 003_endpoint_security.sql
-- Endpoint Security, Agent Management, Inventory, Vulnerability and Patch Subsystem

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

-- Seed Default Policy
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

-- Seed Default Groups
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

-- 6. Current Inventory Metadata (Detailed Host Snapshots)
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

CREATE INDEX IF NOT EXISTS idx_endpoint_inventory_tenant ON endpoint_inventory_current(tenant_slug);

-- 7. Normalized Software Inventory
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

CREATE INDEX IF NOT EXISTS idx_endpoint_software_tenant ON endpoint_software_current(tenant_slug);
CREATE INDEX IF NOT EXISTS idx_endpoint_software_name ON endpoint_software_current(name);
CREATE INDEX IF NOT EXISTS idx_endpoint_software_agent ON endpoint_software_current(agent_id);

-- 8. Normalized CVE Intelligence Catalog
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

CREATE INDEX IF NOT EXISTS idx_endpoint_cve_severity ON endpoint_cve_catalog(severity);
CREATE INDEX IF NOT EXISTS idx_endpoint_cve_score ON endpoint_cve_catalog(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_endpoint_cve_kev ON endpoint_cve_catalog(cisa_kev);
CREATE INDEX IF NOT EXISTS idx_endpoint_cve_epss ON endpoint_cve_catalog(epss_probability DESC);

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

CREATE INDEX IF NOT EXISTS idx_endpoint_findings_tenant ON endpoint_vulnerability_findings(tenant_slug);
CREATE INDEX IF NOT EXISTS idx_endpoint_findings_agent ON endpoint_vulnerability_findings(agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_findings_cve ON endpoint_vulnerability_findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_findings_status ON endpoint_vulnerability_findings(status);
CREATE INDEX IF NOT EXISTS idx_endpoint_findings_priority ON endpoint_vulnerability_findings(priority);

-- 10. Vulnerability Exceptions (Risk Acceptance & Suppression)
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

CREATE INDEX IF NOT EXISTS idx_endpoint_exceptions_tenant ON endpoint_vulnerability_exceptions(tenant_slug);
CREATE INDEX IF NOT EXISTS idx_endpoint_exceptions_cve ON endpoint_vulnerability_exceptions(cve_id);

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

CREATE INDEX IF NOT EXISTS idx_endpoint_patches_tenant ON endpoint_patches_current(tenant_slug);
CREATE INDEX IF NOT EXISTS idx_endpoint_patches_agent ON endpoint_patches_current(agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_patches_status ON endpoint_patches_current(status);

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

CREATE INDEX IF NOT EXISTS idx_endpoint_tasks_agent ON endpoint_tasks(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_endpoint_tasks_tenant ON endpoint_tasks(tenant_slug);

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

-- 14. Vulnerability Feed Sources
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

-- Seed Default Feed Sources
INSERT INTO endpoint_feed_sources (name, feed_type, url, enabled, sync_interval_minutes)
VALUES
    ('nvd', 'cve_nvd_api', 'https://services.nvd.nist.gov/rest/json/cves/2.0', TRUE, 360),
    ('cisa_kev', 'cisa_kev_json', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', TRUE, 720),
    ('epss', 'first_epss_csv', 'https://epss.cyentia.com/epss_scores-current.csv.gz', TRUE, 1440),
    ('osv', 'osv_ecosystems', 'https://osv.dev/docs/api', TRUE, 720)
ON CONFLICT (name) DO NOTHING;

-- 15. Feed Sync Runs
CREATE TABLE IF NOT EXISTS endpoint_feed_sync_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_name VARCHAR(64) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    status VARCHAR(32) NOT NULL DEFAULT 'running',
    records_added INT DEFAULT 0,
    records_updated INT DEFAULT 0,
    error_message TEXT DEFAULT ''
);

-- 16. Agent Releases (Signed Packages Repository)
CREATE TABLE IF NOT EXISTS endpoint_agent_releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version VARCHAR(32) NOT NULL,
    channel VARCHAR(32) NOT NULL DEFAULT 'stable',
    platform VARCHAR(32) NOT NULL,
    arch VARCHAR(32) NOT NULL,
    binary_url TEXT NOT NULL,
    sha256_hash VARCHAR(128) NOT NULL,
    signature TEXT DEFAULT '',
    min_server_version VARCHAR(32) DEFAULT '1.0.0',
    release_notes TEXT DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_endpoint_releases UNIQUE (version, platform, arch, channel)
);
