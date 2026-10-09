-- PostgreSQL Migration: 001_initial_schema.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Device Groups
CREATE TABLE IF NOT EXISTS device_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Registered Syslog Devices
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL,
    ip_address INET NOT NULL UNIQUE,
    hostname VARCHAR(255) DEFAULT '',
    description TEXT DEFAULT '',
    vendor VARCHAR(64) NOT NULL DEFAULT 'Generic',
    device_type VARCHAR(64) NOT NULL DEFAULT 'Other',
    group_id UUID REFERENCES device_groups(id) ON DELETE SET NULL,
    site_location VARCHAR(128) DEFAULT '',
    expected_protocol VARCHAR(16) NOT NULL DEFAULT 'ANY',
    expected_port INT NOT NULL DEFAULT 514,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    retention_days INT NOT NULL DEFAULT 365,
    timestamping_policy VARCHAR(32) NOT NULL DEFAULT 'HOURLY',
    last_seen_at TIMESTAMPTZ,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);

-- Unregistered Sources (auto-detected syslog senders)
CREATE TABLE IF NOT EXISTS unregistered_sources (
    ip_address INET PRIMARY KEY,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    packet_count BIGINT NOT NULL DEFAULT 1,
    last_raw_sample TEXT DEFAULT '',
    detected_facility VARCHAR(32) DEFAULT '',
    detected_severity VARCHAR(32) DEFAULT ''
);

-- Users & Authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(128) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(32) NOT NULL DEFAULT 'Administrator',
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    auth_source VARCHAR(32) NOT NULL DEFAULT 'local',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(128) DEFAULT '',
    mfa_recovery_codes TEXT[] DEFAULT '{}',
    mfa_enrolled_at TIMESTAMPTZ,
    mfa_provider VARCHAR(32) DEFAULT 'totp',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Log Archives (Deterministic batch storage & 5651 timestamp tracking)
CREATE TABLE IF NOT EXISTS log_archives (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    archive_name VARCHAR(255) NOT NULL UNIQUE,
    start_timestamp TIMESTAMPTZ NOT NULL,
    end_timestamp TIMESTAMPTZ NOT NULL,
    record_count BIGINT NOT NULL,
    archive_path TEXT NOT NULL,
    archive_size BIGINT NOT NULL,
    hash_algorithm VARCHAR(32) NOT NULL DEFAULT 'SHA-256',
    hash_value CHAR(64) NOT NULL,
    timestamp_status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    timestamp_request_time TIMESTAMPTZ,
    timestamp_completion_time TIMESTAMPTZ,
    timestamp_evidence_path TEXT DEFAULT '',
    retry_count INT NOT NULL DEFAULT 0,
    last_error TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_archives_timestamps ON log_archives(start_timestamp, end_timestamp);
CREATE INDEX IF NOT EXISTS idx_archives_status ON log_archives(timestamp_status);

-- Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(128) NOT NULL,
    source_ip INET NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource VARCHAR(128) NOT NULL,
    result VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);

-- System Settings
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(64) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
