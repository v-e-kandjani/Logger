-- ClickHouse Migration: 004_endpoint_telemetry.sql
-- Endpoint Security High-Throughput Event Ingestion & Agent Telemetry Metrics

CREATE DATABASE IF NOT EXISTS syslog;

-- 1. Endpoint Events / Logs Forwarded from Agents
CREATE TABLE IF NOT EXISTS syslog.endpoint_events
(
    internal_id UUID DEFAULT generateUUIDv4(),
    event_timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    received_at DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    tenant_slug LowCardinality(String),
    agent_id UUID CODEC(ZSTD(1)),
    hostname LowCardinality(String),
    
    source_type LowCardinality(String),  -- 'winevent', 'journald', 'syslog', 'file'
    channel LowCardinality(String),      -- e.g. 'System', 'Security', 'Application', 'PowerShell'
    severity LowCardinality(String),     -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'
    provider LowCardinality(String),     -- e.g. 'Microsoft-Windows-Security-Auditing'
    event_code UInt32 CODEC(T64, ZSTD(1)),
    
    process String CODEC(ZSTD(1)),
    process_id UInt32 CODEC(T64, ZSTD(1)),
    user String CODEC(ZSTD(1)),
    
    message String CODEC(ZSTD(6)),
    raw_message String CODEC(ZSTD(6)),
    labels Map(String, String) CODEC(ZSTD(1)),
    
    INDEX idx_message message TYPE tokenbf_v1(30720, 2, 0) GRANULARITY 1,
    INDEX idx_hostname hostname TYPE set(100) GRANULARITY 2
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_timestamp)
ORDER BY (tenant_slug, agent_id, severity, event_timestamp, internal_id)
TTL toDateTime(event_timestamp) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- 2. Endpoint Agent Resource Metrics Telemetry
CREATE TABLE IF NOT EXISTS syslog.endpoint_agent_metrics
(
    timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    tenant_slug LowCardinality(String),
    agent_id UUID CODEC(ZSTD(1)),
    cpu_percent Float32 CODEC(Gorilla, ZSTD(1)),
    ram_rss_bytes UInt64 CODEC(T64, ZSTD(1)),
    spool_disk_bytes UInt64 CODEC(T64, ZSTD(1)),
    queue_depth UInt32 CODEC(T64, ZSTD(1)),
    eps_out Float32 CODEC(Gorilla, ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_slug, agent_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
