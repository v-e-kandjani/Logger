-- ClickHouse Migration: 001_initial_events.sql
CREATE DATABASE IF NOT EXISTS syslog;

CREATE TABLE IF NOT EXISTS syslog.syslog_events
(
    internal_id UUID DEFAULT generateUUIDv4(),
    event_timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    received_at DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    source_ip IPv4 CODEC(ZSTD(1)),
    source_port UInt16 CODEC(T64, ZSTD(1)),
    transport_protocol LowCardinality(String),
    
    device_id UUID CODEC(ZSTD(1)),
    device_name LowCardinality(String),
    device_group LowCardinality(String),
    vendor LowCardinality(String),
    product LowCardinality(String),
    
    facility_code UInt8 CODEC(T64, ZSTD(1)),
    facility LowCardinality(String),
    severity_code UInt8 CODEC(T64, ZSTD(1)),
    severity LowCardinality(String),
    
    hostname String CODEC(ZSTD(3)),
    application_name LowCardinality(String),
    process_id String CODEC(ZSTD(1)),
    message_id String CODEC(ZSTD(1)),
    structured_data String CODEC(ZSTD(3)),
    
    message String CODEC(ZSTD(6)),
    raw_message String CODEC(ZSTD(6)),
    
    collector_node LowCardinality(String),
    parser_status LowCardinality(String),
    ingestion_timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    
    INDEX idx_message message TYPE tokenbf_v1(30720, 2, 0) GRANULARITY 1,
    INDEX idx_raw raw_message TYPE tokenbf_v1(30720, 2, 0) GRANULARITY 1,
    INDEX idx_source_ip source_ip TYPE minmax GRANULARITY 1,
    INDEX idx_hostname hostname TYPE set(100) GRANULARITY 2
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_timestamp)
ORDER BY (device_id, severity_code, event_timestamp, internal_id)
TTL toDateTime(event_timestamp) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Aggregated Ingestion Rates Materialized View (for ultra-fast dashboard queries)
CREATE TABLE IF NOT EXISTS syslog.events_per_minute
(
    minute DateTime,
    device_id UUID,
    severity LowCardinality(String),
    event_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (minute, device_id, severity);

CREATE MATERIALIZED VIEW IF NOT EXISTS syslog.mv_events_per_minute TO syslog.events_per_minute AS
SELECT
    toStartOfMinute(event_timestamp) AS minute,
    device_id,
    severity,
    count() AS event_count
FROM syslog.syslog_events
GROUP BY minute, device_id, severity;
