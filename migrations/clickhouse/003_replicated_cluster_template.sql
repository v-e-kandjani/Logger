-- ClickHouse Migration: 003_replicated_cluster_template.sql
-- High-Availability & SaaS Multi-Node Scale-Out Template for LogSeal
-- Note: Deploy on multi-node ClickHouse clusters using ClickHouse Keeper or ZooKeeper.

-- 1. Local Replicated Events Table on each cluster node
CREATE TABLE IF NOT EXISTS syslog.syslog_events_local ON CLUSTER '{cluster}'
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
    tenant LowCardinality(String) DEFAULT 'default',
    
    INDEX idx_message message TYPE tokenbf_v1(30720, 2, 0) GRANULARITY 1,
    INDEX idx_raw raw_message TYPE tokenbf_v1(30720, 2, 0) GRANULARITY 1,
    INDEX idx_source_ip source_ip TYPE minmax GRANULARITY 1,
    INDEX idx_hostname hostname TYPE set(100) GRANULARITY 2
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/syslog_events', '{replica}')
PARTITION BY toYYYYMM(event_timestamp)
ORDER BY (tenant, device_id, severity_code, event_timestamp, internal_id)
TTL toDateTime(event_timestamp) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- 2. Distributed Virtual Table for querying across all cluster shards
CREATE TABLE IF NOT EXISTS syslog.syslog_events_all ON CLUSTER '{cluster}'
AS syslog.syslog_events_local
ENGINE = Distributed('{cluster}', syslog, syslog_events_local, rand());
