-- ClickHouse Migration: 002_materialized_views_1m.sql
-- 1-Minute Materialized Views for sub-millisecond dashboard telemetry and time-series analytics

CREATE TABLE IF NOT EXISTS syslog.events_1m
(
    minute DateTime CODEC(DoubleDelta, ZSTD(1)),
    tenant LowCardinality(String) DEFAULT 'default',
    device_id UUID,
    device_name LowCardinality(String),
    vendor LowCardinality(String),
    product LowCardinality(String),
    severity LowCardinality(String),
    facility LowCardinality(String),
    event_count UInt64,
    total_bytes UInt64
)
ENGINE = SummingMergeTree((event_count, total_bytes))
PARTITION BY toYYYYMM(minute)
ORDER BY (tenant, minute, device_id, vendor, product, severity, facility)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS syslog.mv_events_1m TO syslog.events_1m AS
SELECT
    toStartOfMinute(received_at) AS minute,
    tenant,
    device_id,
    device_name,
    vendor,
    product,
    severity,
    facility,
    count() AS event_count,
    sum(length(raw_message)) AS total_bytes
FROM syslog.syslog_events
GROUP BY
    minute,
    tenant,
    device_id,
    device_name,
    vendor,
    product,
    severity,
    facility;
