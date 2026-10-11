package clickhouse

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/syslog-platform/logger/internal/config"
	"github.com/syslog-platform/logger/internal/models"
)

var defaultZeroIPv4 = net.IPv4(0, 0, 0, 0).To4()

// Client wraps ClickHouse connection and asynchronous batch inserter
type Client struct {
	conn        driver.Conn
	cfg         config.ClickHouseConfig
	batchCh     chan *models.LogEvent
	stopCh      chan struct{}
	wg          sync.WaitGroup
	isHealthy   atomic.Bool
	insertQuery string

	// Metrics
	TotalInserted atomic.Uint64
	TotalFailed   atomic.Uint64
	LastFlushTime atomic.Int64
}

// NewClient establishes connection pool to ClickHouse
func NewClient(cfg config.ClickHouseConfig) (*Client, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		DialTimeout: 5 * time.Second,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		if cfg.Host != "127.0.0.1" && cfg.Host != "localhost" {
			log.Printf("[ClickHouse] Host '%s' connection failed (%v), falling back to 127.0.0.1...", cfg.Host, err)
			fallbackCfg := cfg
			fallbackCfg.Host = "127.0.0.1"
			return NewClient(fallbackCfg)
		}
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	c := &Client{
		conn:    conn,
		cfg:     cfg,
		batchCh: make(chan *models.LogEvent, cfg.BatchSize*2),
		stopCh:  make(chan struct{}),
	}
	// Multi-tenant scoping column (idempotent migration; existing rows belong to root tenant)
	if err := conn.Exec(ctx, fmt.Sprintf(
		"ALTER TABLE %s.syslog_events ADD COLUMN IF NOT EXISTS tenant LowCardinality(String) DEFAULT 'default'",
		c.Database())); err != nil {
		log.Printf("[ClickHouse] tenant column migration warning: %v", err)
	}

	// Phase 3: 1-Minute Materialized View table & view initialization
	events1mSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s.events_1m
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
		SETTINGS index_granularity = 8192
	`, c.Database())
	if err := conn.Exec(ctx, events1mSQL); err != nil {
		log.Printf("[ClickHouse] events_1m table init warning: %v", err)
	}

	mv1mSQL := fmt.Sprintf(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS %s.mv_events_1m TO %s.events_1m AS
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
		FROM %s.syslog_events
		GROUP BY
			minute,
			tenant,
			device_id,
			device_name,
			vendor,
			product,
			severity,
			facility
	`, c.Database(), c.Database(), c.Database())
	if err := conn.Exec(ctx, mv1mSQL); err != nil {
		log.Printf("[ClickHouse] mv_events_1m materialized view init warning: %v", err)
	}

	c.insertQuery = fmt.Sprintf(`
		INSERT INTO %s.syslog_events (
			internal_id, event_timestamp, received_at, source_ip, source_port,
			transport_protocol, device_id, device_name, device_group, vendor,
			product, facility_code, facility, severity_code, severity,
			hostname, application_name, process_id, message_id, structured_data,
			message, raw_message, collector_node, parser_status, ingestion_timestamp,
			tenant
		)
	`, c.Database())
	c.isHealthy.Store(true)

	// Start background batch writer worker
	c.wg.Add(1)
	go c.batchWorker()

	return c, nil
}

// Database returns the configured ClickHouse database name with fallback
func (c *Client) Database() string {
	if c.cfg.Database != "" {
		return c.cfg.Database
	}
	return "syslog"
}


// Enqueue delivers an event into the batch buffer
func (c *Client) Enqueue(event *models.LogEvent) {
	select {
	case c.batchCh <- event:
	default:
		// Queue saturated: log warning and drop or push to spool
		c.TotalFailed.Add(1)
		log.Printf("[ClickHouse] Batch channel saturated, event %s dropped", event.InternalID)
	}
}

// batchWorker flushes micro-batches based on batch size or elapsed timeout
func (c *Client) batchWorker() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.cfg.FlushTimeout)
	defer ticker.Stop()

	batch := make([]*models.LogEvent, 0, c.cfg.BatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := c.flushBatch(batch); err != nil {
			log.Printf("[ClickHouse] Batch insert error (%d rows): %v", len(batch), err)
			c.isHealthy.Store(false)
			c.TotalFailed.Add(uint64(len(batch)))
		} else {
			c.isHealthy.Store(true)
			c.TotalInserted.Add(uint64(len(batch)))
			c.LastFlushTime.Store(time.Now().Unix())
		}
		// Zero-allocation: retain slice capacity for next batch
		batch = batch[:0]
	}

	for {
		select {
		case <-c.stopCh:
			// Drain remaining
			for {
				select {
				case ev := <-c.batchCh:
					batch = append(batch, ev)
					if len(batch) >= c.cfg.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}

		case ev := <-c.batchCh:
			batch = append(batch, ev)
			if len(batch) >= c.cfg.BatchSize {
				flush()
			}

		case <-ticker.C:
			if len(batch) > 0 {
				flush()
			}
		}
	}
}

func (c *Client) flushBatch(events []*models.LogEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	batch, err := c.conn.PrepareBatch(ctx, c.insertQuery)
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	for _, ev := range events {
		srcIP := ev.SourceIP
		if srcIP == nil {
			srcIP = defaultZeroIPv4
		} else if ip4 := srcIP.To4(); ip4 != nil {
			srcIP = ip4
		}

		tenant := ev.Tenant
		if tenant == "" {
			tenant = "default"
		}

		err := batch.Append(
			ev.InternalID,
			ev.EventTimestamp,
			ev.ReceivedAt,
			srcIP,
			ev.SourcePort,
			ev.TransportProtocol,
			ev.DeviceID,
			ev.DeviceName,
			ev.DeviceGroup,
			ev.Vendor,
			ev.Product,
			ev.FacilityCode,
			ev.Facility,
			ev.SeverityCode,
			ev.Severity,
			ev.Hostname,
			ev.ApplicationName,
			ev.ProcessID,
			ev.MessageID,
			ev.StructuredData,
			ev.Message,
			ev.RawMessage,
			ev.CollectorNode,
			ev.ParserStatus,
			ev.IngestionTimestamp,
			tenant,
		)
		if err != nil {
			return fmt.Errorf("batch append: %w", err)
		}
	}

	return batch.Send()
}

// Close gracefully drains pending events and terminates connection
func (c *Client) Close() error {
	close(c.stopCh)
	c.wg.Wait()
	return c.conn.Close()
}

// Ping checks if ClickHouse is alive
func (c *Client) Ping(ctx context.Context) error {
	return c.conn.Ping(ctx)
}

// IsHealthy returns atomic connectivity state
func (c *Client) IsHealthy() bool {
	return c.isHealthy.Load()
}

// QueryEvents allows faceted searching over historical records
func (c *Client) QueryEvents(ctx context.Context, query string, args ...any) (driver.Rows, error) {
	return c.conn.Query(ctx, query, args...)
}

// StorageRunway encapsulates retention calculations based on 1st week baseline
type StorageRunway struct {
	HasOneWeekBaseline bool       `json:"has_one_week_baseline"`
	FirstLogReceivedAt *time.Time `json:"first_log_received_at,omitempty"`
	DaysSinceFirstLog  float64    `json:"days_since_first_log"`
	Week1TotalLogs     uint64     `json:"week1_total_logs"`
	Week1AvgEPS        float64    `json:"week1_avg_eps"`
	Week1DailyLogs     float64    `json:"week1_daily_logs"`
	Week1DailyBytes    uint64     `json:"week1_daily_bytes"`
	StorageDays        int        `json:"storage_days"`
	RunwayLabel        string     `json:"runway_label"`
	RunwaySubLabel     string     `json:"runway_sub_label"`
	RunwayLabelTR      string     `json:"runway_label_tr"`
	RunwaySubLabelTR   string     `json:"runway_sub_label_tr"`
}

// StorageStats encapsulates physical disk and table volume telemetry
type StorageStats struct {
	TotalBytesOnDisk      uint64  `json:"total_bytes_on_disk"`
	UncompressedDataBytes uint64  `json:"uncompressed_data_bytes"`
	TotalRows             uint64  `json:"total_rows"`
	CompressionRatio      float64 `json:"compression_ratio"`
	FreeDiskBytes         uint64  `json:"free_disk_bytes"`
	TotalDiskBytes        uint64  `json:"total_disk_bytes"`
	DiskUsagePercent      float64 `json:"disk_usage_percent"`
	ActivePartitions      uint64  `json:"active_partitions"`
}

// CalculateStorageRunway recalculates how many days of storage remain based on the 1st week of logs received.
// Before 1 week (7 days) has elapsed, it returns "Estimated 365 Days (based on Archival & Retention Policies)".
func (c *Client) CalculateStorageRunway(ctx context.Context, tenant string, stats *StorageStats, fifoThresholdPct float64) (*StorageRunway, error) {
	runway := &StorageRunway{
		HasOneWeekBaseline: false,
		StorageDays:        365,
		RunwayLabel:        "Estimated 365 Days",
		RunwaySubLabel:     "(based on Archival & Retention Policies)",
		RunwayLabelTR:      "Tahmini 365 Gün",
		RunwaySubLabelTR:   "(Arşivleme ve Saklama Politikalarına Göre)",
	}

	if stats == nil {
		return runway, nil
	}

	// 1. Find earliest log timestamp from events_1m or syslog_events
	var earliest time.Time
	var latest time.Time

	query1m := fmt.Sprintf("SELECT min(minute), max(minute) FROM %s.events_1m", c.Database())
	if tenant != "" && tenant != "all" && tenant != "*" {
		query1m = fmt.Sprintf("SELECT min(minute), max(minute) FROM %s.events_1m WHERE tenant = '%s'", c.Database(), tenant)
	}
	row := c.conn.QueryRow(ctx, query1m)
	_ = row.Scan(&earliest, &latest)

	if earliest.IsZero() {
		queryRaw := fmt.Sprintf("SELECT min(received_at), max(received_at) FROM %s.syslog_events", c.Database())
		if tenant != "" && tenant != "all" && tenant != "*" {
			queryRaw = fmt.Sprintf("SELECT min(received_at), max(received_at) FROM %s.syslog_events WHERE tenant = '%s'", c.Database(), tenant)
		}
		rowRaw := c.conn.QueryRow(ctx, queryRaw)
		_ = rowRaw.Scan(&earliest, &latest)
	}

	if earliest.IsZero() {
		return runway, nil
	}

	runway.FirstLogReceivedAt = &earliest
	daysSince := time.Since(earliest).Hours() / 24.0
	runway.DaysSinceFirstLog = daysSince

	// If less than 7 days (1st week) of logs have elapsed, policy default is 365 days
	if daysSince < 7.0 {
		return runway, nil
	}

	// We have 1st week baseline! Query event counts and bytes from the 1st week (earliest to earliest + 7 days)
	week1End := earliest.Add(7 * 24 * time.Hour)
	var week1Events uint64
	var week1Bytes uint64

	wQuery := fmt.Sprintf(`
		SELECT coalesce(sum(event_count), 0), coalesce(sum(total_bytes), 0)
		FROM %s.events_1m
		WHERE minute >= ? AND minute < ?
	`, c.Database())
	var wArgs []any
	if tenant != "" && tenant != "all" && tenant != "*" {
		wQuery = fmt.Sprintf(`
			SELECT coalesce(sum(event_count), 0), coalesce(sum(total_bytes), 0)
			FROM %s.events_1m
			WHERE minute >= ? AND minute < ? AND tenant = ?
		`, c.Database())
		wArgs = []any{earliest, week1End, tenant}
	} else {
		wArgs = []any{earliest, week1End}
	}

	wRow := c.conn.QueryRow(ctx, wQuery, wArgs...)
	_ = wRow.Scan(&week1Events, &week1Bytes)

	if week1Events == 0 {
		rawWQuery := fmt.Sprintf(`
			SELECT count(), coalesce(sum(length(raw_message)), 0)
			FROM %s.syslog_events
			WHERE received_at >= ? AND received_at < ?
		`, c.Database())
		if tenant != "" && tenant != "all" && tenant != "*" {
			rawWQuery += " AND tenant = ?"
			wRow = c.conn.QueryRow(ctx, rawWQuery, earliest, week1End, tenant)
		} else {
			wRow = c.conn.QueryRow(ctx, rawWQuery, earliest, week1End)
		}
		_ = wRow.Scan(&week1Events, &week1Bytes)
	}

	if week1Events == 0 {
		return runway, nil
	}

	runway.HasOneWeekBaseline = true
	runway.Week1TotalLogs = week1Events
	runway.Week1AvgEPS = float64(week1Events) / (7.0 * 86400.0)
	runway.Week1DailyLogs = float64(week1Events) / 7.0
	runway.Week1DailyBytes = uint64(float64(week1Bytes) / 7.0)

	compression := stats.CompressionRatio
	if compression <= 0 {
		compression = 1.0
	}
	dailyDiskBytes := float64(runway.Week1DailyBytes) / compression
	if dailyDiskBytes <= 0 {
		dailyDiskBytes = runway.Week1DailyLogs * 120.0
	}

	if fifoThresholdPct <= 0 || fifoThresholdPct > 99 {
		fifoThresholdPct = 85.0
	}
	totalUsableBytes := float64(stats.TotalDiskBytes) * (fifoThresholdPct / 100.0)
	currentlyUsed := float64(stats.TotalDiskBytes - stats.FreeDiskBytes)
	remainingHeadroom := totalUsableBytes - currentlyUsed
	if remainingHeadroom < float64(stats.FreeDiskBytes)*0.5 && stats.FreeDiskBytes > 0 {
		remainingHeadroom = float64(stats.FreeDiskBytes) * 0.85
	}
	if remainingHeadroom <= 0 {
		remainingHeadroom = float64(stats.FreeDiskBytes)
	}

	calcDays := int(remainingHeadroom / dailyDiskBytes)
	if calcDays < 1 {
		calcDays = 1
	}

	runway.StorageDays = calcDays
	runway.RunwayLabel = fmt.Sprintf("%d Days", calcDays)
	runway.RunwaySubLabel = fmt.Sprintf("(recalculated: 1st week avg %.1f EPS, %.0f logs/day)", runway.Week1AvgEPS, runway.Week1DailyLogs)
	runway.RunwayLabelTR = fmt.Sprintf("%d Gün", calcDays)
	runway.RunwaySubLabelTR = fmt.Sprintf("(1. hafta baz alındı: ort. %.1f EPS, %.0f log/gün)", runway.Week1AvgEPS, runway.Week1DailyLogs)

	return runway, nil
}

// GetStorageStats retrieves storage consumption and host disk allocation
func (c *Client) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	stats := &StorageStats{}

	// Query table size metrics
	row := c.conn.QueryRow(ctx, `
		SELECT 
			coalesce(sum(bytes_on_disk), 0),
			coalesce(sum(data_uncompressed_bytes), 0),
			coalesce(sum(rows), 0),
			count(DISTINCT partition)
		FROM system.parts 
		WHERE database = 'syslog' AND active = 1
	`)
	if err := row.Scan(&stats.TotalBytesOnDisk, &stats.UncompressedDataBytes, &stats.TotalRows, &stats.ActivePartitions); err != nil {
		return nil, fmt.Errorf("querying parts stats: %w", err)
	}

	if stats.TotalBytesOnDisk > 0 && stats.UncompressedDataBytes > 0 {
		stats.CompressionRatio = float64(stats.UncompressedDataBytes) / float64(stats.TotalBytesOnDisk)
	} else {
		stats.CompressionRatio = 1.0
	}

	// Query host disk partition metrics
	diskRow := c.conn.QueryRow(ctx, `
		SELECT coalesce(free_space, 0), coalesce(total_space, 0)
		FROM system.disks
		WHERE name = 'default'
	`)
	if err := diskRow.Scan(&stats.FreeDiskBytes, &stats.TotalDiskBytes); err == nil && stats.TotalDiskBytes > 0 {
		used := stats.TotalDiskBytes - stats.FreeDiskBytes
		stats.DiskUsagePercent = (float64(used) / float64(stats.TotalDiskBytes)) * 100
	}

	return stats, nil
}

// PruneOldestPartition drops the chronologically oldest partition to immediately reclaim disk space
func (c *Client) PruneOldestPartition(ctx context.Context) (string, error) {
	var oldestPartition string
	row := c.conn.QueryRow(ctx, `
		SELECT partition
		FROM system.parts
		WHERE database = 'syslog' AND table = 'syslog_events' AND active = 1
		ORDER BY partition ASC
		LIMIT 1
	`)
	if err := row.Scan(&oldestPartition); err != nil {
		return "", fmt.Errorf("finding oldest partition: %w", err)
	}
	if oldestPartition == "" {
		return "", fmt.Errorf("no active partitions found to prune")
	}

	dropQuery := fmt.Sprintf("ALTER TABLE %s.syslog_events DROP PARTITION '%s'", c.Database(), oldestPartition)
	if err := c.conn.Exec(ctx, dropQuery); err != nil {
		return "", fmt.Errorf("dropping partition %s: %w", oldestPartition, err)
	}

	return oldestPartition, nil
}

// PruneOlderThanDays deletes events older than the retention threshold
func (c *Client) PruneOlderThanDays(ctx context.Context, days int) error {
	query := fmt.Sprintf("ALTER TABLE %s.syslog_events DELETE WHERE event_timestamp < now() - INTERVAL %d DAY", c.Database(), days)
	return c.conn.Exec(ctx, query)
}

// TenantStorageMetrics represents detailed physical & logical storage usage per tenant
type TenantStorageMetrics struct {
	Tenant          string    `json:"tenant"`
	LogCount        uint64    `json:"log_count"`
	TotalBytes      uint64    `json:"total_bytes"`
	TotalGB         float64   `json:"total_gb"`
	OldestTimestamp time.Time `json:"oldest_timestamp"`
	NewestTimestamp time.Time `json:"newest_timestamp"`
}

// GetTenantStorageMetrics returns log counts, uncompressed byte volumes, and time bounds per tenant
func (c *Client) GetTenantStorageMetrics(ctx context.Context) (map[string]*TenantStorageMetrics, error) {
	query := fmt.Sprintf(`
		SELECT
			tenant,
			count() AS log_count,
			coalesce(sum(length(raw_message)), 0) AS total_bytes,
			min(received_at) AS oldest_timestamp,
			max(received_at) AS newest_timestamp
		FROM %s.syslog_events
		GROUP BY tenant`, c.Database())
	rows, err := c.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[string]*TenantStorageMetrics)
	for rows.Next() {
		var t string
		var cnt uint64
		var totalBytes uint64
		var oldest, newest time.Time
		if err := rows.Scan(&t, &cnt, &totalBytes, &oldest, &newest); err == nil {
			if t == "" {
				t = "default"
			}
			res[t] = &TenantStorageMetrics{
				Tenant:          t,
				LogCount:        cnt,
				TotalBytes:      totalBytes,
				TotalGB:         float64(totalBytes) / (1024 * 1024 * 1024),
				OldestTimestamp: oldest,
				NewestTimestamp: newest,
			}
		}
	}
	return res, nil
}

// PruneTenantOlderThanDays deletes events and 1m metrics for a specific tenant older than the retention threshold
func (c *Client) PruneTenantOlderThanDays(ctx context.Context, tenant string, days int) error {
	if days <= 0 || tenant == "" {
		return nil
	}
	query := fmt.Sprintf("ALTER TABLE %s.syslog_events DELETE WHERE tenant = '%s' AND received_at < now() - INTERVAL %d DAY", c.Database(), tenant, days)
	if err := c.conn.Exec(ctx, query); err != nil {
		return err
	}
	// Also clean materialized summary table
	query1m := fmt.Sprintf("ALTER TABLE %s.events_1m DELETE WHERE tenant = '%s' AND minute < now() - INTERVAL %d DAY", c.Database(), tenant, days)
	_ = c.conn.Exec(ctx, query1m)
	return nil
}

// PruneTenantOldestBatch deletes the oldest batch of logs for a tenant when their storage quota is exceeded
func (c *Client) PruneTenantOldestBatch(ctx context.Context, tenant string, hours int) error {
	if hours <= 0 {
		hours = 24
	}
	deleteQuery := fmt.Sprintf(`
		ALTER TABLE %s.syslog_events 
		DELETE WHERE tenant = '%s' AND received_at <= (
			SELECT min(received_at) + INTERVAL %d HOUR 
			FROM %s.syslog_events 
			WHERE tenant = '%s'
		)
	`, c.Database(), tenant, hours, c.Database(), tenant)
	return c.conn.Exec(ctx, deleteQuery)
}

// PrunePartitionsOlderThan drops whole monthly ClickHouse partitions that are strictly older than the cutoff month
func (c *Client) PrunePartitionsOlderThan(ctx context.Context, cutoffMonth string) ([]string, error) {
	if cutoffMonth == "" {
		return nil, nil
	}
	query := fmt.Sprintf(`
		SELECT DISTINCT partition
		FROM system.parts
		WHERE database = '%s' AND table = 'syslog_events' AND active = 1 AND partition < '%s'
		ORDER BY partition ASC`, c.Database(), cutoffMonth)
	rows, err := c.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var toDrop []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err == nil && p != "" {
			toDrop = append(toDrop, p)
		}
	}

	var dropped []string
	for _, part := range toDrop {
		dropQuery := fmt.Sprintf("ALTER TABLE %s.syslog_events DROP PARTITION '%s'", c.Database(), part)
		if err := c.conn.Exec(ctx, dropQuery); err == nil {
			dropped = append(dropped, part)
			// Drop from events_1m too if partition exists
			_ = c.conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s.events_1m DROP PARTITION '%s'", c.Database(), part))
		}
	}
	return dropped, nil
}

// GetTenantStorageBreakdown returns total log count per tenant from ClickHouse
func (c *Client) GetTenantStorageBreakdown(ctx context.Context) (map[string]uint64, error) {
	query := fmt.Sprintf(`
		SELECT tenant, count(*)
		FROM %s.syslog_events
		GROUP BY tenant`, c.Database())
	rows, err := c.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[string]uint64)
	for rows.Next() {
		var t string
		var cnt uint64
		if err := rows.Scan(&t, &cnt); err == nil {
			if t == "" {
				t = "default"
			}
			res[t] = cnt
		}
	}
	return res, nil
}

// MinuteMetric represents a 1-minute aggregated metrics bucket
type MinuteMetric struct {
	Minute     time.Time `json:"minute"`
	Tenant     string    `json:"tenant"`
	DeviceID   string    `json:"device_id,omitempty"`
	DeviceName string    `json:"device_name,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	Product    string    `json:"product,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Facility   string    `json:"facility,omitempty"`
	EventCount uint64    `json:"event_count"`
	TotalBytes uint64    `json:"total_bytes"`
}

// GetTimeseries1m returns minute-by-minute aggregated event counts and byte volumes
func (c *Client) GetTimeseries1m(ctx context.Context, tenant string, from, to time.Time) ([]MinuteMetric, error) {
	whereClauses := "minute >= ? AND minute <= ?"
	args := []interface{}{from, to}

	if tenant != "" && tenant != "all" && tenant != "*" {
		whereClauses += " AND tenant = ?"
		args = append(args, tenant)
	}

	query := fmt.Sprintf(`
		SELECT
			minute,
			tenant,
			sum(event_count) AS event_count,
			sum(total_bytes) AS total_bytes
		FROM %s.events_1m
		WHERE %s
		GROUP BY minute, tenant
		ORDER BY minute ASC
	`, c.Database(), whereClauses)

	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []MinuteMetric
	for rows.Next() {
		var m MinuteMetric
		if err := rows.Scan(&m.Minute, &m.Tenant, &m.EventCount, &m.TotalBytes); err == nil {
			metrics = append(metrics, m)
		}
	}
	return metrics, nil
}

// GetAggregatedCounts1m retrieves today's count and all-time total count using events_1m summing table
func (c *Client) GetAggregatedCounts1m(ctx context.Context, tenant string, todayStart time.Time) (todayCount uint64, totalCount uint64, err error) {
	var query string
	var rows driver.Rows

	if tenant != "" && tenant != "all" && tenant != "*" {
		query = fmt.Sprintf(`
			SELECT
				sumIf(event_count, minute >= ?),
				sum(event_count)
			FROM %s.events_1m
			WHERE tenant = ?
		`, c.Database())
		rows, err = c.conn.Query(ctx, query, todayStart, tenant)
	} else {
		query = fmt.Sprintf(`
			SELECT
				sumIf(event_count, minute >= ?),
				sum(event_count)
			FROM %s.events_1m
		`, c.Database())
		rows, err = c.conn.Query(ctx, query, todayStart)
	}

	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	if rows.Next() {
		_ = rows.Scan(&todayCount, &totalCount)
	}
	return todayCount, totalCount, nil
}


