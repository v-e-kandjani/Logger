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

// Client wraps ClickHouse connection and asynchronous batch inserter
type Client struct {
	conn       driver.Conn
	cfg        config.ClickHouseConfig
	batchCh    chan *models.LogEvent
	stopCh     chan struct{}
	wg         sync.WaitGroup
	isHealthy  atomic.Bool

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
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	c := &Client{
		conn:    conn,
		cfg:     cfg,
		batchCh: make(chan *models.LogEvent, cfg.BatchSize*2),
		stopCh:  make(chan struct{}),
	}
	c.isHealthy.Store(true)

	// Start background batch writer worker
	c.wg.Add(1)
	go c.batchWorker()

	return c, nil
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
		batch = make([]*models.LogEvent, 0, c.cfg.BatchSize)
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

	batch, err := c.conn.PrepareBatch(ctx, `
		INSERT INTO syslog.syslog_events (
			internal_id, event_timestamp, received_at, source_ip, source_port,
			transport_protocol, device_id, device_name, device_group, vendor,
			product, facility_code, facility, severity_code, severity,
			hostname, application_name, process_id, message_id, structured_data,
			message, raw_message, collector_node, parser_status, ingestion_timestamp
		)
	`)
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	for _, ev := range events {
		srcIP := ev.SourceIP
		if srcIP == nil {
			srcIP = net.IPv4(0, 0, 0, 0)
		}
		// Convert to IPv4 4-byte slice if possible
		if ip4 := srcIP.To4(); ip4 != nil {
			srcIP = ip4
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
