package pipeline

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/database/clickhouse"
	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/siem/correlation"
	"github.com/syslog-platform/logger/internal/syslog/detector"
	"github.com/syslog-platform/logger/internal/syslog/parser"
)

// RawPacket represents an incoming unparsed datagram or stream frame
type RawPacket struct {
	Data       []byte
	SourceIP   net.IP
	SourcePort uint16
	Protocol   string
	ReceivedAt time.Time
}

// Pipeline orchestrates ingestion, parser workers, enrichment, ClickHouse batching, and live broadcast
type Pipeline struct {
	inQueue     chan RawPacket
	parser      *parser.UniversalSyslogParser
	chClient    *clickhouse.Client
	deviceCache *postgres.DeviceCache
	pgDB        *postgres.DB
	workers     int
	wg          sync.WaitGroup
	stopCh      chan struct{}

	// Live Stream Broadcast Subscribers
	mu          sync.RWMutex
	subscribers map[chan *models.LogEvent]struct{}

	// Metrics
	PacketsReceived     atomic.Uint64
	EventsParsed        atomic.Uint64
	ParsingErrors       atomic.Uint64
	DroppedPackets      atomic.Uint64
	DroppedUnauthorized atomic.Uint64

	// Access Control
	strictFilter atomic.Bool

	// SIEM Detection & Normalization Engine
	siemEngine *correlation.Engine
}

func NewPipeline(
	capacity int,
	workers int,
	nodeName string,
	chClient *clickhouse.Client,
	deviceCache *postgres.DeviceCache,
	pgDB *postgres.DB,
) *Pipeline {
	if capacity <= 0 {
		capacity = 250000
	}
	if workers <= 0 {
		workers = 16
	}

	return &Pipeline{
		inQueue:     make(chan RawPacket, capacity),
		parser:      parser.NewUniversalParser(nodeName),
		chClient:    chClient,
		deviceCache: deviceCache,
		pgDB:        pgDB,
		workers:     workers,
		stopCh:      make(chan struct{}),
		subscribers: make(map[chan *models.LogEvent]struct{}),
	}
}

// SetStrictFiltering enables or disables rejecting packets from unregistered IPs
func (p *Pipeline) SetStrictFiltering(enabled bool) {
	p.strictFilter.Store(enabled)
}

// IsStrictFiltering returns current authorization mode
func (p *Pipeline) IsStrictFiltering() bool {
	return p.strictFilter.Load()
}

// SetSIEMEngine connects the security correlation and detection engine
func (p *Pipeline) SetSIEMEngine(engine *correlation.Engine) {
	p.siemEngine = engine
}

// GetSIEMEngine returns the active SIEM correlation engine
func (p *Pipeline) GetSIEMEngine() *correlation.Engine {
	return p.siemEngine
}

// Ingest submits a raw packet into the non-blocking ring buffer
func (p *Pipeline) Ingest(pkt RawPacket) {
	p.PacketsReceived.Add(1)
	select {
	case p.inQueue <- pkt:
	default:
		p.DroppedPackets.Add(1)
	}
}

// Start launches worker goroutines
func (p *Pipeline) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.workerLoop()
	}
}

func (p *Pipeline) workerLoop() {
	defer p.wg.Done()

	for {
		select {
		case <-p.stopCh:
			return
		case pkt := <-p.inQueue:
			ipStr := pkt.SourceIP.String()
			dev, found := p.deviceCache.LookupIP(ipStr)

			// Strict Zero-Trust Filtering: Discard packets from unauthorized / random IP senders
			if p.strictFilter.Load() && !found {
				p.DroppedUnauthorized.Add(1)
				continue
			}

			event, err := p.parser.Parse(pkt.Data, pkt.SourceIP, pkt.SourcePort, pkt.Protocol)
			if err != nil {
				p.ParsingErrors.Add(1)
				continue
			}

			// Device Enrichment via in-memory DeviceCache
			if found {
				event.DeviceID = dev.ID
				event.DeviceName = dev.Name
				if dev.GroupName != "" {
					event.DeviceGroup = dev.GroupName
				} else if dev.DeviceType != "" {
					event.DeviceGroup = dev.DeviceType
				} else {
					event.DeviceGroup = "Registered"
				}
				if dev.Vendor != "" {
					event.Vendor = dev.Vendor
				} else if event.Vendor == "" || event.Vendor == "Generic" {
					detection := detector.Detect(event.RawMessage, event.Hostname, event.ApplicationName)
					event.Vendor = detection.Vendor
				}
				if dev.DeviceType != "" {
					event.Product = dev.DeviceType
				} else if event.Product == "" || event.Product == "Unknown" {
					detection := detector.Detect(event.RawMessage, event.Hostname, event.ApplicationName)
					event.Product = detection.DeviceType
				}
				// Asynchronously update last_seen_at in postgres
				go func(ip string) {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = p.pgDB.UpdateDeviceLastSeen(ctx, ip, time.Now())
				}(ipStr)
			} else {
				// Permissive mode: auto-discovery with deep device type & vendor fingerprinting
				event.DeviceID = uuid.Nil
				detection := detector.Detect(event.RawMessage, event.Hostname, event.ApplicationName)

				if detection.Hostname != "" {
					event.Hostname = detection.Hostname
					if event.DeviceName == "" || event.DeviceName == "UNKNOWN" {
						event.DeviceName = detection.Hostname
					}
				} else if event.DeviceName == "" {
					if event.Hostname != "" && event.Hostname != ipStr {
						event.DeviceName = event.Hostname
					} else {
						event.DeviceName = "UNKNOWN"
					}
				}

				event.DeviceGroup = "Unregistered"
				if event.Vendor == "" || event.Vendor == "Generic" {
					event.Vendor = detection.Vendor
				}
				if event.Product == "" || event.Product == "Unknown" {
					event.Product = detection.DeviceType
				}

				// Fire-and-forget record unknown sender with auto-discovered metadata
				go func(ip, host, vendor, devType, conf, sample, fac, sev string) {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = p.pgDB.RecordUnregisteredSource(ctx, &models.UnregisteredSource{
						IPAddress:        ip,
						Hostname:         host,
						DetectedVendor:   vendor,
						DetectedType:     devType,
						Confidence:       conf,
						LastSeenAt:       time.Now(),
						LastRawSample:    sample,
						DetectedFacility: fac,
						DetectedSeverity: sev,
					})
				}(ipStr, detection.Hostname, detection.Vendor, detection.DeviceType, detection.Confidence, event.RawMessage, event.Facility, event.Severity)
			}

			p.EventsParsed.Add(1)

			// 1. Deliver to ClickHouse batch engine
			if p.chClient != nil {
				p.chClient.Enqueue(event)
			}

			// 2. Broadcast to connected Live Stream clients (non-blocking)
			p.broadcast(event)

			// 3. Evaluate in SIEM correlation & normalization engine
			if p.siemEngine != nil {
				p.siemEngine.ProcessLogEvent(event)
			}
		}
	}
}

// Subscribe attaches a live log channel
func (p *Pipeline) Subscribe() chan *models.LogEvent {
	ch := make(chan *models.LogEvent, 1024)
	p.mu.Lock()
	p.subscribers[ch] = struct{}{}
	p.mu.Unlock()
	return ch
}

// Unsubscribe removes a client channel
func (p *Pipeline) Unsubscribe(ch chan *models.LogEvent) {
	p.mu.Lock()
	delete(p.subscribers, ch)
	p.mu.Unlock()
	close(ch)
}

func (p *Pipeline) broadcast(event *models.LogEvent) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for ch := range p.subscribers {
		select {
		case ch <- event:
		default:
			// Client buffer full: drop to avoid slowing down pipeline
		}
	}
}

// Stop gracefully shuts down workers
func (p *Pipeline) Stop() {
	close(p.stopCh)
	p.wg.Wait()
	log.Println("[Pipeline] Workers stopped successfully")
}

// QueueDepth returns the current backpressure depth
func (p *Pipeline) QueueDepth() int {
	return len(p.inQueue)
}
