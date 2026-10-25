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
	"github.com/syslog-platform/logger/internal/ti"
	"github.com/syslog-platform/logger/internal/ueba"
)

// RawPacket represents an incoming unparsed datagram or stream frame
type RawPacket struct {
	Data       []byte
	SourceIP   net.IP
	SourcePort uint16
	Protocol   string
	ReceivedAt time.Time
	Tenant     string // owning tenant slug when known at ingest (e.g. edge proxy node); empty = resolve from device
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
	siemQueue  chan *models.LogEvent

	// Threat Intelligence & External IOC Feeds Engine (Phase Q)
	tiEngine *ti.Engine

	// User & Entity Behavior Analytics (UEBA) Engine (Phase R)
	uebaEngine *ueba.Engine

	// Cooldown cache for rate-limiting PostgreSQL device metadata writes
	lastDeviceSeen sync.Map
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
		siemQueue:   make(chan *models.LogEvent, 65536),
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

// SetThreatIntelEngine connects the Threat Intelligence cross-matcher (Phase Q)
func (p *Pipeline) SetThreatIntelEngine(engine *ti.Engine) {
	p.tiEngine = engine
}

// GetThreatIntelEngine returns the active Threat Intelligence engine
func (p *Pipeline) GetThreatIntelEngine() *ti.Engine {
	return p.tiEngine
}

// SetUEBAEngine connects the User & Entity Behavior Analytics engine (Phase R)
func (p *Pipeline) SetUEBAEngine(engine *ueba.Engine) {
	p.uebaEngine = engine
}

// GetUEBAEngine returns the active UEBA engine
func (p *Pipeline) GetUEBAEngine() *ueba.Engine {
	return p.uebaEngine
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
	// Start decoupled SIEM background consumer
	p.wg.Add(1)
	go p.siemWorkerLoop()
}

func (p *Pipeline) siemWorkerLoop() {
	defer p.wg.Done()
	for {
		select {
		case <-p.stopCh:
			return
		case event := <-p.siemQueue:
			if p.siemEngine != nil {
				p.siemEngine.ProcessLogEvent(event)
			}
		}
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

			// Tenant-aware device lookup:
			// If pkt.Tenant is specified (e.g. from edge node), attempt tenant-scoped lookup first
			var dev *models.Device
			var found bool
			if pkt.Tenant != "" {
				dev, found = p.deviceCache.LookupIPAndTenant(ipStr, pkt.Tenant)
			} else {
				dev, found = p.deviceCache.LookupIP(ipStr)
			}

			// Determine tenant attribution
			tenant := "default"
			switch {
			case pkt.Tenant != "":
				tenant = pkt.Tenant
			case found && dev.TenantSlug != "":
				tenant = dev.TenantSlug
			}

			// Ingest Policy Enforcement (Phase 5):
			// If global strictFilter is enabled OR tenant enforces 'strict' whitelist-only
			tenantPolicy := p.deviceCache.GetTenantIngestPolicy(tenant)
			if (p.strictFilter.Load() || tenantPolicy == "strict") && !found {
				p.DroppedUnauthorized.Add(1)
				continue
			}

			event, err := p.parser.Parse(pkt.Data, pkt.SourceIP, pkt.SourcePort, pkt.Protocol)
			if err != nil {
				p.ParsingErrors.Add(1)
				continue
			}

			event.Tenant = tenant

			// Cooldown rate-limiting: only persist device metadata updates to PostgreSQL once every 30 seconds per source
			now := time.Now()
			shouldUpdateDB := false
			if last, ok := p.lastDeviceSeen.Load(ipStr); !ok || now.Sub(last.(time.Time)) > 30*time.Second {
				p.lastDeviceSeen.Store(ipStr, now)
				shouldUpdateDB = true
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
				// Asynchronously update last_seen_at in postgres (rate-limited)
				if shouldUpdateDB {
					go func(ip string) {
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						defer cancel()
						_ = p.pgDB.UpdateDeviceLastSeen(ctx, ip, time.Now())
					}(ipStr)
				}
			} else {
				// Permissive mode: auto-discovery with deep device type, vendor fingerprinting & category
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

				if detection.SuggestedGroup != "" {
					event.DeviceGroup = detection.SuggestedGroup
				} else {
					event.DeviceGroup = "Unregistered"
				}
				if event.Vendor == "" || event.Vendor == "Generic" {
					event.Vendor = detection.Vendor
				}
				if event.Product == "" || event.Product == "Unknown" {
					event.Product = detection.DeviceType
				}

				// Fire-and-forget record unknown sender with auto-discovered metadata and tenant scoping (rate-limited)
				if shouldUpdateDB {
					go func(ip, host, vendor, devType, conf, sample, fac, sev, ten string) {
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
							TenantSlug:       ten,
						})
					}(ipStr, detection.Hostname, detection.Vendor, detection.DeviceType, detection.Confidence, event.RawMessage, event.Facility, event.Severity, tenant)
				}
			}

			p.EventsParsed.Add(1)

			// 1. Deliver to ClickHouse batch engine
			if p.chClient != nil {
				p.chClient.Enqueue(event)
			}

			// 2. Broadcast to connected Live Stream clients (non-blocking)
			p.broadcast(event)

			// 3. Evaluate in SIEM correlation & normalization engine (non-blocking decoupled ring buffer)
			if p.siemEngine != nil {
				select {
				case p.siemQueue <- event:
				default:
					// Ring buffer saturated during heavy spike; avoid blocking ingestion pipeline
				}
			}

			// 4. Stream Cross-Matching in Threat Intelligence Engine (Phase Q)
			if p.tiEngine != nil {
				p.tiEngine.ProcessSyslogMatch(context.Background(), event.Tenant, event.SourceIP.String(), "", event.Hostname, event.DeviceName, event.RawMessage)
			}

			// 5. Evaluate User & Entity Behavior Analytics (Phase R)
			if p.uebaEngine != nil {
				u := event.Facility
				if event.ApplicationName != "" && event.ApplicationName != "-" {
					u = event.ApplicationName
				}
				p.uebaEngine.ProcessEvent(context.Background(), event.Tenant, u, event.SourceIP.String(), event.DeviceName, event.ApplicationName, event.RawMessage, event.EventTimestamp)
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
