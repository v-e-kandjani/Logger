package archive

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/database/clickhouse"
	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/timestamp"
)

type Engine struct {
	baseDir  string
	chClient *clickhouse.Client
	pgDB     *postgres.DB
	provider timestamp.TimestampProvider
}

func NewEngine(baseDir string, chClient *clickhouse.Client, pgDB *postgres.DB, provider timestamp.TimestampProvider) *Engine {
	return &Engine{
		baseDir:  baseDir,
		chClient: chClient,
		pgDB:     pgDB,
		provider: provider,
	}
}

// BaseDir returns the root archive directory
func (e *Engine) BaseDir() string {
	return e.baseDir
}

// StartAutoArchiving starts background worker that triggers periodic hourly archiving and timestamping
func (e *Engine) StartAutoArchiving(ctx context.Context, interval string, scheduleMinute int) {
	if scheduleMinute < 0 || scheduleMinute > 59 {
		scheduleMinute = 5
	}
	go func() {
		log.Printf("[Archive Engine] Periodic auto-archiving scheduler started (interval: %s, schedule_minute: %d)", interval, scheduleMinute)
		
		// Immediate initial auto-sealing sweep on startup to clear any existing backlog
		go func() {
			time.Sleep(2 * time.Second)
			sweepCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer sCancel()
			reconciled := e.ReconcilePendingArchives(sweepCtx)
			if reconciled > 0 {
				log.Printf("[Archive Engine] Initial startup auto-seal sweep processed %d pending archives", reconciled)
			}
		}()

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		var lastArchivedHour time.Time

		for {
			select {
			case <-ctx.Done():
				log.Println("[Archive Engine] Periodic auto-archiving scheduler stopped")
				return
			case now := <-ticker.C:
				utcNow := now.UTC()
				if utcNow.Minute() == scheduleMinute {
					currentHour := utcNow.Truncate(time.Hour)
					prevHour := currentHour.Add(-1 * time.Hour)

					if !prevHour.Equal(lastArchivedHour) {
						lastArchivedHour = prevHour
						sliceStart := prevHour
						sliceEnd := currentHour

						log.Printf("[Archive Engine] Triggering scheduled archive for slice: %s to %s",
							sliceStart.Format("2006-01-02 15:04:05"), sliceEnd.Format("15:04:05"))

						sliceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
						
						// Query all distinct tenants that logged within this hour
						tenants := []string{"default"}
						tQuery := fmt.Sprintf("SELECT DISTINCT tenant FROM %s.syslog_events WHERE event_timestamp >= ? AND event_timestamp < ?", e.chClient.Database())
						if tRows, err := e.chClient.QueryEvents(sliceCtx, tQuery, sliceStart, sliceEnd); err == nil && tRows != nil {
							var found []string
							for tRows.Next() {
								var t string
								if err := tRows.Scan(&t); err == nil && t != "" {
									found = append(found, t)
								}
							}
							tRows.Close()
							if len(found) > 0 {
								tenants = found
							}
						}

						for _, t := range tenants {
							arch, err := e.CreateArchiveSliceForTenant(sliceCtx, t, sliceStart, sliceEnd)
							if err != nil {
								log.Printf("[Archive Engine] Auto-archive error for tenant %s slice %s: %v", t, sliceStart.Format(time.RFC3339), err)
							} else {
								log.Printf("[Archive Engine] Auto-archive completed for tenant %s: %s (Logs: %d, SHA-256: %s, Status: %s)",
									t, arch.ArchiveName, arch.RecordCount, arch.HashValue, arch.TimestampStatus)
							}
						}
						cancel()
					}
				}

				// Continuous background auto-sealer for pending archives based on seal settings
				reconcileCtx, rCancel := context.WithTimeout(context.Background(), 30*time.Second)
				_ = e.ReconcilePendingArchives(reconcileCtx)
				rCancel()
			}
		}
	}()
}

// ReconcilePendingArchives scans PostgreSQL for any archives stuck in PENDING, TSA_PENDING,
// TIMESTAMP_FAILED or retryable FAILED status and auto-seals them using the active timestamp provider.
func (e *Engine) ReconcilePendingArchives(ctx context.Context) int {
	if e.provider == nil || e.pgDB == nil {
		return 0
	}

	// Check if auto-seal has been explicitly turned off in system settings
	settings, err := e.pgDB.GetSettings(ctx)
	if err == nil && settings != nil {
		if val, ok := settings["auto_seal_pending"]; ok && (val == "false" || val == "0") {
			return 0
		}
	}

	pendingList, err := e.pgDB.ListPendingArchives(ctx, 50)
	if err != nil || len(pendingList) == 0 {
		return 0
	}
	reconciled := 0
	for _, a := range pendingList {
		archivePath := a.ArchivePath
		if archivePath == "" {
			archivePath = filepath.Join(e.baseDir, a.ArchiveName+".jsonl.gz")
		}
		if _, err := os.Stat(archivePath); err != nil {
			// Fallback check 1: BaseDir root
			fallbackPath := filepath.Join(e.baseDir, filepath.Base(archivePath))
			if _, fbErr := os.Stat(fallbackPath); fbErr == nil {
				archivePath = fallbackPath
			} else {
				// Fallback check 2: Date-based path /archive/YYYY/MM/DD/
				dateDir := filepath.Join(
					e.baseDir,
					fmt.Sprintf("%04d", a.StartTimestamp.Year()),
					fmt.Sprintf("%02d", a.StartTimestamp.Month()),
					fmt.Sprintf("%02d", a.StartTimestamp.Day()),
				)
				dateFallback := filepath.Join(dateDir, filepath.Base(archivePath))
				if _, dfErr := os.Stat(dateFallback); dfErr == nil {
					archivePath = dateFallback
				} else {
					log.Printf("[Archive Engine] Pending archive %s file not found at %s or fallback paths: %v", a.ID, a.ArchivePath, err)
					continue
				}
			}
		}

		res, err := e.provider.Timestamp(ctx, archivePath)
		if err != nil {
			log.Printf("[Archive Engine] Auto-seal error for archive %s (%s): %v", a.ID, a.ArchiveName, err)
			_ = e.pgDB.UpdateArchiveTimestamp(ctx, a.ID, "FAILED", "", err.Error())
		} else {
			status := "STAMPED"
			if res.EvidenceFile == "" {
				status = "ARCHIVED_NO_STAMP"
			}
			_ = e.pgDB.UpdateArchiveTimestamp(ctx, a.ID, status, res.EvidenceFile, "")
			_ = e.pgDB.SyncArchiveJobCommitted(ctx, a.Tenant, a.StartTimestamp, a.EndTimestamp)
			reconciled++
			log.Printf("[Archive Engine] Auto-sealed pending archive %s (%s) -> %s (evidence: %s)", a.ID, a.ArchiveName, status, res.EvidenceFile)
		}
	}
	return reconciled
}

// ReconcileArchiveByID stamps a single archive on-demand given its UUID.
func (e *Engine) ReconcileArchiveByID(ctx context.Context, id uuid.UUID) (*models.LogArchive, error) {
	if e.provider == nil || e.pgDB == nil {
		return nil, fmt.Errorf("archive engine or database not initialized")
	}
	arch, err := e.pgDB.GetArchive(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("archive not found: %w", err)
	}
	archivePath := arch.ArchivePath
	if archivePath == "" {
		return nil, fmt.Errorf("archive path is empty in database for %s", id)
	}
	if _, err := os.Stat(archivePath); err != nil {
		// Fallback check in baseDir
		fallbackPath := filepath.Join(e.baseDir, filepath.Base(archivePath))
		if _, fbErr := os.Stat(fallbackPath); fbErr == nil {
			archivePath = fallbackPath
		} else {
			return nil, fmt.Errorf("archive file not found on disk at %s: %w", arch.ArchivePath, err)
		}
	}

	res, err := e.provider.Timestamp(ctx, archivePath)
	if err != nil {
		_ = e.pgDB.UpdateArchiveTimestamp(ctx, arch.ID, "FAILED", "", err.Error())
		return nil, fmt.Errorf("timestamp provider error: %w", err)
	}
	status := "STAMPED"
	if res.EvidenceFile == "" {
		status = "ARCHIVED_NO_STAMP"
	}
	_ = e.pgDB.UpdateArchiveTimestamp(ctx, arch.ID, status, res.EvidenceFile, "")
	arch.TimestampStatus = status
	arch.TimestampEvidencePath = res.EvidenceFile
	log.Printf("[Archive Engine] Reconciled individual archive %s (%s) -> %s", arch.ID, arch.ArchiveName, status)
	return arch, nil
}

// CreateArchiveSlice queries an immutable time slice for default tenant
func (e *Engine) CreateArchiveSlice(ctx context.Context, start, end time.Time) (*models.LogArchive, error) {
	return e.CreateArchiveSliceForTenant(ctx, "default", start, end)
}

// CreateArchiveSliceForTenant queries an immutable time slice for a specific tenant, writes deterministic JSONL.GZ, computes SHA-256, and submits to KamuSM
func (e *Engine) CreateArchiveSliceForTenant(ctx context.Context, tenant string, start, end time.Time) (*models.LogArchive, error) {
	if tenant == "" {
		tenant = "default"
	}

	// Construct directory: /archive/YYYY/MM/DD/
	dirPath := filepath.Join(
		e.baseDir,
		fmt.Sprintf("%04d", start.Year()),
		fmt.Sprintf("%02d", start.Month()),
		fmt.Sprintf("%02d", start.Day()),
	)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return nil, fmt.Errorf("creating archive directory: %w", err)
	}

	var archiveBaseName string
	if tenant == "default" {
		archiveBaseName = fmt.Sprintf("logs-%s-%s", start.Format("20060102-150405"), end.Format("150405"))
	} else {
		archiveBaseName = fmt.Sprintf("logs-%s-%s-%s", tenant, start.Format("20060102-150405"), end.Format("150405"))
	}
	archiveFilePath := filepath.Join(dirPath, archiveBaseName+".jsonl.gz")

	// Query ClickHouse for records strictly inside bounds, filtered by tenant
	var query string
	var rows driver.Rows
	var err error

	if tenant != "" && tenant != "all" && tenant != "*" {
		query = fmt.Sprintf(`
			SELECT internal_id, event_timestamp, received_at, source_ip, source_port,
			       transport_protocol, device_id, device_name, device_group, vendor,
			       product, facility_code, facility, severity_code, severity,
			       hostname, application_name, process_id, message_id, structured_data,
			       message, raw_message, collector_node, parser_status, ingestion_timestamp
			FROM %s.syslog_events
			WHERE event_timestamp >= ? AND event_timestamp < ? AND tenant = ?
			ORDER BY event_timestamp ASC, internal_id ASC`, e.chClient.Database())
		rows, err = e.chClient.QueryEvents(ctx, query, start, end, tenant)
	} else {
		query = fmt.Sprintf(`
			SELECT internal_id, event_timestamp, received_at, source_ip, source_port,
			       transport_protocol, device_id, device_name, device_group, vendor,
			       product, facility_code, facility, severity_code, severity,
			       hostname, application_name, process_id, message_id, structured_data,
			       message, raw_message, collector_node, parser_status, ingestion_timestamp
			FROM %s.syslog_events
			WHERE event_timestamp >= ? AND event_timestamp < ?
			ORDER BY event_timestamp ASC, internal_id ASC`, e.chClient.Database())
		rows, err = e.chClient.QueryEvents(ctx, query, start, end)
	}
	if err != nil {
		return nil, fmt.Errorf("querying clickhouse for archive slice: %w", err)
	}
	defer rows.Close()

	outFile, err := os.Create(archiveFilePath)
	if err != nil {
		return nil, fmt.Errorf("creating archive file: %w", err)
	}
	defer outFile.Close()

	// Deterministic Gzip compression (DefaultCompression provides fast compression without high CPU overhead)
	gw, err := gzip.NewWriterLevel(outFile, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}
	gw.Header.Name = archiveBaseName + ".jsonl"
	gw.Header.ModTime = end // Fixed deterministic modtime

	var recordCount int64
	for rows.Next() {
		var ev models.LogEvent
		if err := rows.Scan(
			&ev.InternalID, &ev.EventTimestamp, &ev.ReceivedAt, &ev.SourceIP, &ev.SourcePort,
			&ev.TransportProtocol, &ev.DeviceID, &ev.DeviceName, &ev.DeviceGroup, &ev.Vendor,
			&ev.Product, &ev.FacilityCode, &ev.Facility, &ev.SeverityCode, &ev.Severity,
			&ev.Hostname, &ev.ApplicationName, &ev.ProcessID, &ev.MessageID, &ev.StructuredData,
			&ev.Message, &ev.RawMessage, &ev.CollectorNode, &ev.ParserStatus, &ev.IngestionTimestamp,
		); err != nil {
			gw.Close()
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		line, err := json.Marshal(ev)
		if err != nil {
			gw.Close()
			return nil, err
		}
		if _, err := gw.Write(append(line, '\n')); err != nil {
			gw.Close()
			return nil, err
		}
		recordCount++
	}

	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip: %w", err)
	}

	// Compute Cryptographic SHA-256
	hashVal, err := timestamp.ComputeSHA256(archiveFilePath)
	if err != nil {
		return nil, fmt.Errorf("computing sha256: %w", err)
	}

	// Write hash file alongside archive
	hashFilePath := filepath.Join(dirPath, archiveBaseName+".sha256")
	_ = os.WriteFile(hashFilePath, []byte(hashVal+"  "+archiveBaseName+".jsonl.gz\n"), 0644)

	fi, _ := outFile.Stat()
	archiveSize := fi.Size()

	archiveRecord := &models.LogArchive{
		ArchiveName:     archiveBaseName,
		StartTimestamp:  start,
		EndTimestamp:    end,
		RecordCount:     recordCount,
		ArchivePath:     archiveFilePath,
		ArchiveSize:     archiveSize,
		HashAlgorithm:   "SHA-256",
		HashValue:       hashVal,
		TimestampStatus: "PENDING",
		Tenant:          tenant,
	}

	// Record in PostgreSQL catalog
	if err := e.pgDB.CreateArchiveRecord(ctx, archiveRecord); err != nil {
		return nil, fmt.Errorf("recording archive in postgres: %w", err)
	}

	// Submit to Timestamp Provider (KamuSM, Internal, or Mock)
	if e.provider != nil {
		go func(recID uuid.UUID, path string) {
			tsCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			res, err := e.provider.Timestamp(tsCtx, path)
			if err != nil {
				log.Printf("[Archive Engine] Timestamping error for %s: %v", recID, err)
				if upErr := e.pgDB.UpdateArchiveTimestamp(context.Background(), recID, "FAILED", "", err.Error()); upErr != nil {
					log.Printf("[Archive Engine] Failed updating archive %s to FAILED: %v", recID, upErr)
				}
			} else {
				status := "STAMPED"
				if res.EvidenceFile == "" {
					status = "ARCHIVED_NO_STAMP"
				}
				log.Printf("[Archive Engine] Archive %s stamped successfully: status=%s, evidence=%s", recID, status, res.EvidenceFile)
				if upErr := e.pgDB.UpdateArchiveTimestamp(context.Background(), recID, status, res.EvidenceFile, ""); upErr != nil {
					log.Printf("[Archive Engine] Failed updating archive %s to %s: %v", recID, status, upErr)
				}
			}
		}(archiveRecord.ID, archiveFilePath)
	}

	return archiveRecord, nil
}

// CustomRangeOptions configures a custom-range log export or compliance archive
type CustomRangeOptions struct {
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	TimeField string    `json:"time_field"` // "event_timestamp" (device log time) or "received_at" (collector reception time)
	Format    string    `json:"format"`     // "bundle" (zip with jsonl.gz + zd + sha256), "archive" (jsonl.gz), "csv"
	Seal      bool      `json:"seal"`       // whether to apply cryptographic timestamp seal (.zd)
	Register  bool      `json:"register"`   // whether to save in the system archives catalog
	Tenant    string    `json:"tenant"`     // multi-tenant isolation scope
}

// CustomArchiveResult holds the paths and metadata for the generated export
type CustomArchiveResult struct {
	ArchiveName     string             `json:"archive_name"`
	FilePath        string             `json:"file_path"`
	Format          string             `json:"format"`
	TimeField       string             `json:"time_field"`
	Start           time.Time          `json:"start"`
	End             time.Time          `json:"end"`
	RecordCount     int64              `json:"record_count"`
	ArchiveSize     int64              `json:"archive_size"`
	HashSHA256      string             `json:"hash_sha256"`
	EvidencePath    string             `json:"evidence_path,omitempty"`
	BundlePath      string             `json:"bundle_path,omitempty"`
	TimestampStatus string             `json:"timestamp_status"`
	ArchiveRecord   *models.LogArchive `json:"archive_record,omitempty"`
}

// ExportProgressCallback defines progress and log feedback during export operations
type ExportProgressCallback func(stage string, percent int, logMsg string, currentCount int64, totalCount int64)

// CreateCustomRangeArchive queries logs in an arbitrary period using either event_timestamp or received_at,
// generates the requested format (.jsonl.gz, .csv, or .zip compliance bundle), and applies a cryptographic seal if requested.
func (e *Engine) CreateCustomRangeArchive(ctx context.Context, opts CustomRangeOptions) (*CustomArchiveResult, error) {
	return e.CreateCustomRangeArchiveWithProgress(ctx, opts, nil)
}

// CreateCustomRangeArchiveWithProgress performs custom range export while reporting granular stage and console telemetry
func (e *Engine) CreateCustomRangeArchiveWithProgress(ctx context.Context, opts CustomRangeOptions, progressFn ExportProgressCallback) (*CustomArchiveResult, error) {
	notify := func(stage string, percent int, msg string, cur, tot int64) {
		if progressFn != nil {
			progressFn(stage, percent, msg, cur, tot)
		}
	}

	if opts.End.Before(opts.Start) {
		err := fmt.Errorf("end time (%s) must be after start time (%s)", opts.End.Format(time.RFC3339), opts.Start.Format(time.RFC3339))
		notify("FAILED", 0, "HATA: "+err.Error(), 0, 0)
		return nil, err
	}

	timeCol := "event_timestamp"
	fieldLabel := "Olay Zamanı (event_timestamp - Cihaz Kayıt Saati)"
	if opts.TimeField == "received_at" {
		timeCol = "received_at"
		fieldLabel = "Kayıt / Alınma Zamanı (received_at - Sunucu Geliş Saati)"
	} else {
		opts.TimeField = "event_timestamp"
	}

	if opts.Format == "" {
		opts.Format = "bundle"
	}

	notify("INITIALIZING", 5, "Dışa aktarma parametreleri ve hedef dizin hazırlanıyor...", 0, 0)

	dirPath := filepath.Join(
		e.baseDir,
		"exports",
		fmt.Sprintf("%04d", opts.Start.Year()),
		fmt.Sprintf("%02d", opts.Start.Month()),
		fmt.Sprintf("%02d", opts.Start.Day()),
	)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		notify("FAILED", 0, "Dizin oluşturulamadı: "+err.Error(), 0, 0)
		return nil, fmt.Errorf("creating export directory: %w", err)
	}

	prefix := "logseal"
	if opts.TimeField == "received_at" {
		prefix = "logseal-rx"
	}

	tenantScope := strings.TrimSpace(opts.Tenant)
	if tenantScope == "all" || tenantScope == "*" {
		tenantScope = ""
	}

	var baseName string
	if tenantScope != "" && tenantScope != "default" {
		baseName = fmt.Sprintf("%s-%s-%s-%s", prefix, tenantScope, opts.Start.Format("20060102-150405"), opts.End.Format("20060102-150405"))
	} else {
		baseName = fmt.Sprintf("%s-%s-%s", prefix, opts.Start.Format("20060102-150405"), opts.End.Format("20060102-150405"))
	}

	// Pre-count total matching events for progress percentage calculation
	var estimatedCount uint64
	var countQuery string
	var countRows driver.Rows
	var err error
	if tenantScope != "" {
		countQuery = fmt.Sprintf("SELECT count() FROM %s.syslog_events WHERE %s >= ? AND %s <= ? AND tenant = ?", e.chClient.Database(), timeCol, timeCol)
		countRows, err = e.chClient.QueryEvents(ctx, countQuery, opts.Start, opts.End, tenantScope)
	} else {
		countQuery = fmt.Sprintf("SELECT count() FROM %s.syslog_events WHERE %s >= ? AND %s <= ?", e.chClient.Database(), timeCol, timeCol)
		countRows, err = e.chClient.QueryEvents(ctx, countQuery, opts.Start, opts.End)
	}

	notify("QUERYING", 8, fmt.Sprintf("ClickHouse veritabanı taranıyor (%s - %s, referans: %s)...", opts.Start.Format("2006-01-02 15:04:05"), opts.End.Format("2006-01-02 15:04:05"), opts.TimeField), 0, 0)

	if err == nil && countRows != nil {
		if countRows.Next() {
			_ = countRows.Scan(&estimatedCount)
		}
		countRows.Close()
	}

	if estimatedCount == 0 {
		notify("QUERYING", 12, "Seçilen tarih aralığında log kaydı bulunamadı (0 kayıt). Boş arşiv dosyası oluşturulacak.", 0, 0)
	} else {
		notify("EXTRACTING", 15, fmt.Sprintf("ClickHouse üzerinde toplam %d adet log kaydı bulundu. Veri akışı ve sıkıştırma başlatılıyor...", estimatedCount), 0, int64(estimatedCount))
	}

	var query string
	var rows driver.Rows
	if tenantScope != "" {
		query = fmt.Sprintf(`
			SELECT internal_id, event_timestamp, received_at, source_ip, source_port,
			       transport_protocol, device_id, device_name, device_group, vendor,
			       product, facility_code, facility, severity_code, severity,
			       hostname, application_name, process_id, message_id, structured_data,
			       message, raw_message, collector_node, parser_status, ingestion_timestamp
			FROM %s.syslog_events
			WHERE %s >= ? AND %s <= ? AND tenant = ?
			ORDER BY %s ASC, internal_id ASC`, e.chClient.Database(), timeCol, timeCol, timeCol)
		rows, err = e.chClient.QueryEvents(ctx, query, opts.Start, opts.End, tenantScope)
	} else {
		query = fmt.Sprintf(`
			SELECT internal_id, event_timestamp, received_at, source_ip, source_port,
			       transport_protocol, device_id, device_name, device_group, vendor,
			       product, facility_code, facility, severity_code, severity,
			       hostname, application_name, process_id, message_id, structured_data,
			       message, raw_message, collector_node, parser_status, ingestion_timestamp
			FROM %s.syslog_events
			WHERE %s >= ? AND %s <= ?
			ORDER BY %s ASC, internal_id ASC`, e.chClient.Database(), timeCol, timeCol, timeCol)
		rows, err = e.chClient.QueryEvents(ctx, query, opts.Start, opts.End)
	}
	if err != nil {
		notify("FAILED", 0, "ClickHouse sorgu hatası: "+err.Error(), 0, int64(estimatedCount))
		return nil, fmt.Errorf("querying clickhouse for custom range: %w", err)
	}
	defer rows.Close()

	var recordCount int64
	var targetDataFilePath string
	lastNotifyTime := time.Now()

	if opts.Format == "csv" {
		targetDataFilePath = filepath.Join(dirPath, baseName+".csv")
		f, err := os.Create(targetDataFilePath)
		if err != nil {
			notify("FAILED", 0, "CSV dosyası oluşturulamadı: "+err.Error(), 0, int64(estimatedCount))
			return nil, fmt.Errorf("creating csv file: %w", err)
		}
		cw := csv.NewWriter(f)
		_ = cw.Write([]string{
			"EventTimestamp", "ReceivedAt", "SourceIP", "SourcePort", "Protocol",
			"DeviceName", "Vendor", "Facility", "Severity", "Hostname",
			"AppName", "ProcessID", "Message",
		})

		for rows.Next() {
			var ev models.LogEvent
			if err := rows.Scan(
				&ev.InternalID, &ev.EventTimestamp, &ev.ReceivedAt, &ev.SourceIP, &ev.SourcePort,
				&ev.TransportProtocol, &ev.DeviceID, &ev.DeviceName, &ev.DeviceGroup, &ev.Vendor,
				&ev.Product, &ev.FacilityCode, &ev.Facility, &ev.SeverityCode, &ev.Severity,
				&ev.Hostname, &ev.ApplicationName, &ev.ProcessID, &ev.MessageID, &ev.StructuredData,
				&ev.Message, &ev.RawMessage, &ev.CollectorNode, &ev.ParserStatus, &ev.IngestionTimestamp,
			); err != nil {
				cw.Flush()
				f.Close()
				notify("FAILED", 0, "Log satırı okunamadı: "+err.Error(), recordCount, int64(estimatedCount))
				return nil, fmt.Errorf("scanning csv row: %w", err)
			}

			srcIP := ""
			if ev.SourceIP != nil {
				srcIP = ev.SourceIP.String()
			}
			_ = cw.Write([]string{
				ev.EventTimestamp.Format(time.RFC3339),
				ev.ReceivedAt.Format(time.RFC3339),
				srcIP,
				fmt.Sprintf("%d", ev.SourcePort),
				ev.TransportProtocol,
				ev.DeviceName,
				ev.Vendor,
				ev.Facility,
				ev.Severity,
				ev.Hostname,
				ev.ApplicationName,
				ev.ProcessID,
				ev.Message,
			})
			recordCount++

			if recordCount%1000 == 0 || time.Since(lastNotifyTime) > 800*time.Millisecond {
				pct := 15
				if estimatedCount > 0 {
					pct = 15 + int((float64(recordCount)/float64(estimatedCount))*55.0)
					if pct > 70 {
						pct = 70
					}
				}
				notify("STREAMING", pct, fmt.Sprintf("CSV tablosuna yazılıyor: %d / %d kayıt (%%%d)", recordCount, estimatedCount, pct), recordCount, int64(estimatedCount))
				lastNotifyTime = time.Now()
			}
		}
		cw.Flush()
		f.Close()
	} else {
		// Default to JSONL.GZ (for both "archive" and "bundle" formats)
		targetDataFilePath = filepath.Join(dirPath, baseName+".jsonl.gz")
		outFile, err := os.Create(targetDataFilePath)
		if err != nil {
			notify("FAILED", 0, "Arşiv dosyası oluşturulamadı: "+err.Error(), 0, int64(estimatedCount))
			return nil, fmt.Errorf("creating archive file: %w", err)
		}

		gw, err := gzip.NewWriterLevel(outFile, gzip.DefaultCompression)
		if err != nil {
			outFile.Close()
			notify("FAILED", 0, "Gzip başlatılamadı: "+err.Error(), 0, int64(estimatedCount))
			return nil, err
		}
		gw.Header.Name = baseName + ".jsonl"
		gw.Header.ModTime = opts.End

		for rows.Next() {
			var ev models.LogEvent
			if err := rows.Scan(
				&ev.InternalID, &ev.EventTimestamp, &ev.ReceivedAt, &ev.SourceIP, &ev.SourcePort,
				&ev.TransportProtocol, &ev.DeviceID, &ev.DeviceName, &ev.DeviceGroup, &ev.Vendor,
				&ev.Product, &ev.FacilityCode, &ev.Facility, &ev.SeverityCode, &ev.Severity,
				&ev.Hostname, &ev.ApplicationName, &ev.ProcessID, &ev.MessageID, &ev.StructuredData,
				&ev.Message, &ev.RawMessage, &ev.CollectorNode, &ev.ParserStatus, &ev.IngestionTimestamp,
			); err != nil {
				gw.Close()
				outFile.Close()
				notify("FAILED", 0, "Log satırı okunamadı: "+err.Error(), recordCount, int64(estimatedCount))
				return nil, fmt.Errorf("scanning row: %w", err)
			}

			line, err := json.Marshal(ev)
			if err != nil {
				gw.Close()
				outFile.Close()
				notify("FAILED", 0, "JSON serileştirme hatası: "+err.Error(), recordCount, int64(estimatedCount))
				return nil, err
			}
			if _, err := gw.Write(append(line, '\n')); err != nil {
				gw.Close()
				outFile.Close()
				notify("FAILED", 0, "Gzip yazma hatası: "+err.Error(), recordCount, int64(estimatedCount))
				return nil, err
			}
			recordCount++

			if recordCount%1000 == 0 || time.Since(lastNotifyTime) > 800*time.Millisecond {
				pct := 15
				if estimatedCount > 0 {
					pct = 15 + int((float64(recordCount)/float64(estimatedCount))*55.0)
					if pct > 70 {
						pct = 70
					}
				}
				notify("STREAMING", pct, fmt.Sprintf("Log kayıtları sıkıştırılıyor: %d / %d kayıt (%%%d)", recordCount, estimatedCount, pct), recordCount, int64(estimatedCount))
				lastNotifyTime = time.Now()
			}
		}
		gw.Close()
		outFile.Close()
	}

	notify("STREAMING", 72, fmt.Sprintf("Tüm log kayıtları yazıldı ve sıkıştırıldı (Toplam: %d kayıt).", recordCount), recordCount, int64(estimatedCount))

	// Compute Cryptographic SHA-256 for the data file
	notify("HASHING", 75, fmt.Sprintf("FIPS 180-4 SHA-256 kriptografik özeti hesaplanıyor (%s)...", filepath.Base(targetDataFilePath)), recordCount, int64(estimatedCount))
	hashVal, err := timestamp.ComputeSHA256(targetDataFilePath)
	if err != nil {
		notify("FAILED", 75, "SHA-256 hesaplama hatası: "+err.Error(), recordCount, int64(estimatedCount))
		return nil, fmt.Errorf("computing sha256: %w", err)
	}

	hashFilePath := filepath.Join(dirPath, baseName+".sha256")
	_ = os.WriteFile(hashFilePath, []byte(hashVal+"  "+filepath.Base(targetDataFilePath)+"\n"), 0644)

	fi, _ := os.Stat(targetDataFilePath)
	archiveSize := fi.Size()
	notify("HASHING", 82, fmt.Sprintf("SHA-256 özeti oluşturuldu: %s (Boyut: %d bayt)", hashVal, archiveSize), recordCount, int64(estimatedCount))

	tsStatus := "ARCHIVED_NO_STAMP"
	evidencePath := ""

	// Perform Cryptographic Sealing if requested or if bundle format
	if (opts.Seal || opts.Format == "bundle") && e.provider != nil {
		notify("STAMPING", 85, "Kriptografik Zaman Damgası servisine bağlanılıyor (KamuSM / Entegre TSA)...", recordCount, int64(estimatedCount))
		tsCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		res, err := e.provider.Timestamp(tsCtx, targetDataFilePath)
		cancel()
		if err != nil {
			log.Printf("[Custom Export] Timestamp warning for %s: %v", targetDataFilePath, err)
			tsStatus = "TIMESTAMP_FAILED"
			notify("STAMPING", 88, fmt.Sprintf("Zaman damgası uyarısı: %v (arşiv damgasız mühürlendi)", err), recordCount, int64(estimatedCount))
		} else {
			if res.EvidenceFile != "" {
				tsStatus = "STAMPED"
				evidencePath = res.EvidenceFile
				notify("STAMPING", 90, fmt.Sprintf("Zaman damgası mühürleme başarılı! .zd kanıtı oluşturuldu (%s)", filepath.Base(evidencePath)), recordCount, int64(estimatedCount))
			} else {
				tsStatus = "ARCHIVED_NO_STAMP"
				notify("STAMPING", 90, "Zaman damgası sağlayıcısı kanıt üretmedi.", recordCount, int64(estimatedCount))
			}
		}
	}

	result := &CustomArchiveResult{
		ArchiveName:     baseName,
		FilePath:        targetDataFilePath,
		Format:          opts.Format,
		TimeField:       opts.TimeField,
		Start:           opts.Start,
		End:             opts.End,
		RecordCount:     recordCount,
		ArchiveSize:     archiveSize,
		HashSHA256:      hashVal,
		EvidencePath:    evidencePath,
		TimestampStatus: tsStatus,
	}

	// If format is bundle, wrap everything into a compliance .zip
	if opts.Format == "bundle" {
		notify("PACKAGING", 92, "5651 Sayılı Kanun Uyumlu ZIP paketi ve adli sertifika (Valtrivo LogSeal) derleniyor...", recordCount, int64(estimatedCount))
		zipPath := filepath.Join(dirPath, baseName+"-compliance-bundle.zip")
		zf, err := os.Create(zipPath)
		if err != nil {
			notify("FAILED", 92, "ZIP paketi oluşturulamadı: "+err.Error(), recordCount, int64(estimatedCount))
			return nil, fmt.Errorf("creating compliance zip: %w", err)
		}
		zw := zip.NewWriter(zf)

		// 1. Data file
		if dataBytes, err := os.ReadFile(targetDataFilePath); err == nil {
			if w, err := zw.Create(filepath.Base(targetDataFilePath)); err == nil {
				_, _ = w.Write(dataBytes)
			}
		}

		// 2. Hash file
		if hashBytes, err := os.ReadFile(hashFilePath); err == nil {
			if w, err := zw.Create(baseName + ".sha256"); err == nil {
				_, _ = w.Write(hashBytes)
			}
		}

		// 3. Evidence file (.zd)
		if evidencePath != "" {
			if zdBytes, err := os.ReadFile(evidencePath); err == nil {
				if w, err := zw.Create(filepath.Base(evidencePath)); err == nil {
					_, _ = w.Write(zdBytes)
				}
			}
		}

		// 4. Compliance Certificate
		certContent := fmt.Sprintf(`================================================================================
                    VALTRIVO LOGSEAL COMPLIANCE CERTIFICATE
       Merkezi Log Yönetimi ve 5651 Sayılı Kanun Uyumlu Zaman Damgalama
                     Tagline: "Her kayıt, zamanıyla kanıt."
================================================================================

Paket Dosyası          : %s
Zaman Referans Esası   : %s
Aralık Başlangıç (UTC) : %s
Aralık Bitiş (UTC)     : %s
Toplam Kayıt Adedi     : %d
Veri Dosyası Boyutu    : %d bayt

KRİPTOGRAFİK BÜTÜNLÜK BİLGİLERİ:
- Özetleme Algoritması : SHA-256 (FIPS 180-4 / RFC 3161)
- Veri Dosyası SHA-256 : %s
- Zaman Damgası Durumu : %s
- Zaman Damgası Kanıtı : %s
- Üretilme Tarihi (UTC): %s

YASAL VE ADLİ DELİL NİTELİĞİ:
Bu paket, Valtrivo LogSeal tarafından 5651 Sayılı Kanun ve ilgili mevzuat uyarınca
oluşturulmuştur. Log verisi hash değeri ve zaman damgası kanıt dosyası (.zd) ile
birlikte adli makamlar, mahkemeler ve denetim organları nezdinde delil niteliği taşır.
Doğrulama için TÜBİTAK KamuSM doğrulayıcı veya LogSeal dahili doğrulayıcısı kullanılabilir.

================================================================================
(C) Valtrivo Inc. Tüm hakları saklıdır.
`,
			baseName+"-compliance-bundle.zip",
			fieldLabel,
			opts.Start.Format(time.RFC3339),
			opts.End.Format(time.RFC3339),
			recordCount,
			archiveSize,
			hashVal,
			tsStatus,
			filepath.Base(evidencePath),
			time.Now().UTC().Format(time.RFC3339),
		)

		if w, err := zw.Create("VALTRIVO_LOGSEAL_COMPLIANCE_CERTIFICATE.txt"); err == nil {
			_, _ = w.Write([]byte(certContent))
		}

		zw.Close()
		zf.Close()

		zipFi, _ := os.Stat(zipPath)
		result.BundlePath = zipPath
		result.FilePath = zipPath
		result.ArchiveSize = zipFi.Size()
		notify("PACKAGING", 96, fmt.Sprintf("5651 Uyum paketi oluşturuldu: %s (%d bayt)", filepath.Base(zipPath), zipFi.Size()), recordCount, int64(estimatedCount))
	}

	// Register in PostgreSQL catalog if requested
	if opts.Register {
		notify("REGISTERING", 97, "Arşiv kaydı PostgreSQL sistem kataloğuna tescil ediliyor...", recordCount, int64(estimatedCount))
		regTenant := opts.Tenant
		if regTenant == "" || regTenant == "all" || regTenant == "*" {
			regTenant = "default"
		}
		rec := &models.LogArchive{
			ArchiveName:           baseName,
			StartTimestamp:        opts.Start,
			EndTimestamp:          opts.End,
			RecordCount:           recordCount,
			ArchivePath:           targetDataFilePath,
			ArchiveSize:           archiveSize,
			HashAlgorithm:         "SHA-256",
			HashValue:             hashVal,
			TimestampStatus:       tsStatus,
			TimestampEvidencePath: evidencePath,
			Tenant:                regTenant,
		}
		if err := e.pgDB.CreateArchiveRecord(ctx, rec); err == nil {
			result.ArchiveRecord = rec
			notify("REGISTERING", 99, "PostgreSQL tescil işlemi tamamlandı.", recordCount, int64(estimatedCount))
		} else {
			log.Printf("[Custom Export] Registering in pg catalog warning: %v", err)
			notify("REGISTERING", 99, "PostgreSQL kayıt uyarısı: "+err.Error(), recordCount, int64(estimatedCount))
		}
	}

	notify("COMPLETED", 100, fmt.Sprintf("Dışa aktarma ve mühürleme tamamlandı! Toplam %d kayıt arşivlendi.", recordCount), recordCount, int64(estimatedCount))
	return result, nil
}

