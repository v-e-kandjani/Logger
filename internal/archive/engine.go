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
	"time"

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

// StartAutoArchiving starts background worker that triggers periodic hourly archiving and timestamping
func (e *Engine) StartAutoArchiving(ctx context.Context, interval string, scheduleMinute int) {
	if scheduleMinute < 0 || scheduleMinute > 59 {
		scheduleMinute = 5
	}
	go func() {
		log.Printf("[Archive Engine] Periodic auto-archiving scheduler started (interval: %s, schedule_minute: %d)", interval, scheduleMinute)
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
						arch, err := e.CreateArchiveSlice(sliceCtx, sliceStart, sliceEnd)
						cancel()

						if err != nil {
							log.Printf("[Archive Engine] Auto-archive error for slice %s: %v", sliceStart.Format(time.RFC3339), err)
						} else {
							log.Printf("[Archive Engine] Auto-archive completed: %s (Logs: %d, SHA-256: %s, Status: %s)",
								arch.ArchiveName, arch.RecordCount, arch.HashValue, arch.TimestampStatus)
						}
					}
				}
			}
		}
	}()
}


// CreateArchiveSlice queries an immutable time slice, writes deterministic JSONL.GZ, computes SHA-256, and submits to KamuSM
func (e *Engine) CreateArchiveSlice(ctx context.Context, start, end time.Time) (*models.LogArchive, error) {
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

	archiveBaseName := fmt.Sprintf("logs-%s-%s", start.Format("20060102-150405"), end.Format("150405"))
	archiveFilePath := filepath.Join(dirPath, archiveBaseName+".jsonl.gz")

	// Query ClickHouse for records strictly inside bounds
	query := fmt.Sprintf(`
		SELECT internal_id, event_timestamp, received_at, source_ip, source_port,
		       transport_protocol, device_id, device_name, device_group, vendor,
		       product, facility_code, facility, severity_code, severity,
		       hostname, application_name, process_id, message_id, structured_data,
		       message, raw_message, collector_node, parser_status, ingestion_timestamp
		FROM %s.syslog_events
		WHERE event_timestamp >= ? AND event_timestamp < ?
		ORDER BY event_timestamp ASC, internal_id ASC`, e.chClient.Database())

	rows, err := e.chClient.QueryEvents(ctx, query, start, end)
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

// CreateCustomRangeArchive queries logs in an arbitrary period using either event_timestamp or received_at,
// generates the requested format (.jsonl.gz, .csv, or .zip compliance bundle), and applies a cryptographic seal if requested.
func (e *Engine) CreateCustomRangeArchive(ctx context.Context, opts CustomRangeOptions) (*CustomArchiveResult, error) {
	if opts.End.Before(opts.Start) {
		return nil, fmt.Errorf("end time (%s) must be after start time (%s)", opts.End.Format(time.RFC3339), opts.Start.Format(time.RFC3339))
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

	dirPath := filepath.Join(
		e.baseDir,
		"exports",
		fmt.Sprintf("%04d", opts.Start.Year()),
		fmt.Sprintf("%02d", opts.Start.Month()),
		fmt.Sprintf("%02d", opts.Start.Day()),
	)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return nil, fmt.Errorf("creating export directory: %w", err)
	}

	prefix := "logseal"
	if opts.TimeField == "received_at" {
		prefix = "logseal-rx"
	}
	baseName := fmt.Sprintf("%s-%s-%s", prefix, opts.Start.Format("20060102-150405"), opts.End.Format("20060102-150405"))

	query := fmt.Sprintf(`
		SELECT internal_id, event_timestamp, received_at, source_ip, source_port,
		       transport_protocol, device_id, device_name, device_group, vendor,
		       product, facility_code, facility, severity_code, severity,
		       hostname, application_name, process_id, message_id, structured_data,
		       message, raw_message, collector_node, parser_status, ingestion_timestamp
		FROM %s.syslog_events
		WHERE %s >= ? AND %s <= ?
		ORDER BY %s ASC, internal_id ASC`, e.chClient.Database(), timeCol, timeCol, timeCol)

	rows, err := e.chClient.QueryEvents(ctx, query, opts.Start, opts.End)
	if err != nil {
		return nil, fmt.Errorf("querying clickhouse for custom range: %w", err)
	}
	defer rows.Close()

	var recordCount int64
	var targetDataFilePath string

	if opts.Format == "csv" {
		targetDataFilePath = filepath.Join(dirPath, baseName+".csv")
		f, err := os.Create(targetDataFilePath)
		if err != nil {
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
		}
		cw.Flush()
		f.Close()
	} else {
		// Default to JSONL.GZ (for both "archive" and "bundle" formats)
		targetDataFilePath = filepath.Join(dirPath, baseName+".jsonl.gz")
		outFile, err := os.Create(targetDataFilePath)
		if err != nil {
			return nil, fmt.Errorf("creating archive file: %w", err)
		}

		gw, err := gzip.NewWriterLevel(outFile, gzip.DefaultCompression)
		if err != nil {
			outFile.Close()
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
				return nil, fmt.Errorf("scanning row: %w", err)
			}

			line, err := json.Marshal(ev)
			if err != nil {
				gw.Close()
				outFile.Close()
				return nil, err
			}
			if _, err := gw.Write(append(line, '\n')); err != nil {
				gw.Close()
				outFile.Close()
				return nil, err
			}
			recordCount++
		}
		gw.Close()
		outFile.Close()
	}

	// Compute Cryptographic SHA-256 for the data file
	hashVal, err := timestamp.ComputeSHA256(targetDataFilePath)
	if err != nil {
		return nil, fmt.Errorf("computing sha256: %w", err)
	}

	hashFilePath := filepath.Join(dirPath, baseName+".sha256")
	_ = os.WriteFile(hashFilePath, []byte(hashVal+"  "+filepath.Base(targetDataFilePath)+"\n"), 0644)

	fi, _ := os.Stat(targetDataFilePath)
	archiveSize := fi.Size()

	tsStatus := "ARCHIVED_NO_STAMP"
	evidencePath := ""

	// Perform Cryptographic Sealing if requested or if bundle format
	if (opts.Seal || opts.Format == "bundle") && e.provider != nil {
		tsCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		res, err := e.provider.Timestamp(tsCtx, targetDataFilePath)
		cancel()
		if err != nil {
			log.Printf("[Custom Export] Timestamp warning for %s: %v", targetDataFilePath, err)
			tsStatus = "TIMESTAMP_FAILED"
		} else {
			if res.EvidenceFile != "" {
				tsStatus = "STAMPED"
				evidencePath = res.EvidenceFile
			} else {
				tsStatus = "ARCHIVED_NO_STAMP"
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
		zipPath := filepath.Join(dirPath, baseName+"-compliance-bundle.zip")
		zf, err := os.Create(zipPath)
		if err != nil {
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
	}

	// Register in PostgreSQL catalog if requested
	if opts.Register {
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
		}
		if err := e.pgDB.CreateArchiveRecord(ctx, rec); err == nil {
			result.ArchiveRecord = rec
		} else {
			log.Printf("[Custom Export] Registering in pg catalog warning: %v", err)
		}
	}

	return result, nil
}

