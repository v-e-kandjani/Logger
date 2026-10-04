package archive

import (
	"compress/gzip"
	"context"
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
	query := `
		SELECT internal_id, event_timestamp, received_at, source_ip, source_port,
		       transport_protocol, device_id, device_name, device_group, vendor,
		       product, facility_code, facility, severity_code, severity,
		       hostname, application_name, process_id, message_id, structured_data,
		       message, raw_message, collector_node, parser_status, ingestion_timestamp
		FROM syslog.syslog_events
		WHERE event_timestamp >= ? AND event_timestamp < ?
		ORDER BY event_timestamp ASC, internal_id ASC`

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

	// Deterministic Gzip compression
	gw, err := gzip.NewWriterLevel(outFile, gzip.BestCompression)
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
