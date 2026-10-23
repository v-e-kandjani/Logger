package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/syslog-platform/logger/internal/models"
)

// EnsureUSBSchema initializes tables and indexes for USB & Storage DLP Control (Phase M)
func (db *DB) EnsureUSBSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS endpoint_usb_devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			device_id TEXT NOT NULL DEFAULT '',
			vendor_id VARCHAR(16) NOT NULL DEFAULT '',
			product_id VARCHAR(16) NOT NULL DEFAULT '',
			serial_number VARCHAR(128) NOT NULL DEFAULT '',
			vendor_name VARCHAR(128) DEFAULT '',
			product_name VARCHAR(128) DEFAULT '',
			drive_letter VARCHAR(16) DEFAULT '',
			mount_point TEXT DEFAULT '',
			capacity_bytes BIGINT DEFAULT 0,
			file_system VARCHAR(32) DEFAULT '',
			is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
			is_read_only BOOLEAN NOT NULL DEFAULT FALSE,
			is_connected BOOLEAN NOT NULL DEFAULT TRUE,
			is_whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
			first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_endpoint_usb_dev UNIQUE(agent_id, vendor_id, product_id, serial_number, device_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_usb_devices_tenant ON endpoint_usb_devices(tenant_slug);`,
		`CREATE INDEX IF NOT EXISTS idx_usb_devices_agent ON endpoint_usb_devices(agent_id, is_connected);`,
		`CREATE INDEX IF NOT EXISTS idx_usb_devices_vid_pid ON endpoint_usb_devices(vendor_id, product_id);`,

		`CREATE TABLE IF NOT EXISTS endpoint_usb_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			agent_id UUID NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
			event_type VARCHAR(64) NOT NULL,
			vendor_id VARCHAR(16) DEFAULT '',
			product_id VARCHAR(16) DEFAULT '',
			serial_number VARCHAR(128) DEFAULT '',
			device_name VARCHAR(255) DEFAULT '',
			drive_letter VARCHAR(16) DEFAULT '',
			mount_point TEXT DEFAULT '',
			action_taken VARCHAR(64) DEFAULT 'allowed',
			mitre_technique VARCHAR(64) DEFAULT 'T1052.001',
			details TEXT DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_usb_events_tenant_time ON endpoint_usb_events(tenant_slug, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_usb_events_agent ON endpoint_usb_events(agent_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_usb_events_type ON endpoint_usb_events(event_type);`,

		`CREATE TABLE IF NOT EXISTS endpoint_usb_whitelist (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			name VARCHAR(128) NOT NULL DEFAULT '',
			vendor_id VARCHAR(16) NOT NULL DEFAULT '',
			product_id VARCHAR(16) NOT NULL DEFAULT '',
			serial_number VARCHAR(128) NOT NULL DEFAULT '',
			description TEXT DEFAULT '',
			approved_by VARCHAR(128) DEFAULT 'admin',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_usb_whitelist_dev UNIQUE(tenant_slug, vendor_id, product_id, serial_number)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_usb_whitelist_tenant ON endpoint_usb_whitelist(tenant_slug);`,
	}

	for _, q := range queries {
		if _, err := db.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("executing USB schema query: %w", err)
		}
	}
	return nil
}

// UpsertAgentUSBDevices updates currently connected USB devices reported by an agent
func (db *DB) UpsertAgentUSBDevices(ctx context.Context, tenantSlug string, agentID uuid.UUID, devices []models.EndpointUSBDevice) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Mark all previously connected devices for this agent as disconnected
	_, err = tx.Exec(ctx, `
		UPDATE endpoint_usb_devices 
		SET is_connected = FALSE, updated_at = NOW() 
		WHERE agent_id = $1
	`, agentID)
	if err != nil {
		return fmt.Errorf("marking devices disconnected: %w", err)
	}

	for _, d := range devices {
		// Check if whitelisted for this tenant
		var isWhitelisted bool
		_ = tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM endpoint_usb_whitelist 
				WHERE (tenant_slug = $1 OR tenant_slug = 'default')
				  AND (
					(vendor_id != '' AND vendor_id = $2 AND product_id != '' AND product_id = $3) OR
					(serial_number != '' AND serial_number = $4)
				  )
			)
		`, tenantSlug, d.VendorID, d.ProductID, d.SerialNumber).Scan(&isWhitelisted)

		query := `
			INSERT INTO endpoint_usb_devices (
				tenant_slug, agent_id, device_id, vendor_id, product_id, serial_number,
				vendor_name, product_name, drive_letter, mount_point, capacity_bytes,
				file_system, is_blocked, is_read_only, is_connected, is_whitelisted,
				first_seen, last_seen, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, TRUE, $15, NOW(), NOW(), NOW()
			)
			ON CONFLICT (agent_id, vendor_id, product_id, serial_number, device_id) DO UPDATE SET
				tenant_slug = EXCLUDED.tenant_slug,
				vendor_name = EXCLUDED.vendor_name,
				product_name = EXCLUDED.product_name,
				drive_letter = EXCLUDED.drive_letter,
				mount_point = EXCLUDED.mount_point,
				capacity_bytes = EXCLUDED.capacity_bytes,
				file_system = EXCLUDED.file_system,
				is_blocked = EXCLUDED.is_blocked,
				is_read_only = EXCLUDED.is_read_only,
				is_connected = TRUE,
				is_whitelisted = EXCLUDED.is_whitelisted,
				last_seen = NOW(),
				updated_at = NOW()
		`
		_, err = tx.Exec(ctx, query,
			tenantSlug, agentID, d.DeviceID, d.VendorID, d.ProductID, d.SerialNumber,
			d.VendorName, d.ProductName, d.DriveLetter, d.MountPoint, d.CapacityBytes,
			d.FileSystem, d.IsBlocked, d.IsReadOnly, isWhitelisted,
		)
		if err != nil {
			return fmt.Errorf("upserting usb device: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// RecordUSBEvents inserts audit events for USB insertions, removals, and policy violations
func (db *DB) RecordUSBEvents(ctx context.Context, tenantSlug string, agentID uuid.UUID, events []models.EndpointUSBEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, e := range events {
		mitre := e.MitreTechnique
		if mitre == "" {
			if e.EventType == "blocked" || e.EventType == "unauthorized_whitelist" {
				mitre = "T1200" // Hardware Additions
			} else if e.EventType == "write_denied" {
				mitre = "T1052.001" // Exfiltration Over Physical Medium
			} else {
				mitre = "T1052.001"
			}
		}

		query := `
			INSERT INTO endpoint_usb_events (
				tenant_slug, agent_id, event_type, vendor_id, product_id, serial_number,
				device_name, drive_letter, mount_point, action_taken, mitre_technique, details, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
		`
		_, err = tx.Exec(ctx, query,
			tenantSlug, agentID, e.EventType, e.VendorID, e.ProductID, e.SerialNumber,
			e.DeviceName, e.DriveLetter, e.MountPoint, e.ActionTaken, mitre, e.Details,
		)
		if err != nil {
			return fmt.Errorf("inserting usb event: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// ListUSBDevices queries connected and historical USB devices for a tenant or agent
func (db *DB) ListUSBDevices(ctx context.Context, tenantSlug string, agentID *uuid.UUID, connectedOnly bool, limit, offset int) ([]models.EndpointUSBDevice, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	var sb strings.Builder
	var countSb strings.Builder
	args := []interface{}{}
	argIdx := 1

	baseFilter := ` WHERE 1=1 `
	if tenantSlug != "" && tenantSlug != "all" {
		baseFilter += fmt.Sprintf(` AND (d.tenant_slug = $%d OR d.tenant_slug = 'default')`, argIdx)
		args = append(args, tenantSlug)
		argIdx++
	}

	if agentID != nil {
		baseFilter += fmt.Sprintf(` AND d.agent_id = $%d`, argIdx)
		args = append(args, *agentID)
		argIdx++
	}

	if connectedOnly {
		baseFilter += ` AND d.is_connected = TRUE `
	}

	countSb.WriteString(`SELECT COUNT(*) FROM endpoint_usb_devices d ` + baseFilter)
	var total int
	err := db.pool.QueryRow(ctx, countSb.String(), args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("counting usb devices: %w", err)
	}

	sb.WriteString(`
		SELECT d.id, d.agent_id, d.tenant_slug, COALESCE(a.hostname, '') as agent_hostname, 
		       COALESCE(a.ip_address, '') as agent_ip, d.device_id, d.vendor_id, d.product_id, 
		       d.serial_number, d.vendor_name, d.product_name, d.drive_letter, d.mount_point, 
		       d.capacity_bytes, d.file_system, d.is_blocked, d.is_read_only, d.is_connected, 
		       d.is_whitelisted, d.first_seen, d.last_seen, d.updated_at
		FROM endpoint_usb_devices d
		LEFT JOIN endpoint_agents a ON a.id = d.agent_id
	`)
	sb.WriteString(baseFilter)
	sb.WriteString(` ORDER BY d.is_connected DESC, d.last_seen DESC `)
	sb.WriteString(fmt.Sprintf(` LIMIT $%d OFFSET $%d`, argIdx, argIdx+1))
	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying usb devices: %w", err)
	}
	defer rows.Close()

	var devices []models.EndpointUSBDevice
	for rows.Next() {
		var dev models.EndpointUSBDevice
		if err := rows.Scan(
			&dev.ID, &dev.AgentID, &dev.TenantSlug, &dev.AgentHostname, &dev.AgentIP,
			&dev.DeviceID, &dev.VendorID, &dev.ProductID, &dev.SerialNumber,
			&dev.VendorName, &dev.ProductName, &dev.DriveLetter, &dev.MountPoint,
			&dev.CapacityBytes, &dev.FileSystem, &dev.IsBlocked, &dev.IsReadOnly,
			&dev.IsConnected, &dev.IsWhitelisted, &dev.FirstSeen, &dev.LastSeen, &dev.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning usb device row: %w", err)
		}
		devices = append(devices, dev)
	}

	if devices == nil {
		devices = []models.EndpointUSBDevice{}
	}
	return devices, total, nil
}

// ListUSBEvents queries DLP audit events with pagination and filtering
func (db *DB) ListUSBEvents(ctx context.Context, tenantSlug string, agentID *uuid.UUID, eventType string, limit, offset int) ([]models.EndpointUSBEvent, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	var sb strings.Builder
	var countSb strings.Builder
	args := []interface{}{}
	argIdx := 1

	baseFilter := ` WHERE 1=1 `
	if tenantSlug != "" && tenantSlug != "all" {
		baseFilter += fmt.Sprintf(` AND (e.tenant_slug = $%d OR e.tenant_slug = 'default')`, argIdx)
		args = append(args, tenantSlug)
		argIdx++
	}

	if agentID != nil {
		baseFilter += fmt.Sprintf(` AND e.agent_id = $%d`, argIdx)
		args = append(args, *agentID)
		argIdx++
	}

	if eventType != "" && eventType != "all" {
		baseFilter += fmt.Sprintf(` AND e.event_type = $%d`, argIdx)
		args = append(args, eventType)
		argIdx++
	}

	countSb.WriteString(`SELECT COUNT(*) FROM endpoint_usb_events e ` + baseFilter)
	var total int
	err := db.pool.QueryRow(ctx, countSb.String(), args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("counting usb events: %w", err)
	}

	sb.WriteString(`
		SELECT e.id, e.tenant_slug, e.agent_id, COALESCE(a.hostname, '') as agent_hostname,
		       COALESCE(a.ip_address, '') as agent_ip, e.event_type, e.vendor_id, e.product_id,
		       e.serial_number, e.device_name, e.drive_letter, e.mount_point, e.action_taken,
		       e.mitre_technique, e.details, e.created_at
		FROM endpoint_usb_events e
		LEFT JOIN endpoint_agents a ON a.id = e.agent_id
	`)
	sb.WriteString(baseFilter)
	sb.WriteString(` ORDER BY e.created_at DESC `)
	sb.WriteString(fmt.Sprintf(` LIMIT $%d OFFSET $%d`, argIdx, argIdx+1))
	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying usb events: %w", err)
	}
	defer rows.Close()

	var events []models.EndpointUSBEvent
	for rows.Next() {
		var ev models.EndpointUSBEvent
		if err := rows.Scan(
			&ev.ID, &ev.TenantSlug, &ev.AgentID, &ev.AgentHostname, &ev.AgentIP,
			&ev.EventType, &ev.VendorID, &ev.ProductID, &ev.SerialNumber,
			&ev.DeviceName, &ev.DriveLetter, &ev.MountPoint, &ev.ActionTaken,
			&ev.MitreTechnique, &ev.Details, &ev.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning usb event row: %w", err)
		}
		events = append(events, ev)
	}

	if events == nil {
		events = []models.EndpointUSBEvent{}
	}
	return events, total, nil
}

// ListUSBWhitelist returns authorized USB entries for a tenant
func (db *DB) ListUSBWhitelist(ctx context.Context, tenantSlug string) ([]models.EndpointUSBWhitelistEntry, error) {
	query := `
		SELECT id, tenant_slug, name, vendor_id, product_id, serial_number, description, approved_by, created_at
		FROM endpoint_usb_whitelist
		WHERE ($1 = '' OR $1 = 'all' OR tenant_slug = $1 OR tenant_slug = 'default')
		ORDER BY created_at DESC
	`
	rows, err := db.pool.Query(ctx, query, tenantSlug)
	if err != nil {
		return nil, fmt.Errorf("querying usb whitelist: %w", err)
	}
	defer rows.Close()

	var list []models.EndpointUSBWhitelistEntry
	for rows.Next() {
		var entry models.EndpointUSBWhitelistEntry
		if err := rows.Scan(
			&entry.ID, &entry.TenantSlug, &entry.Name, &entry.VendorID,
			&entry.ProductID, &entry.SerialNumber, &entry.Description,
			&entry.ApprovedBy, &entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning whitelist row: %w", err)
		}
		list = append(list, entry)
	}

	if list == nil {
		list = []models.EndpointUSBWhitelistEntry{}
	}
	return list, nil
}

// AddUSBWhitelistEntry inserts or updates an authorized device
func (db *DB) AddUSBWhitelistEntry(ctx context.Context, entry *models.EndpointUSBWhitelistEntry) (*models.EndpointUSBWhitelistEntry, error) {
	if entry.TenantSlug == "" {
		entry.TenantSlug = "default"
	}
	entry.VendorID = strings.TrimSpace(strings.ToUpper(entry.VendorID))
	entry.ProductID = strings.TrimSpace(strings.ToUpper(entry.ProductID))
	entry.SerialNumber = strings.TrimSpace(entry.SerialNumber)

	if entry.VendorID == "" && entry.SerialNumber == "" {
		return nil, errors.New("either Vendor ID or Serial Number is required for whitelisting")
	}

	query := `
		INSERT INTO endpoint_usb_whitelist (
			tenant_slug, name, vendor_id, product_id, serial_number, description, approved_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (tenant_slug, vendor_id, product_id, serial_number) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			approved_by = EXCLUDED.approved_by
		RETURNING id, created_at
	`
	err := db.pool.QueryRow(ctx, query,
		entry.TenantSlug, entry.Name, entry.VendorID, entry.ProductID,
		entry.SerialNumber, entry.Description, entry.ApprovedBy,
	).Scan(&entry.ID, &entry.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting usb whitelist entry: %w", err)
	}

	// Update previously marked devices as whitelisted
	_, _ = db.pool.Exec(ctx, `
		UPDATE endpoint_usb_devices 
		SET is_whitelisted = TRUE 
		WHERE (tenant_slug = $1 OR tenant_slug = 'default')
		  AND (
			(vendor_id != '' AND vendor_id = $2 AND product_id != '' AND product_id = $3) OR
			(serial_number != '' AND serial_number = $4)
		  )
	`, entry.TenantSlug, entry.VendorID, entry.ProductID, entry.SerialNumber)

	return entry, nil
}

// DeleteUSBWhitelistEntry removes an authorized device by ID
func (db *DB) DeleteUSBWhitelistEntry(ctx context.Context, tenantSlug string, id uuid.UUID) error {
	var entryTenant, vid, pid, serial string
	err := db.pool.QueryRow(ctx, `
		SELECT tenant_slug, vendor_id, product_id, serial_number 
		FROM endpoint_usb_whitelist 
		WHERE id = $1
	`, id).Scan(&entryTenant, &vid, &pid, &serial)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("whitelist entry not found")
		}
		return err
	}

	if tenantSlug != "" && tenantSlug != "all" && entryTenant != tenantSlug {
		return errors.New("unauthorized: entry belongs to another tenant")
	}

	_, err = db.pool.Exec(ctx, `DELETE FROM endpoint_usb_whitelist WHERE id = $1`, id)
	if err != nil {
		return err
	}

	// Recalculate is_whitelisted for devices matching this entry
	_, _ = db.pool.Exec(ctx, `
		UPDATE endpoint_usb_devices d
		SET is_whitelisted = EXISTS(
			SELECT 1 FROM endpoint_usb_whitelist w
			WHERE (w.tenant_slug = d.tenant_slug OR w.tenant_slug = 'default')
			  AND (
				(w.vendor_id != '' AND w.vendor_id = d.vendor_id AND w.product_id != '' AND w.product_id = d.product_id) OR
				(w.serial_number != '' AND w.serial_number = d.serial_number)
			  )
		)
		WHERE d.vendor_id = $1 AND d.product_id = $2
	`, vid, pid)

	return nil
}

// GetUSBStats returns summary metrics for DLP telemetry
func (db *DB) GetUSBStats(ctx context.Context, tenantSlug string) (totalDevices, connectedDevices, blockedEvents, totalEvents int, err error) {
	baseDevFilter := ` WHERE 1=1 `
	baseEvtFilter := ` WHERE 1=1 `
	args := []interface{}{}

	if tenantSlug != "" && tenantSlug != "all" {
		baseDevFilter += ` AND (tenant_slug = $1 OR tenant_slug = 'default') `
		baseEvtFilter += ` AND (tenant_slug = $1 OR tenant_slug = 'default') `
		args = append(args, tenantSlug)
	}

	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_usb_devices `+baseDevFilter, args...).Scan(&totalDevices)
	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_usb_devices `+baseDevFilter+` AND is_connected = TRUE`, args...).Scan(&connectedDevices)
	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_usb_events `+baseEvtFilter+` AND event_type IN ('blocked', 'write_denied', 'unauthorized_whitelist')`, args...).Scan(&blockedEvents)
	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_usb_events `+baseEvtFilter, args...).Scan(&totalEvents)

	return totalDevices, connectedDevices, blockedEvents, totalEvents, nil
}
