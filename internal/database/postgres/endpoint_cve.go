package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// IngestAgentInventory processes software packages, patches, and host metadata uploaded by an agent
func (db *DB) IngestAgentInventory(ctx context.Context, agentUUID string, req models.AgentInventoryRequest) (*models.AgentInventoryResponse, error) {
	// 1. Locate agent
	var (
		agentID    uuid.UUID
		tenantSlug string
	)
	err := db.pool.QueryRow(ctx, `
		SELECT id, tenant_slug
		FROM endpoint_agents
		WHERE agent_uuid = $1
	`, agentUUID).Scan(&agentID, &tenantSlug)
	if err != nil {
		return nil, fmt.Errorf("agent not found by uuid %s: %w", agentUUID, err)
	}

	now := time.Now().UTC()

	// 2. Update agent metadata
	_, err = db.pool.Exec(ctx, `
		UPDATE endpoint_agents
		SET os_name = COALESCE(NULLIF($1, ''), os_name),
		    os_version = COALESCE(NULLIF($2, ''), os_version),
		    os_build = COALESCE(NULLIF($3, ''), os_build),
		    kernel_version = COALESCE(NULLIF($4, ''), kernel_version),
		    architecture = COALESCE(NULLIF($5, ''), architecture),
		    ip_address = COALESCE(NULLIF($6, ''), ip_address),
		    mac_address = COALESCE(NULLIF($7, ''), mac_address),
		    last_seen = $8,
		    last_inventory = $8,
		    updated_at = $8
		WHERE id = $9
	`, req.OSName, req.OSVersion, req.OSBuild, req.KernelVersion, req.Architecture,
		req.IPAddress, req.MACAddress, now, agentID)
	if err != nil {
		return nil, fmt.Errorf("updating agent host metadata: %w", err)
	}

	// 3. Upsert into endpoint_inventory_current
	sysJSON, _ := json.Marshal(req.SystemInfo)
	hwJSON, _ := json.Marshal(req.HardwareInfo)
	netJSON, _ := json.Marshal(req.NetworkInfo)

	_, err = db.pool.Exec(ctx, `
		INSERT INTO endpoint_inventory_current (agent_id, tenant_slug, system_info, hardware_info, network_info, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (agent_id) DO UPDATE SET
			tenant_slug = EXCLUDED.tenant_slug,
			system_info = EXCLUDED.system_info,
			hardware_info = EXCLUDED.hardware_info,
			network_info = EXCLUDED.network_info,
			updated_at = EXCLUDED.updated_at
	`, agentID, tenantSlug, sysJSON, hwJSON, netJSON, now)
	if err != nil {
		return nil, fmt.Errorf("upserting inventory snapshot: %w", err)
	}

	// 4. Ingest software packages
	processedSoftware := 0
	if len(req.Software) > 0 {
		// Clean stale software for this agent
		_, _ = db.pool.Exec(ctx, `DELETE FROM endpoint_software_current WHERE agent_id = $1`, agentID)

		for _, sw := range req.Software {
			name := strings.TrimSpace(sw.Name)
			if name == "" {
				continue
			}
			version := strings.TrimSpace(sw.Version)
			if version == "" {
				version = "1.0"
			}
			arch := strings.TrimSpace(sw.Arch)
			if arch == "" {
				arch = req.Architecture
			}

			_, err := db.pool.Exec(ctx, `
				INSERT INTO endpoint_software_current (
					agent_id, tenant_slug, name, vendor, version, arch, package_type, install_location, first_seen, last_seen
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
				ON CONFLICT (agent_id, name, version, arch) DO UPDATE SET
					vendor = EXCLUDED.vendor,
					install_location = EXCLUDED.install_location,
					last_seen = EXCLUDED.last_seen
			`, agentID, tenantSlug, name, sw.Vendor, version, arch, sw.PackageType, sw.InstallLocation, now)
			if err == nil {
				processedSoftware++
			}
		}
	}

	// 5. Ingest patches
	processedPatches := 0
	if len(req.Patches) > 0 {
		_, _ = db.pool.Exec(ctx, `DELETE FROM endpoint_patches_current WHERE agent_id = $1`, agentID)

		for _, p := range req.Patches {
			kb := strings.TrimSpace(p.HotFixID)
			if kb == "" {
				continue
			}
			_, err := db.pool.Exec(ctx, `
				INSERT INTO endpoint_patches_current (
					agent_id, tenant_slug, patch_id, kb_id, title, status, detected_at
				) VALUES ($1, $2, $3, $3, $4, 'installed', $5)
			`, agentID, tenantSlug, kb, p.Description, now)
			if err == nil {
				processedPatches++
			}
		}
	}

	// 6. Correlate with CVE Catalog to produce real-time findings
	detectedVulns, _ := db.CorrelateAgentVulnerabilities(ctx, agentID, tenantSlug)

	return &models.AgentInventoryResponse{
		Ack:               true,
		ProcessedSoftware: processedSoftware,
		ProcessedPatches:  processedPatches,
		DetectedVulns:     detectedVulns,
		ServerTime:        now,
	}, nil
}

// CorrelateAgentVulnerabilities matches an agent's installed software and OS against the CVE catalog
func (db *DB) CorrelateAgentVulnerabilities(ctx context.Context, agentID uuid.UUID, tenantSlug string) (int, error) {
	// Query installed software
	rows, err := db.pool.Query(ctx, `
		SELECT id, name, version, vendor
		FROM endpoint_software_current
		WHERE agent_id = $1
	`, agentID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type swItem struct {
		ID      uuid.UUID
		Name    string
		Version string
		Vendor  string
	}
	var softwares []swItem
	for rows.Next() {
		var sw swItem
		if err := rows.Scan(&sw.ID, &sw.Name, &sw.Version, &sw.Vendor); err == nil {
			softwares = append(softwares, sw)
		}
	}
	rows.Close()

	now := time.Now().UTC()
	detectedCount := 0

	for _, sw := range softwares {
		swLower := strings.ToLower(sw.Name)

		// Search matching CVEs in catalog by title, description, or criteria
		cveRows, err := db.pool.Query(ctx, `
			SELECT cve_id, title, cvss_score, severity, cisa_kev, epss_probability
			FROM endpoint_cve_catalog
			WHERE (
				LOWER(title) LIKE '%' || $1 || '%'
				OR LOWER(description) LIKE '%' || $1 || '%'
				OR cpe_criteria_json::text ILIKE '%' || $1 || '%'
			)
			LIMIT 10
		`, swLower)
		if err != nil {
			continue
		}

		for cveRows.Next() {
			var (
				cveID     string
				title     string
				cvss      float64
				severity  string
				cisaKev   bool
				epssScore float64
			)
			if err := cveRows.Scan(&cveID, &title, &cvss, &severity, &cisaKev, &epssScore); err == nil {
				priority := "MEDIUM"
				if severity == "CRITICAL" || cisaKev || cvss >= 9.0 {
					priority = "CRITICAL"
				} else if severity == "HIGH" || cvss >= 7.0 {
					priority = "HIGH"
				}

				evidence := map[string]interface{}{
					"matched_software": sw.Name,
					"detected_version": sw.Version,
					"cve_id":           cveID,
					"cve_title":        title,
					"correlation_time": now,
				}
				evidenceJSON, _ := json.Marshal(evidence)

				_, err := db.pool.Exec(ctx, `
					INSERT INTO endpoint_vulnerability_findings (
						tenant_slug, agent_id, cve_id, software_id, status,
						detected_version, cvss_score, severity, priority,
						cisa_kev, epss_probability, detection_source, evidence_json,
						first_seen, last_seen
					) VALUES (
						$1, $2, $3, $4, 'open',
						$5, $6, $7, $8,
						$9, $10, 'Automated Correlation Engine', $11,
						$12, $12
					)
					ON CONFLICT (agent_id, cve_id, software_id) DO UPDATE SET
						detected_version = EXCLUDED.detected_version,
						cvss_score = EXCLUDED.cvss_score,
						severity = EXCLUDED.severity,
						priority = EXCLUDED.priority,
						cisa_kev = EXCLUDED.cisa_kev,
						last_seen = EXCLUDED.last_seen
				`, tenantSlug, agentID, cveID, sw.ID,
					sw.Version, cvss, severity, priority,
					cisaKev, epssScore, evidenceJSON, now)
				if err == nil {
					detectedCount++
				}
			}
		}
		cveRows.Close()
	}

	// Update vulnerability counts on agent record
	var totalVulns, critVulns int
	_ = db.pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE severity = 'CRITICAL' OR priority = 'CRITICAL' OR cisa_kev = TRUE)
		FROM endpoint_vulnerability_findings
		WHERE agent_id = $1 AND status = 'open'
	`, agentID).Scan(&totalVulns, &critVulns)

	_, _ = db.pool.Exec(ctx, `
		UPDATE endpoint_agents
		SET open_vulns_count = $1,
		    critical_vulns_count = $2,
		    updated_at = $3
		WHERE id = $4
	`, totalVulns, critVulns, now, agentID)

	return detectedCount, nil
}

// UpsertCVEBatch inserts or updates a slice of CVE records into endpoint_cve_catalog
func (db *DB) UpsertCVEBatch(ctx context.Context, cves []models.EndpointCVE) (int, error) {
	if len(cves) == 0 {
		return 0, nil
	}

	count := 0
	now := time.Now().UTC()

	for _, c := range cves {
		cveID := strings.TrimSpace(c.CVEID)
		if cveID == "" {
			continue
		}

		severity := strings.ToUpper(strings.TrimSpace(c.Severity))
		if severity == "" {
			if c.CVSSScore >= 9.0 {
				severity = "CRITICAL"
			} else if c.CVSSScore >= 7.0 {
				severity = "HIGH"
			} else if c.CVSSScore >= 4.0 {
				severity = "MEDIUM"
			} else {
				severity = "LOW"
			}
		}

		cpeJSON := c.CPECriteria
		if len(cpeJSON) == 0 {
			cpeJSON = []byte("[]")
		}
		refJSON := c.References
		if len(refJSON) == 0 {
			refJSON = []byte("[]")
		}

		_, err := db.pool.Exec(ctx, `
			INSERT INTO endpoint_cve_catalog (
				cve_id, title, description, published_at, modified_at,
				cvss_score, severity, cisa_kev, epss_probability, source,
				cpe_criteria_json, references_json, updated_at
			) VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8, $9, $10,
				$11, $12, $13
			)
			ON CONFLICT (cve_id) DO UPDATE SET
				title = EXCLUDED.title,
				description = EXCLUDED.description,
				cvss_score = EXCLUDED.cvss_score,
				severity = EXCLUDED.severity,
				cisa_kev = EXCLUDED.cisa_kev,
				epss_probability = EXCLUDED.epss_probability,
				source = EXCLUDED.source,
				cpe_criteria_json = EXCLUDED.cpe_criteria_json,
				references_json = EXCLUDED.references_json,
				updated_at = EXCLUDED.updated_at
		`, cveID, c.Title, c.Description, c.PublishedAt, c.ModifiedAt,
			c.CVSSScore, severity, c.CISAKEV, c.EPSSProbability, c.Source,
			cpeJSON, refJSON, now)
		if err == nil {
			count++
		}
	}

	return count, nil
}

// GetCVESyncStatus returns statistics, last sync time, and schedule configuration
func (db *DB) GetCVESyncStatus(ctx context.Context) (*models.CVESyncStatus, error) {
	status := &models.CVESyncStatus{
		ScheduleMode:   "daily",
		LastSyncStatus: "idle",
	}

	// 1. Count totals from endpoint_cve_catalog
	_ = db.pool.QueryRow(ctx, `
		SELECT 
			COUNT(*),
			COUNT(*) FILTER (WHERE cisa_kev = TRUE),
			COUNT(*) FILTER (WHERE severity = 'CRITICAL' OR cvss_score >= 9.0)
		FROM endpoint_cve_catalog
	`).Scan(&status.TotalCVEs, &status.CISAKEVCount, &status.HighCritCount)

	// 2. Query endpoint_feed_sources for schedule and sync metadata
	var (
		lastSync  *time.Time
		intervalM int
		feedStat  string
		lastErr   string
	)
	err := db.pool.QueryRow(ctx, `
		SELECT last_sync_at, sync_interval_minutes, last_sync_status, last_error
		FROM endpoint_feed_sources
		WHERE name = 'cisa_kev'
	`).Scan(&lastSync, &intervalM, &feedStat, &lastErr)
	if err == nil {
		status.LastSyncAt = lastSync
		status.LastSyncStatus = feedStat
		status.LastError = lastErr

		// Infer schedule mode from sync_interval_minutes
		switch {
		case intervalM <= 0:
			status.ScheduleMode = "manual"
		case intervalM <= 1440:
			status.ScheduleMode = "daily"
		case intervalM <= 10080:
			status.ScheduleMode = "weekly"
		default:
			status.ScheduleMode = "monthly"
		}

		if lastSync != nil && intervalM > 0 {
			next := lastSync.Add(time.Duration(intervalM) * time.Minute)
			status.NextSyncAt = &next
		}
	}

	return status, nil
}

// UpdateCVESchedule saves the auto-update schedule preference (daily, weekly, monthly, manual)
func (db *DB) UpdateCVESchedule(ctx context.Context, scheduleMode string) error {
	intervalM := 1440 // default daily
	switch strings.ToLower(scheduleMode) {
	case "manual":
		intervalM = 0
	case "daily":
		intervalM = 1440 // 24 hours
	case "weekly":
		intervalM = 10080 // 7 days
	case "monthly":
		intervalM = 43200 // 30 days
	default:
		intervalM = 1440
	}

	_, err := db.pool.Exec(ctx, `
		UPDATE endpoint_feed_sources
		SET sync_interval_minutes = $1,
		    updated_at = NOW()
		WHERE name IN ('cisa_kev', 'nvd')
	`, intervalM)
	return err
}

// RecordCVESyncResult updates feed status after a sync attempt
func (db *DB) RecordCVESyncResult(ctx context.Context, feedName string, recordsCount int, syncErr error) error {
	status := "completed"
	errStr := ""
	if syncErr != nil {
		status = "error"
		errStr = syncErr.Error()
	}

	_, err := db.pool.Exec(ctx, `
		UPDATE endpoint_feed_sources
		SET last_sync_at = NOW(),
		    last_sync_status = $1,
		    last_error = $2,
		    records_count = $3,
		    updated_at = NOW()
		WHERE name = $4
	`, status, errStr, recordsCount, feedName)
	return err
}

// ListVulnerabilityFindings lists detected CVE findings joined with host and CVE catalog details
func (db *DB) ListVulnerabilityFindings(ctx context.Context, tenantSlug, severity, status, search string, limit, offset int) ([]models.EndpointFinding, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if tenantSlug != "" && tenantSlug != "all" {
		where = append(where, fmt.Sprintf("f.tenant_slug = $%d", argIdx))
		args = append(args, tenantSlug)
		argIdx++
	}
	if severity != "" && severity != "all" {
		where = append(where, fmt.Sprintf("f.severity = $%d", argIdx))
		args = append(args, strings.ToUpper(severity))
		argIdx++
	}
	if status != "" && status != "all" {
		where = append(where, fmt.Sprintf("f.status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}
	if search != "" {
		where = append(where, fmt.Sprintf("(f.cve_id ILIKE $%d OR a.hostname ILIKE $%d OR s.name ILIKE $%d)", argIdx, argIdx, argIdx))
		args = append(args, "%"+search+"%")
		argIdx++
	}

	whereClause := strings.Join(where, " AND ")

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_vulnerability_findings f
		JOIN endpoint_agents a ON a.id = f.agent_id
		LEFT JOIN endpoint_software_current s ON s.id = f.software_id
		WHERE %s
	`, whereClause)

	var total int
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT 
			f.id, f.tenant_slug, f.agent_id, a.hostname, a.ip_address, a.os_type,
			f.cve_id, COALESCE(c.title, ''), f.cvss_score, f.severity, f.cisa_kev,
			f.epss_probability, f.software_id, COALESCE(s.name, ''), f.status,
			f.detected_version, f.fixed_version, f.patch_available, f.patch_id,
			f.priority, f.reboot_required, f.detection_source, f.first_seen, f.last_seen
		FROM endpoint_vulnerability_findings f
		JOIN endpoint_agents a ON a.id = f.agent_id
		LEFT JOIN endpoint_cve_catalog c ON c.cve_id = f.cve_id
		LEFT JOIN endpoint_software_current s ON s.id = f.software_id
		WHERE %s
		ORDER BY f.cisa_kev DESC, f.cvss_score DESC, f.last_seen DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	findings := []models.EndpointFinding{}
	for rows.Next() {
		var f models.EndpointFinding
		var softID *uuid.UUID
		err := rows.Scan(
			&f.ID, &f.TenantSlug, &f.AgentID, &f.AgentHostname, &f.AgentIP, &f.AgentOS,
			&f.CVEID, &f.CVETitle, &f.CVSSScore, &f.Severity, &f.CISAKEV,
			&f.EPSSProbability, &softID, &f.SoftwareName, &f.Status,
			&f.DetectedVersion, &f.FixedVersion, &f.PatchAvailable, &f.PatchID,
			&f.Priority, &f.RebootRequired, &f.DetectionSource, &f.FirstSeen, &f.LastSeen,
		)
		if err == nil {
			f.SoftwareID = softID
			findings = append(findings, f)
		}
	}

	return findings, total, nil
}

// ListEndpointSoftware lists discovered installed software across endpoints
func (db *DB) ListEndpointSoftware(ctx context.Context, tenantSlug, search string, limit, offset int) ([]models.EndpointSoftware, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if tenantSlug != "" && tenantSlug != "all" {
		where = append(where, fmt.Sprintf("s.tenant_slug = $%d", argIdx))
		args = append(args, tenantSlug)
		argIdx++
	}
	if search != "" {
		where = append(where, fmt.Sprintf("(s.name ILIKE $%d OR s.vendor ILIKE $%d OR a.hostname ILIKE $%d)", argIdx, argIdx, argIdx))
		args = append(args, "%"+search+"%")
		argIdx++
	}

	whereClause := strings.Join(where, " AND ")

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_software_current s
		JOIN endpoint_agents a ON a.id = s.agent_id
		WHERE %s
	`, whereClause)

	var total int
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT 
			s.id, s.agent_id, s.tenant_slug, s.name, s.vendor, s.version,
			s.arch, s.package_type, s.package_name, s.install_location,
			s.purl, s.cpe, s.first_seen, s.last_seen,
			COALESCE(a.hostname, ''), COALESCE(a.ip_address, ''), COALESCE(a.os_type, '')
		FROM endpoint_software_current s
		JOIN endpoint_agents a ON a.id = s.agent_id
		WHERE %s
		ORDER BY s.last_seen DESC, s.name ASC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	list := []models.EndpointSoftware{}
	for rows.Next() {
		var s models.EndpointSoftware
		err := rows.Scan(
			&s.ID, &s.AgentID, &s.TenantSlug, &s.Name, &s.Vendor, &s.Version,
			&s.Arch, &s.PackageType, &s.PackageName, &s.InstallLocation,
			&s.PURL, &s.CPE, &s.FirstSeen, &s.LastSeen,
			&s.AgentHostname, &s.AgentIP, &s.AgentOS,
		)
		if err == nil {
			list = append(list, s)
		}
	}

	return list, total, nil
}

// ListEndpointPatches returns patches joining agent details
func (db *DB) ListEndpointPatches(ctx context.Context, tenantSlug, status, search string, limit, offset int) ([]models.EndpointPatchItem, int, error) {
	if limit <= 0 {
		limit = 50
	}

	whereConditions := []string{"($1 = '' OR $1 = 'all' OR p.tenant_slug = $1)"}
	args := []interface{}{tenantSlug}
	argIdx := 2

	if status != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("p.status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}

	if search != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("(p.patch_id ILIKE '%%' || $%d || '%%' OR p.title ILIKE '%%' || $%d || '%%' OR a.hostname ILIKE '%%' || $%d || '%%')", argIdx, argIdx, argIdx))
		args = append(args, search)
		argIdx++
	}

	whereClause := strings.Join(whereConditions, " AND ")

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM endpoint_patches_current p
		JOIN endpoint_agents a ON a.id = p.agent_id
		WHERE %s
	`, whereClause)

	var total int
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT 
			p.id, p.agent_id, a.hostname, a.ip_address, a.os_type,
			p.patch_id, p.title, COALESCE(p.vendor, ''), COALESCE(p.kb_id, ''),
			COALESCE(p.severity, 'UNKNOWN'), COALESCE(p.cve_ids, '{}'),
			p.requires_reboot, p.status, p.installed_at, p.detected_at
		FROM endpoint_patches_current p
		JOIN endpoint_agents a ON a.id = p.agent_id
		WHERE %s
		ORDER BY p.detected_at DESC, p.title ASC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	list := []models.EndpointPatchItem{}
	for rows.Next() {
		var item models.EndpointPatchItem
		var cveIDs []string
		err := rows.Scan(
			&item.ID, &item.AgentID, &item.AgentHostname, &item.AgentIP, &item.AgentOS,
			&item.PatchID, &item.Title, &item.Vendor, &item.KBID,
			&item.Severity, &cveIDs,
			&item.RequiresReboot, &item.Status, &item.InstalledAt, &item.DetectedAt,
		)
		if err == nil {
			item.CVEIDs = cveIDs
			list = append(list, item)
		}
	}

	return list, total, nil
}

// GetPatchComplianceSummary aggregates fleet patch compliance statistics
func (db *DB) GetPatchComplianceSummary(ctx context.Context, tenantSlug string) (*models.PatchComplianceSummary, error) {
	query := `
		SELECT 
			COUNT(*) as total_patches,
			COALESCE(COUNT(*) FILTER (WHERE p.status = 'installed'), 0) as installed_count,
			COALESCE(COUNT(*) FILTER (WHERE p.status = 'missing'), 0) as missing_count,
			COALESCE(COUNT(*) FILTER (WHERE p.requires_reboot = true), 0) as reboot_count,
			COALESCE(COUNT(DISTINCT p.agent_id) FILTER (WHERE p.requires_reboot = true), 0) as agents_need_reboot
		FROM endpoint_patches_current p
		WHERE ($1 = '' OR $1 = 'all' OR p.tenant_slug = $1)
	`

	var total, installed, missing, reboots, endpointsNeedReboot int
	err := db.pool.QueryRow(ctx, query, tenantSlug).Scan(
		&total, &installed, &missing, &reboots, &endpointsNeedReboot,
	)
	if err != nil {
		return nil, err
	}

	compliancePct := 100.0
	if total > 0 {
		compliancePct = float64(installed) / float64(total) * 100.0
	}

	return &models.PatchComplianceSummary{
		CompliancePct:       compliancePct,
		TotalPatches:        total,
		InstalledCount:      installed,
		MissingCount:        missing,
		PendingRebootsCount: reboots,
		EndpointsNeedReboot: endpointsNeedReboot,
	}, nil
}

