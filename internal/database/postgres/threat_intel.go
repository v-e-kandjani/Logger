package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/syslog-platform/logger/internal/models"
)

// EnsureThreatIntelSchema initializes tables and default feeds for Threat Intelligence (Phase Q)
func (db *DB) EnsureThreatIntelSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS ti_feeds (
			id SERIAL PRIMARY KEY,
			name VARCHAR(128) NOT NULL UNIQUE,
			feed_type VARCHAR(64) NOT NULL DEFAULT 'plain_list',
			url TEXT NOT NULL,
			api_key TEXT NOT NULL DEFAULT '',
			poll_interval_minutes INT NOT NULL DEFAULT 60,
			is_enabled BOOLEAN NOT NULL DEFAULT true,
			indicator_type VARCHAR(32) NOT NULL DEFAULT 'ip',
			threat_category VARCHAR(64) NOT NULL DEFAULT 'botnet_c2',
			default_confidence INT NOT NULL DEFAULT 85,
			last_sync_at TIMESTAMPTZ,
			last_status VARCHAR(32) NOT NULL DEFAULT 'IDLE',
			indicator_count INT NOT NULL DEFAULT 0,
			error_message TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS ti_indicators (
			id BIGSERIAL PRIMARY KEY,
			feed_id INT REFERENCES ti_feeds(id) ON DELETE CASCADE,
			indicator_type VARCHAR(32) NOT NULL,
			indicator_value VARCHAR(512) NOT NULL,
			threat_category VARCHAR(64) NOT NULL DEFAULT 'malware',
			severity VARCHAR(32) NOT NULL DEFAULT 'high',
			confidence INT NOT NULL DEFAULT 80,
			description TEXT NOT NULL DEFAULT '',
			source VARCHAR(128) NOT NULL DEFAULT '',
			expires_at TIMESTAMPTZ,
			first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			is_active BOOLEAN NOT NULL DEFAULT true,
			CONSTRAINT uq_ti_ind_type_val UNIQUE (indicator_type, indicator_value)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ti_ind_type_val ON ti_indicators(indicator_type, indicator_value);`,
		`CREATE INDEX IF NOT EXISTS idx_ti_ind_active ON ti_indicators(is_active) WHERE is_active = true;`,
		`CREATE INDEX IF NOT EXISTS idx_ti_ind_feed ON ti_indicators(feed_id);`,
		`CREATE TABLE IF NOT EXISTS ti_matches (
			id BIGSERIAL PRIMARY KEY,
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			indicator_id BIGINT REFERENCES ti_indicators(id) ON DELETE SET NULL,
			indicator_type VARCHAR(32) NOT NULL,
			indicator_value VARCHAR(512) NOT NULL,
			threat_category VARCHAR(64) NOT NULL DEFAULT '',
			severity VARCHAR(32) NOT NULL DEFAULT 'high',
			source_type VARCHAR(64) NOT NULL DEFAULT 'syslog',
			source_ip VARCHAR(64) NOT NULL DEFAULT '',
			destination_ip VARCHAR(64) NOT NULL DEFAULT '',
			domain VARCHAR(255) NOT NULL DEFAULT '',
			file_hash VARCHAR(128) NOT NULL DEFAULT '',
			device_name VARCHAR(128) NOT NULL DEFAULT '',
			host_identifier VARCHAR(128) NOT NULL DEFAULT '',
			matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			siem_alert_id VARCHAR(64) NOT NULL DEFAULT '',
			raw_event_summary TEXT NOT NULL DEFAULT '',
			action_taken VARCHAR(64) NOT NULL DEFAULT 'ALERT'
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ti_matches_tenant_time ON ti_matches(tenant_slug, matched_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_ti_matches_val ON ti_matches(indicator_value);`,
	}

	for _, q := range queries {
		if _, err := db.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("error executing ti migration: %w", err)
		}
	}

	// Seed default threat feeds if none exist
	var count int
	if err := db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM ti_feeds").Scan(&count); err == nil && count == 0 {
		defaultFeeds := []struct {
			name        string
			feedType    string
			url         string
			pollMin     int
			indType     string
			category    string
			confidence  int
		}{
			{"CISA Known Exploited Vulnerabilities (KEV)", "cisa_kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 360, "mixed", "vulnerability_exploit", 95},
			{"URLhaus Recent Malware URLs & Domains", "csv", "https://urlhaus.abuse.ch/downloads/csv_recent/", 60, "domain", "malicious_url_domain", 90},
			{"Tor Exit Nodes Blocklist", "plain_list", "https://check.torproject.org/torbulkexitlist", 120, "ip", "anonymizer_tor", 85},
			{"Emerging Threats Compromised IPs", "plain_list", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 120, "ip", "compromised_host", 85},
			{"Feodo Tracker Botnet C2 IP Blocklist", "plain_list", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", 120, "ip", "botnet_c2", 95},
			{"AbuseIPDB Verified Blacklist", "abuseipdb", "https://api.abuseipdb.com/api/v2/blacklist", 240, "ip", "botnet_c2", 90},
		}

		for _, f := range defaultFeeds {
			_, _ = db.pool.Exec(ctx, `
				INSERT INTO ti_feeds (name, feed_type, url, poll_interval_minutes, is_enabled, indicator_type, threat_category, default_confidence)
				VALUES ($1, $2, $3, $4, true, $5, $6, $7)
				ON CONFLICT (name) DO NOTHING`,
				f.name, f.feedType, f.url, f.pollMin, f.indType, f.category, f.confidence)
		}
	}

	return nil
}

// ListTIFeeds returns all configured threat intelligence feeds
func (db *DB) ListTIFeeds(ctx context.Context) ([]models.TIFeed, error) {
	query := `
		SELECT id, name, feed_type, url, COALESCE(api_key, ''), poll_interval_minutes, is_enabled,
		       indicator_type, threat_category, default_confidence, last_sync_at, last_status,
		       indicator_count, COALESCE(error_message, ''), created_at, updated_at
		FROM ti_feeds
		ORDER BY id ASC`

	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var feeds []models.TIFeed
	for rows.Next() {
		var f models.TIFeed
		if err := rows.Scan(
			&f.ID, &f.Name, &f.FeedType, &f.URL, &f.APIKey, &f.PollIntervalMinutes, &f.IsEnabled,
			&f.IndicatorType, &f.ThreatCategory, &f.DefaultConfidence, &f.LastSyncAt, &f.LastStatus,
			&f.IndicatorCount, &f.ErrorMessage, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, err
		}
		feeds = append(feeds, f)
	}
	return feeds, nil
}

// GetTIFeed retrieves a single threat feed by ID
func (db *DB) GetTIFeed(ctx context.Context, id int) (*models.TIFeed, error) {
	query := `
		SELECT id, name, feed_type, url, COALESCE(api_key, ''), poll_interval_minutes, is_enabled,
		       indicator_type, threat_category, default_confidence, last_sync_at, last_status,
		       indicator_count, COALESCE(error_message, ''), created_at, updated_at
		FROM ti_feeds
		WHERE id = $1`

	var f models.TIFeed
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&f.ID, &f.Name, &f.FeedType, &f.URL, &f.APIKey, &f.PollIntervalMinutes, &f.IsEnabled,
		&f.IndicatorType, &f.ThreatCategory, &f.DefaultConfidence, &f.LastSyncAt, &f.LastStatus,
		&f.IndicatorCount, &f.ErrorMessage, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// CreateTIFeed inserts a new threat feed
func (db *DB) CreateTIFeed(ctx context.Context, f *models.TIFeed) error {
	query := `
		INSERT INTO ti_feeds (
			name, feed_type, url, api_key, poll_interval_minutes, is_enabled,
			indicator_type, threat_category, default_confidence, last_status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'IDLE')
		RETURNING id, created_at, updated_at`

	return db.pool.QueryRow(ctx, query,
		f.Name, f.FeedType, f.URL, f.APIKey, f.PollIntervalMinutes, f.IsEnabled,
		f.IndicatorType, f.ThreatCategory, f.DefaultConfidence,
	).Scan(&f.ID, &f.CreatedAt, &f.UpdatedAt)
}

// UpdateTIFeed updates feed metadata
func (db *DB) UpdateTIFeed(ctx context.Context, f *models.TIFeed) error {
	query := `
		UPDATE ti_feeds SET
			name = $1, feed_type = $2, url = $3, api_key = $4,
			poll_interval_minutes = $5, is_enabled = $6, indicator_type = $7,
			threat_category = $8, default_confidence = $9, updated_at = NOW()
		WHERE id = $10`

	_, err := db.pool.Exec(ctx, query,
		f.Name, f.FeedType, f.URL, f.APIKey, f.PollIntervalMinutes, f.IsEnabled,
		f.IndicatorType, f.ThreatCategory, f.DefaultConfidence, f.ID,
	)
	return err
}

// DeleteTIFeed deletes a threat feed and all its cascaded indicators
func (db *DB) DeleteTIFeed(ctx context.Context, id int) error {
	_, err := db.pool.Exec(ctx, "DELETE FROM ti_feeds WHERE id = $1", id)
	return err
}

// UpdateTIFeedSyncStatus updates status, last sync timestamp, and indicator count of a feed
func (db *DB) UpdateTIFeedSyncStatus(ctx context.Context, id int, status, errMsg string, count int) error {
	var query string
	if status == "SUCCESS" {
		query = `
			UPDATE ti_feeds SET
				last_sync_at = NOW(),
				last_status = $2,
				indicator_count = $3,
				error_message = '',
				updated_at = NOW()
			WHERE id = $1`
		_, err := db.pool.Exec(ctx, query, id, status, count)
		return err
	}
	query = `
		UPDATE ti_feeds SET
			last_status = $2,
			error_message = $3,
			updated_at = NOW()
		WHERE id = $1`
	_, err := db.pool.Exec(ctx, query, id, status, errMsg)
	return err
}

// UpsertTIIndicatorsBatch batch upserts threat indicators using pgx batching
func (db *DB) UpsertTIIndicatorsBatch(ctx context.Context, feedID int, indicators []models.TIIndicator) (int, error) {
	if len(indicators) == 0 {
		return 0, nil
	}

	batch := &pgx.Batch{}
	query := `
		INSERT INTO ti_indicators (
			feed_id, indicator_type, indicator_value, threat_category, severity,
			confidence, description, source, expires_at, first_seen, last_seen, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW(), true)
		ON CONFLICT (indicator_type, indicator_value) DO UPDATE SET
			feed_id = EXCLUDED.feed_id,
			threat_category = EXCLUDED.threat_category,
			severity = EXCLUDED.severity,
			confidence = EXCLUDED.confidence,
			description = EXCLUDED.description,
			source = EXCLUDED.source,
			expires_at = EXCLUDED.expires_at,
			last_seen = NOW(),
			is_active = true`

	for _, ind := range indicators {
		batch.Queue(query,
			feedID, ind.IndicatorType, ind.IndicatorValue, ind.ThreatCategory, ind.Severity,
			ind.Confidence, ind.Description, ind.Source, ind.ExpiresAt,
		)
	}

	br := db.pool.SendBatch(ctx, batch)
	defer br.Close()

	insertedCount := 0
	for i := 0; i < len(indicators); i++ {
		_, err := br.Exec()
		if err == nil {
			insertedCount++
		}
	}

	return insertedCount, nil
}

// LoadActiveIndicatorsForCache loads all active and non-expired indicators for memory matcher
func (db *DB) LoadActiveIndicatorsForCache(ctx context.Context) ([]models.TIIndicator, error) {
	query := `
		SELECT id, feed_id, indicator_type, indicator_value, threat_category, severity,
		       confidence, description, source, expires_at, first_seen, last_seen, is_active
		FROM ti_indicators
		WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY id ASC`

	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var indicators []models.TIIndicator
	for rows.Next() {
		var ind models.TIIndicator
		if err := rows.Scan(
			&ind.ID, &ind.FeedID, &ind.IndicatorType, &ind.IndicatorValue, &ind.ThreatCategory, &ind.Severity,
			&ind.Confidence, &ind.Description, &ind.Source, &ind.ExpiresAt, &ind.FirstSeen, &ind.LastSeen, &ind.IsActive,
		); err != nil {
			return nil, err
		}
		indicators = append(indicators, ind)
	}
	return indicators, nil
}

// IndicatorFilter represents search and filtering criteria for indicators
type IndicatorFilter struct {
	IndicatorType string
	Severity      string
	Search        string
	FeedID        int
	Limit         int
	Offset        int
}

// ListTIIndicators returns paginated threat indicators with optional filters
func (db *DB) ListTIIndicators(ctx context.Context, filter IndicatorFilter) ([]models.TIIndicator, int, error) {
	if filter.Limit <= 0 || filter.Limit > 200 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}

	var where []string
	var args []interface{}
	idx := 1

	if filter.IndicatorType != "" && filter.IndicatorType != "all" {
		where = append(where, fmt.Sprintf("i.indicator_type = $%d", idx))
		args = append(args, strings.ToLower(filter.IndicatorType))
		idx++
	}
	if filter.Severity != "" && filter.Severity != "all" {
		where = append(where, fmt.Sprintf("LOWER(i.severity) = $%d", idx))
		args = append(args, strings.ToLower(filter.Severity))
		idx++
	}
	if filter.FeedID > 0 {
		where = append(where, fmt.Sprintf("i.feed_id = $%d", idx))
		args = append(args, filter.FeedID)
		idx++
	}
	if filter.Search != "" {
		where = append(where, fmt.Sprintf("(i.indicator_value ILIKE $%d OR i.description ILIKE $%d OR i.source ILIKE $%d)", idx, idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM ti_indicators i %s", whereClause)
	var total int
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT i.id, i.feed_id, COALESCE(f.name, 'Manual Entry'), i.indicator_type, i.indicator_value,
		       i.threat_category, i.severity, i.confidence, i.description, i.source,
		       i.expires_at, i.first_seen, i.last_seen, i.is_active
		FROM ti_indicators i
		LEFT JOIN ti_feeds f ON i.feed_id = f.id
		%s
		ORDER BY i.last_seen DESC
		LIMIT $%d OFFSET $%d`, whereClause, idx, idx+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var indicators []models.TIIndicator
	for rows.Next() {
		var ind models.TIIndicator
		if err := rows.Scan(
			&ind.ID, &ind.FeedID, &ind.FeedName, &ind.IndicatorType, &ind.IndicatorValue,
			&ind.ThreatCategory, &ind.Severity, &ind.Confidence, &ind.Description, &ind.Source,
			&ind.ExpiresAt, &ind.FirstSeen, &ind.LastSeen, &ind.IsActive,
		); err != nil {
			return nil, 0, err
		}
		indicators = append(indicators, ind)
	}

	return indicators, total, nil
}

// CreateTIIndicator adds a manual threat indicator
func (db *DB) CreateTIIndicator(ctx context.Context, ind *models.TIIndicator) error {
	query := `
		INSERT INTO ti_indicators (
			feed_id, indicator_type, indicator_value, threat_category, severity,
			confidence, description, source, expires_at, first_seen, last_seen, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW(), true)
		ON CONFLICT (indicator_type, indicator_value) DO UPDATE SET
			threat_category = EXCLUDED.threat_category,
			severity = EXCLUDED.severity,
			confidence = EXCLUDED.confidence,
			description = EXCLUDED.description,
			source = EXCLUDED.source,
			expires_at = EXCLUDED.expires_at,
			last_seen = NOW(),
			is_active = true
		RETURNING id`

	return db.pool.QueryRow(ctx, query,
		ind.FeedID, strings.ToLower(ind.IndicatorType), ind.IndicatorValue, ind.ThreatCategory,
		strings.ToLower(ind.Severity), ind.Confidence, ind.Description, ind.Source, ind.ExpiresAt,
	).Scan(&ind.ID)
}

// DeleteTIIndicator removes an individual indicator
func (db *DB) DeleteTIIndicator(ctx context.Context, id int64) error {
	_, err := db.pool.Exec(ctx, "DELETE FROM ti_indicators WHERE id = $1", id)
	return err
}

// RecordTIMatch logs a threat intelligence match event
func (db *DB) RecordTIMatch(ctx context.Context, m *models.TIMatch) error {
	if m.TenantSlug == "" {
		m.TenantSlug = "default"
	}
	query := `
		INSERT INTO ti_matches (
			tenant_slug, indicator_id, indicator_type, indicator_value, threat_category,
			severity, source_type, source_ip, destination_ip, domain, file_hash,
			device_name, host_identifier, matched_at, siem_alert_id, raw_event_summary, action_taken
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), $14, $15, $16)
		RETURNING id, matched_at`

	return db.pool.QueryRow(ctx, query,
		m.TenantSlug, m.IndicatorID, m.IndicatorType, m.IndicatorValue, m.ThreatCategory,
		m.Severity, m.SourceType, m.SourceIP, m.DestinationIP, m.Domain, m.FileHash,
		m.DeviceName, m.HostIdentifier, m.SIEMAlertID, m.RawEventSummary, m.ActionTaken,
	).Scan(&m.ID, &m.MatchedAt)
}

// ListTIMatches returns recent match audit records for a tenant
func (db *DB) ListTIMatches(ctx context.Context, tenantSlug string, limit, offset int) ([]models.TIMatch, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	whereClause := ""
	var args []interface{}
	idx := 1

	if tenantSlug != "" && tenantSlug != "all" && tenantSlug != "*" {
		whereClause = fmt.Sprintf("WHERE tenant_slug = $%d", idx)
		args = append(args, tenantSlug)
		idx++
	}

	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM ti_matches %s", whereClause)
	if err := db.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_slug, indicator_id, indicator_type, indicator_value, threat_category,
		       severity, source_type, source_ip, destination_ip, domain, file_hash,
		       device_name, host_identifier, matched_at, siem_alert_id, raw_event_summary, action_taken
		FROM ti_matches
		%s
		ORDER BY matched_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, idx, idx+1)

	args = append(args, limit, offset)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var matches []models.TIMatch
	for rows.Next() {
		var m models.TIMatch
		if err := rows.Scan(
			&m.ID, &m.TenantSlug, &m.IndicatorID, &m.IndicatorType, &m.IndicatorValue, &m.ThreatCategory,
			&m.Severity, &m.SourceType, &m.SourceIP, &m.DestinationIP, &m.Domain, &m.FileHash,
			&m.DeviceName, &m.HostIdentifier, &m.MatchedAt, &m.SIEMAlertID, &m.RawEventSummary, &m.ActionTaken,
		); err != nil {
			return nil, 0, err
		}
		matches = append(matches, m)
	}

	return matches, total, nil
}

// GetTIStats aggregates executive KPIs and distributions for Threat Intelligence
func (db *DB) GetTIStats(ctx context.Context, tenantSlug string) (*models.TIStats, error) {
	stats := &models.TIStats{
		IndicatorsByType:  make(map[string]int),
		MatchesBySeverity: make(map[string]int),
	}

	// 1. Total Indicators & High/Critical Count
	_ = db.pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE LOWER(severity) IN ('high', 'critical'))
		FROM ti_indicators
		WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW())
	`).Scan(&stats.TotalIndicators, &stats.HighCriticalIOCs)

	// 2. Active Feeds Count
	_ = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM ti_feeds WHERE is_enabled = true").Scan(&stats.ActiveFeeds)

	// 3. Matches Today (tenant-scoped)
	matchesWhere := "WHERE matched_at >= DATE_TRUNC('day', NOW())"
	var args []interface{}
	if tenantSlug != "" && tenantSlug != "all" && tenantSlug != "*" {
		matchesWhere += " AND tenant_slug = $1"
		args = append(args, tenantSlug)
	}
	_ = db.pool.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM ti_matches %s", matchesWhere), args...).Scan(&stats.MatchesToday)

	// 4. Indicators by Type
	indRows, err := db.pool.Query(ctx, `
		SELECT indicator_type, COUNT(*)
		FROM ti_indicators
		WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW())
		GROUP BY indicator_type`)
	if err == nil {
		defer indRows.Close()
		for indRows.Next() {
			var t string
			var c int
			if err := indRows.Scan(&t, &c); err == nil {
				stats.IndicatorsByType[t] = c
			}
		}
	}

	// 5. Matches by Severity
	sevRows, err := db.pool.Query(ctx, fmt.Sprintf(`
		SELECT LOWER(severity), COUNT(*)
		FROM ti_matches
		%s
		GROUP BY LOWER(severity)`, matchesWhere), args...)
	if err == nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var s string
			var c int
			if err := sevRows.Scan(&s, &c); err == nil {
				stats.MatchesBySeverity[s] = c
			}
		}
	}

	return stats, nil
}
