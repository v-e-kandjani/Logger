package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// EnsureUEBASchema creates tables and indexes for User & Entity Behavior Analytics
func (db *DB) EnsureUEBASchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS ueba_user_profiles (
			id BIGSERIAL PRIMARY KEY,
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			username VARCHAR(128) NOT NULL,
			primary_workstation VARCHAR(128) NOT NULL DEFAULT '',
			typical_login_window VARCHAR(64) NOT NULL DEFAULT '08:00-19:00',
			usual_cidrs TEXT[] NOT NULL DEFAULT '{}',
			baseline_daily_eps DOUBLE PRECISION NOT NULL DEFAULT 1.0,
			total_events BIGINT NOT NULL DEFAULT 0,
			hourly_histogram INT[] NOT NULL DEFAULT '{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}',
			last_seen_ip VARCHAR(64) NOT NULL DEFAULT '',
			last_seen_country VARCHAR(64) NOT NULL DEFAULT '',
			last_seen_city VARCHAR(64) NOT NULL DEFAULT '',
			last_seen_latitude DOUBLE PRECISION NOT NULL DEFAULT 0.0,
			last_seen_longitude DOUBLE PRECISION NOT NULL DEFAULT 0.0,
			last_seen_at TIMESTAMPTZ,
			first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_ueba_user UNIQUE (tenant_slug, username)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ueba_prof_tenant ON ueba_user_profiles(tenant_slug, updated_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_ueba_prof_user ON ueba_user_profiles(username);`,

		`CREATE TABLE IF NOT EXISTS ueba_risk_scores (
			id BIGSERIAL PRIMARY KEY,
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			username VARCHAR(128) NOT NULL,
			risk_score INT NOT NULL DEFAULT 0,
			risk_level VARCHAR(32) NOT NULL DEFAULT 'LOW',
			risk_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
			trend VARCHAR(32) NOT NULL DEFAULT 'STABLE',
			active_anomalies INT NOT NULL DEFAULT 0,
			last_evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			CONSTRAINT uq_ueba_risk UNIQUE (tenant_slug, username)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ueba_risk_score ON ueba_risk_scores(tenant_slug, risk_score DESC);`,

		`CREATE TABLE IF NOT EXISTS ueba_anomalies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_slug VARCHAR(64) NOT NULL DEFAULT 'default',
			username VARCHAR(128) NOT NULL,
			anomaly_type VARCHAR(64) NOT NULL,
			severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
			risk_points INT NOT NULL DEFAULT 15,
			title VARCHAR(255) NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			source_ip VARCHAR(64) NOT NULL DEFAULT '',
			device_name VARCHAR(128) NOT NULL DEFAULT '',
			evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
			detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ueba_anom_tenant_time ON ueba_anomalies(tenant_slug, detected_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_ueba_anom_user ON ueba_anomalies(username);`,
		`CREATE INDEX IF NOT EXISTS idx_ueba_anom_type ON ueba_anomalies(anomaly_type);`,
	}

	for _, q := range queries {
		if _, err := db.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("error executing ueba migration: %w", err)
		}
	}

	return nil
}

// GetUEBAUserProfile retrieves a behavioral profile for a given identity
func (db *DB) GetUEBAUserProfile(ctx context.Context, tenant, username string) (*models.UEBAUserProfile, error) {
	if tenant == "" {
		tenant = "default"
	}
	query := `
		SELECT id, tenant_slug, username, primary_workstation, typical_login_window, usual_cidrs,
		       baseline_daily_eps, total_events, hourly_histogram, last_seen_ip, last_seen_country,
		       last_seen_city, last_seen_latitude, last_seen_longitude, last_seen_at, first_seen_at, updated_at
		FROM ueba_user_profiles
		WHERE tenant_slug = $1 AND username = $2`

	var p models.UEBAUserProfile
	var hist []int
	err := db.pool.QueryRow(ctx, query, tenant, username).Scan(
		&p.ID, &p.TenantSlug, &p.Username, &p.PrimaryWorkstation, &p.TypicalLoginWindow, &p.UsualCIDRs,
		&p.BaselineDailyEPS, &p.TotalEvents, &hist, &p.LastSeenIP, &p.LastSeenCountry,
		&p.LastSeenCity, &p.LastSeenLatitude, &p.LastSeenLongitude, &p.LastSeenAt, &p.FirstSeenAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(hist) && i < 24; i++ {
		p.HourlyHistogram[i] = hist[i]
	}
	return &p, nil
}

// UpsertUEBAUserProfile saves or updates an identity baseline profile
func (db *DB) UpsertUEBAUserProfile(ctx context.Context, p *models.UEBAUserProfile) error {
	tenant := p.TenantSlug
	if tenant == "" {
		tenant = "default"
	}
	hist := make([]int, 24)
	for i := 0; i < 24; i++ {
		hist[i] = p.HourlyHistogram[i]
	}

	query := `
		INSERT INTO ueba_user_profiles (
			tenant_slug, username, primary_workstation, typical_login_window, usual_cidrs,
			baseline_daily_eps, total_events, hourly_histogram, last_seen_ip, last_seen_country,
			last_seen_city, last_seen_latitude, last_seen_longitude, last_seen_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
		ON CONFLICT (tenant_slug, username) DO UPDATE SET
			primary_workstation = CASE WHEN EXCLUDED.primary_workstation != '' THEN EXCLUDED.primary_workstation ELSE ueba_user_profiles.primary_workstation END,
			typical_login_window = EXCLUDED.typical_login_window,
			usual_cidrs = EXCLUDED.usual_cidrs,
			baseline_daily_eps = EXCLUDED.baseline_daily_eps,
			total_events = ueba_user_profiles.total_events + 1,
			hourly_histogram = EXCLUDED.hourly_histogram,
			last_seen_ip = EXCLUDED.last_seen_ip,
			last_seen_country = EXCLUDED.last_seen_country,
			last_seen_city = EXCLUDED.last_seen_city,
			last_seen_latitude = EXCLUDED.last_seen_latitude,
			last_seen_longitude = EXCLUDED.last_seen_longitude,
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = NOW()`

	_, err := db.pool.Exec(ctx, query,
		tenant, p.Username, p.PrimaryWorkstation, p.TypicalLoginWindow, p.UsualCIDRs,
		p.BaselineDailyEPS, p.TotalEvents, hist, p.LastSeenIP, p.LastSeenCountry,
		p.LastSeenCity, p.LastSeenLatitude, p.LastSeenLongitude, p.LastSeenAt,
	)
	return err
}

// RecordUEBAAnomaly logs an observed behavioral deviation and adjusts user risk score
func (db *DB) RecordUEBAAnomaly(ctx context.Context, a *models.UEBAAnomaly) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	tenant := a.TenantSlug
	if tenant == "" {
		tenant = "default"
	}
	evidenceJSON, _ := json.Marshal(a.Evidence)

	query := `
		INSERT INTO ueba_anomalies (
			id, tenant_slug, username, anomaly_type, severity, risk_points,
			title, description, source_ip, device_name, evidence, detected_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())`

	_, err := db.pool.Exec(ctx, query,
		a.ID, tenant, a.Username, a.AnomalyType, a.Severity, a.RiskPoints,
		a.Title, a.Description, a.SourceIP, a.DeviceName, evidenceJSON,
	)
	if err != nil {
		return err
	}

	// Increment or update risk score
	return db.addRiskPoints(ctx, tenant, a.Username, a.RiskPoints, a.Title)
}

func (db *DB) addRiskPoints(ctx context.Context, tenant, username string, points int, factor string) error {
	query := `
		INSERT INTO ueba_risk_scores (tenant_slug, username, risk_score, risk_level, risk_factors, trend, active_anomalies, last_evaluated_at, updated_at)
		VALUES ($1, $2, LEAST(100, $3), 'MEDIUM', jsonb_build_array($4), 'INCREASING', 1, NOW(), NOW())
		ON CONFLICT (tenant_slug, username) DO UPDATE SET
			risk_score = LEAST(100, ueba_risk_scores.risk_score + $3),
			risk_level = CASE
				WHEN (ueba_risk_scores.risk_score + $3) >= 80 THEN 'CRITICAL'
				WHEN (ueba_risk_scores.risk_score + $3) >= 60 THEN 'HIGH'
				WHEN (ueba_risk_scores.risk_score + $3) >= 30 THEN 'MEDIUM'
				ELSE 'LOW'
			END,
			risk_factors = CASE
				WHEN jsonb_array_length(ueba_risk_scores.risk_factors) > 8
				THEN ueba_risk_scores.risk_factors || jsonb_build_array($4)
				ELSE ueba_risk_scores.risk_factors || jsonb_build_array($4)
			END,
			trend = 'INCREASING',
			active_anomalies = ueba_risk_scores.active_anomalies + 1,
			last_evaluated_at = NOW(),
			updated_at = NOW()`

	_, err := db.pool.Exec(ctx, query, tenant, username, points, factor)
	return err
}

// DecayUEBARiskScores performs automated time decay on risk scores (e.g. -10% daily)
func (db *DB) DecayUEBARiskScores(ctx context.Context, decayFactor float64) error {
	query := `
		UPDATE ueba_risk_scores SET
			risk_score = GREATEST(0, FLOOR(risk_score * $1)),
			risk_level = CASE
				WHEN FLOOR(risk_score * $1) >= 80 THEN 'CRITICAL'
				WHEN FLOOR(risk_score * $1) >= 60 THEN 'HIGH'
				WHEN FLOOR(risk_score * $1) >= 30 THEN 'MEDIUM'
				ELSE 'LOW'
			END,
			trend = CASE
				WHEN risk_score > 0 THEN 'DECREASING'
				ELSE 'STABLE'
			END,
			updated_at = NOW()
		WHERE risk_score > 0`

	_, err := db.pool.Exec(ctx, query, decayFactor)
	return err
}

// ResetUEBARiskScore allows operators to acknowledge/clear risk for an account
func (db *DB) ResetUEBARiskScore(ctx context.Context, tenant, username string) error {
	if tenant == "" {
		tenant = "default"
	}
	query := `
		UPDATE ueba_risk_scores SET
			risk_score = 0,
			risk_level = 'LOW',
			risk_factors = '[]'::jsonb,
			trend = 'STABLE',
			active_anomalies = 0,
			updated_at = NOW()
		WHERE tenant_slug = $1 AND username = $2`

	_, err := db.pool.Exec(ctx, query, tenant, username)
	return err
}

// GetUEBARiskLeaderboard returns the highest risk users for the operations dashboard
func (db *DB) GetUEBARiskLeaderboard(ctx context.Context, tenant string, limit int) ([]models.UEBARiskLeaderboardItem, error) {
	if tenant == "" {
		tenant = "default"
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	query := `
		SELECT r.username, r.risk_score, r.risk_level, r.trend, r.active_anomalies,
		       COALESCE(r.risk_factors->>-1, 'Standard Activity') AS top_anomaly,
		       COALESCE(p.primary_workstation, '') AS primary_host,
		       COALESCE(p.last_seen_at, r.updated_at) AS last_seen_at
		FROM ueba_risk_scores r
		LEFT JOIN ueba_user_profiles p ON r.tenant_slug = p.tenant_slug AND r.username = p.username
		WHERE r.tenant_slug = $1
		ORDER BY r.risk_score DESC, r.updated_at DESC
		LIMIT $2`

	rows, err := db.pool.Query(ctx, query, tenant, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.UEBARiskLeaderboardItem
	for rows.Next() {
		var item models.UEBARiskLeaderboardItem
		if err := rows.Scan(
			&item.Username, &item.RiskScore, &item.RiskLevel, &item.Trend,
			&item.ActiveAnomalies, &item.TopAnomaly, &item.PrimaryHost, &item.LastSeenAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// ListUEBAAnomalies returns paginated detected anomalies with optional filtering
func (db *DB) ListUEBAAnomalies(ctx context.Context, tenant, username, anomalyType string, limit, offset int) ([]models.UEBAAnomaly, int, error) {
	if tenant == "" {
		tenant = "default"
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	countQuery := `
		SELECT COUNT(*)
		FROM ueba_anomalies
		WHERE tenant_slug = $1
		  AND ($2 = '' OR username ILIKE '%' || $2 || '%')
		  AND ($3 = '' OR anomaly_type = $3)`

	var total int
	_ = db.pool.QueryRow(ctx, countQuery, tenant, username, anomalyType).Scan(&total)

	query := `
		SELECT id, tenant_slug, username, anomaly_type, severity, risk_points,
		       title, description, source_ip, device_name, evidence, detected_at
		FROM ueba_anomalies
		WHERE tenant_slug = $1
		  AND ($2 = '' OR username ILIKE '%' || $2 || '%')
		  AND ($3 = '' OR anomaly_type = $3)
		ORDER BY detected_at DESC
		LIMIT $4 OFFSET $5`

	rows, err := db.pool.Query(ctx, query, tenant, username, anomalyType, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var anomalies []models.UEBAAnomaly
	for rows.Next() {
		var a models.UEBAAnomaly
		var evidenceJSON []byte
		if err := rows.Scan(
			&a.ID, &a.TenantSlug, &a.Username, &a.AnomalyType, &a.Severity, &a.RiskPoints,
			&a.Title, &a.Description, &a.SourceIP, &a.DeviceName, &evidenceJSON, &a.DetectedAt,
		); err != nil {
			return nil, 0, err
		}
		if len(evidenceJSON) > 0 {
			_ = json.Unmarshal(evidenceJSON, &a.Evidence)
		}
		anomalies = append(anomalies, a)
	}
	return anomalies, total, nil
}

// ListUEBAProfiles returns paginated behavioral profiles
func (db *DB) ListUEBAProfiles(ctx context.Context, tenant, search string, limit, offset int) ([]models.UEBAUserProfile, int, error) {
	if tenant == "" {
		tenant = "default"
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	countQuery := `
		SELECT COUNT(*)
		FROM ueba_user_profiles
		WHERE tenant_slug = $1
		  AND ($2 = '' OR username ILIKE '%' || $2 || '%' OR primary_workstation ILIKE '%' || $2 || '%')`

	var total int
	_ = db.pool.QueryRow(ctx, countQuery, tenant, search).Scan(&total)

	query := `
		SELECT id, tenant_slug, username, primary_workstation, typical_login_window, usual_cidrs,
		       baseline_daily_eps, total_events, hourly_histogram, last_seen_ip, last_seen_country,
		       last_seen_city, last_seen_latitude, last_seen_longitude, last_seen_at, first_seen_at, updated_at
		FROM ueba_user_profiles
		WHERE tenant_slug = $1
		  AND ($2 = '' OR username ILIKE '%' || $2 || '%' OR primary_workstation ILIKE '%' || $2 || '%')
		ORDER BY total_events DESC, updated_at DESC
		LIMIT $3 OFFSET $4`

	rows, err := db.pool.Query(ctx, query, tenant, search, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var profiles []models.UEBAUserProfile
	for rows.Next() {
		var p models.UEBAUserProfile
		var hist []int
		if err := rows.Scan(
			&p.ID, &p.TenantSlug, &p.Username, &p.PrimaryWorkstation, &p.TypicalLoginWindow, &p.UsualCIDRs,
			&p.BaselineDailyEPS, &p.TotalEvents, &hist, &p.LastSeenIP, &p.LastSeenCountry,
			&p.LastSeenCity, &p.LastSeenLatitude, &p.LastSeenLongitude, &p.LastSeenAt, &p.FirstSeenAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		for i := 0; i < len(hist) && i < 24; i++ {
			p.HourlyHistogram[i] = hist[i]
		}
		profiles = append(profiles, p)
	}
	return profiles, total, nil
}

// GetUEBAStats calculates aggregate KPI metrics for UEBA
func (db *DB) GetUEBAStats(ctx context.Context, tenant string) (*models.UEBAStats, error) {
	if tenant == "" {
		tenant = "default"
	}
	var stats models.UEBAStats

	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ueba_user_profiles WHERE tenant_slug = $1`, tenant).Scan(&stats.MonitoredUsers)
	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ueba_risk_scores WHERE tenant_slug = $1 AND risk_score >= 60`, tenant).Scan(&stats.HighRiskUsers)
	_ = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ueba_anomalies WHERE tenant_slug = $1 AND detected_at >= CURRENT_DATE`, tenant).Scan(&stats.AnomaliesToday)
	_ = db.pool.QueryRow(ctx, `SELECT COALESCE(ROUND(AVG(risk_score)), 0) FROM ueba_risk_scores WHERE tenant_slug = $1`, tenant).Scan(&stats.AverageRiskScore)

	return &stats, nil
}
