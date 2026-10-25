package ueba

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
)

// SIEMDispatcher provides an interface to emit direct security alerts
type SIEMDispatcher interface {
	DispatchDirectAlert(alert *models.SIEMAlert)
}

// Engine orchestrates User & Entity Behavior Analytics
type Engine struct {
	db             *postgres.DB
	temporal       *TemporalEvaluator
	siemDispatcher SIEMDispatcher

	// In-memory cache of active user profiles to avoid constant DB roundtrips on hot packet paths
	cacheMu  sync.RWMutex
	profiles map[string]*models.UEBAUserProfile // key: "tenant:username"

	stopChan chan struct{}
}

// NewEngine initializes the UEBA analytics engine
func NewEngine(db *postgres.DB) *Engine {
	return &Engine{
		db:       db,
		temporal: NewTemporalEvaluator(),
		profiles: make(map[string]*models.UEBAUserProfile),
		stopChan: make(chan struct{}),
	}
}

// SetSIEMDispatcher wires the SIEM alert emission engine
func (e *Engine) SetSIEMDispatcher(dispatcher SIEMDispatcher) {
	e.siemDispatcher = dispatcher
}

// Start begins background maintenance routines (hourly risk score decay and cache grooming)
func (e *Engine) Start() {
	go e.runDecayTicker()
	log.Println("[UEBA] Behavioral Analytics & Dynamic Risk Scoring Engine active")
}

// Stop terminates background tickers
func (e *Engine) Stop() {
	close(e.stopChan)
}

func (e *Engine) runDecayTicker() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Apply a 5% decay every 6 hours (~20% decay per 24 hours of clean activity)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := e.db.DecayUEBARiskScores(ctx, 0.95); err != nil {
				log.Printf("[UEBA] Error running risk score decay: %v", err)
			}
			cancel()
		case <-e.stopChan:
			return
		}
	}
}

// ProcessEvent analyzes an incoming identity action for behavioral anomalies
func (e *Engine) ProcessEvent(ctx context.Context, tenant, username, sourceIP, deviceName, action, message string, eventTime time.Time) {
	username = strings.TrimSpace(username)
	if username == "" || username == "-" || username == "unknown" {
		return
	}
	if tenant == "" {
		tenant = "default"
	}
	if eventTime.IsZero() {
		eventTime = time.Now()
	}

	key := fmt.Sprintf("%s:%s", tenant, username)

	e.cacheMu.RLock()
	prof, found := e.profiles[key]
	e.cacheMu.RUnlock()

	if !found {
		// Attempt load from Postgres or initialize
		dbProf, err := e.db.GetUEBAUserProfile(ctx, tenant, username)
		if err == nil && dbProf != nil {
			prof = dbProf
		} else {
			geo := ResolveIPGeo(sourceIP)
			now := eventTime
			prof = &models.UEBAUserProfile{
				TenantSlug:         tenant,
				Username:           username,
				PrimaryWorkstation: deviceName,
				TypicalLoginWindow: "08:00-19:00",
				UsualCIDRs:         []string{},
				BaselineDailyEPS:   1.0,
				TotalEvents:        0,
				LastSeenIP:         sourceIP,
				LastSeenCountry:    geo.Country,
				LastSeenCity:       geo.City,
				LastSeenLatitude:   geo.Latitude,
				LastSeenLongitude:  geo.Longitude,
				LastSeenAt:         &now,
				FirstSeenAt:        now,
				UpdatedAt:          now,
			}
		}
		e.cacheMu.Lock()
		e.profiles[key] = prof
		e.cacheMu.Unlock()
	}

	// 1. Detect Impossible Travel / Geo-Velocity
	curGeo := ResolveIPGeo(sourceIP)
	if prof.LastSeenAt != nil && prof.LastSeenIP != "" && sourceIP != "" && prof.LastSeenIP != sourceIP {
		diff := eventTime.Sub(*prof.LastSeenAt)
		if diff > 0 && diff < 12*time.Hour {
			velocity := CalculateVelocityKmPerHour(
				prof.LastSeenLatitude, prof.LastSeenLongitude,
				curGeo.Latitude, curGeo.Longitude,
				*prof.LastSeenAt, eventTime,
			)

			dist := HaversineDistance(prof.LastSeenLatitude, prof.LastSeenLongitude, curGeo.Latitude, curGeo.Longitude)
			if dist > 300 && velocity > 900 {
				e.recordAnomaly(ctx, &models.UEBAAnomaly{
					TenantSlug:  tenant,
					Username:    username,
					AnomalyType: "IMPOSSIBLE_TRAVEL",
					Severity:    "CRITICAL",
					RiskPoints:  40,
					Title:       fmt.Sprintf("Impossible Travel Detected for %s", username),
					Description: fmt.Sprintf("User relocated %.0f km from %s (%s) to %s (%s) in %.1f minutes (implied speed: %.0f km/h)",
						dist, prof.LastSeenCity, prof.LastSeenCountry, curGeo.City, curGeo.Country, diff.Minutes(), velocity),
					SourceIP:   sourceIP,
					DeviceName: deviceName,
					Evidence: map[string]interface{}{
						"previous_ip":       prof.LastSeenIP,
						"previous_location": fmt.Sprintf("%s, %s", prof.LastSeenCity, prof.LastSeenCountry),
						"current_ip":        sourceIP,
						"current_location":  fmt.Sprintf("%s, %s", curGeo.City, curGeo.Country),
						"distance_km":       dist,
						"velocity_kmh":      velocity,
						"time_delta_mins":   diff.Minutes(),
					},
					DetectedAt: eventTime,
				})
			}
		}
	}

	// 2. Detect Dormant Account Reactivation
	if prof.LastSeenAt != nil {
		dormantDuration := eventTime.Sub(*prof.LastSeenAt)
		if dormantDuration > 30*24*time.Hour && prof.TotalEvents > 10 {
			e.recordAnomaly(ctx, &models.UEBAAnomaly{
				TenantSlug:  tenant,
				Username:    username,
				AnomalyType: "DORMANT_ACCOUNT",
				Severity:    "HIGH",
				RiskPoints:  25,
				Title:       fmt.Sprintf("Dormant Account Reactivated: %s", username),
				Description: fmt.Sprintf("Identity %s logged in after %.0f days of total inactivity", username, dormantDuration.Hours()/24),
				SourceIP:    sourceIP,
				DeviceName:  deviceName,
				Evidence: map[string]interface{}{
					"inactive_days": dormantDuration.Hours() / 24,
					"previous_seen": prof.LastSeenAt.Format(time.RFC3339),
				},
				DetectedAt: eventTime,
			})
		}
	}

	// 3. Detect Suspicious Off-Hours Administrative Activity
	isOffHours := e.temporal.IsOffHoursAccess(eventTime)
	isAdminAction := strings.Contains(strings.ToLower(action), "admin") ||
		strings.Contains(strings.ToLower(action), "sudo") ||
		strings.Contains(strings.ToLower(message), "privilege") ||
		strings.Contains(strings.ToLower(message), "useradd") ||
		strings.Contains(strings.ToLower(message), "password")

	if isOffHours && isAdminAction {
		isDrift, prob, driftDesc := e.temporal.EvaluateDrift(eventTime.Hour(), prof.HourlyHistogram, prof.TotalEvents)
		if isDrift {
			e.recordAnomaly(ctx, &models.UEBAAnomaly{
				TenantSlug:  tenant,
				Username:    username,
				AnomalyType: "OFF_HOURS",
				Severity:    "HIGH",
				RiskPoints:  25,
				Title:       fmt.Sprintf("Off-Hours Administrative Action: %s", username),
				Description: fmt.Sprintf("Administrative operation conducted at %02d:%02d: %s", eventTime.Hour(), eventTime.Minute(), driftDesc),
				SourceIP:    sourceIP,
				DeviceName:  deviceName,
				Evidence: map[string]interface{}{
					"hour":        eventTime.Hour(),
					"probability": prob,
					"action":      action,
					"message":     message,
				},
				DetectedAt: eventTime,
			})
		}
	}

	// Update in-memory and DB profile
	h := eventTime.Hour()
	if h >= 0 && h < 24 {
		prof.HourlyHistogram[h]++
	}
	prof.TotalEvents++
	prof.LastSeenIP = sourceIP
	prof.LastSeenCountry = curGeo.Country
	prof.LastSeenCity = curGeo.City
	prof.LastSeenLatitude = curGeo.Latitude
	prof.LastSeenLongitude = curGeo.Longitude
	now := eventTime
	prof.LastSeenAt = &now
	prof.UpdatedAt = now

	// Save profile to database asynchronously to avoid blocking packet pipeline
	go func(p models.UEBAUserProfile) {
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.db.UpsertUEBAUserProfile(ctxTimeout, &p)
	}(*prof)
}

func (e *Engine) recordAnomaly(ctx context.Context, a *models.UEBAAnomaly) {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if err := e.db.RecordUEBAAnomaly(ctx, a); err != nil {
		log.Printf("[UEBA] Error recording anomaly: %v", err)
	}

	// Dispatch SIEM Alert for High and Critical behavioral anomalies
	if e.siemDispatcher != nil && (a.Severity == "HIGH" || a.Severity == "CRITICAL") {
		ruleID := "UEBA-ANOMALY-" + a.AnomalyType
		if a.AnomalyType == "IMPOSSIBLE_TRAVEL" {
			ruleID = "UEBA-IMPOSSIBLE-TRAVEL"
		} else if a.AnomalyType == "OFF_HOURS" {
			ruleID = "UEBA-SUSPICIOUS-OFFHOURS-ADMIN"
		}

		alert := &models.SIEMAlert{
			ID:             uuid.New(),
			RuleID:         ruleID,
			RuleName:       a.Title,
			Severity:       a.Severity,
			RiskScore:      a.RiskPoints * 2,
			Category:       "ueba_insider_threat",
			Status:         "NEW",
			SourceIP:       a.SourceIP,
			DestinationIP:  "",
			Username:       a.Username,
			DeviceName:     a.DeviceName,
			EventCount:     1,
			FirstSeen:      a.DetectedAt,
			LastSeen:       a.DetectedAt,
			MitreTactic:    "Initial Access / Lateral Movement",
			MitreTechnique: "T1078",
			Summary:        a.Description,
			Tenant:         a.TenantSlug,
			CreatedAt:      a.DetectedAt,
			UpdatedAt:      a.DetectedAt,
			EvidenceLogs: []string{
				fmt.Sprintf("UEBA Anomaly %s: %s (Severity: %s, RiskPoints: +%d, Source: %s)", a.AnomalyType, a.Title, a.Severity, a.RiskPoints, a.SourceIP),
			},
		}
		e.siemDispatcher.DispatchDirectAlert(alert)
	}
}

// SimulateAnomaly allows operators to inject synthetic anomalies for verification
func (e *Engine) SimulateAnomaly(ctx context.Context, tenant, username, anomalyType, sourceIP, deviceName string) (*models.UEBAAnomaly, error) {
	if username == "" {
		username = "sec-admin"
	}
	if tenant == "" {
		tenant = "default"
	}
	if sourceIP == "" {
		sourceIP = "198.51.100.42"
	}
	if deviceName == "" {
		deviceName = "FINANCE-SRV01"
	}

	now := time.Now()
	var a models.UEBAAnomaly

	switch anomalyType {
	case "IMPOSSIBLE_TRAVEL":
		a = models.UEBAAnomaly{
			TenantSlug:  tenant,
			Username:    username,
			AnomalyType: "IMPOSSIBLE_TRAVEL",
			Severity:    "CRITICAL",
			RiskPoints:  40,
			Title:       fmt.Sprintf("Simulated: Impossible Travel Detected for %s", username),
			Description: fmt.Sprintf("Identity %s authenticated from New York, United States (40.71, -74.00) 15 minutes after authentication from Istanbul, Turkey (41.01, 28.98). Implied velocity: 3,210 km/h.", username),
			SourceIP:    sourceIP,
			DeviceName:  deviceName,
			Evidence: map[string]interface{}{
				"origin_city":        "Istanbul",
				"origin_country":     "Turkey",
				"destination_city":   "New York",
				"destination_country":"United States",
				"implied_velocity":   3210,
				"delta_minutes":      15,
				"simulation":         true,
			},
			DetectedAt: now,
		}
	case "OFF_HOURS":
		a = models.UEBAAnomaly{
			TenantSlug:  tenant,
			Username:    username,
			AnomalyType: "OFF_HOURS",
			Severity:    "HIGH",
			RiskPoints:  25,
			Title:       fmt.Sprintf("Simulated: Off-Hours Privilege Escalation by %s", username),
			Description: fmt.Sprintf("Identity %s executed sudo group elevation at 03:22 AM on Sunday, deviating from historical baseline (P = 0.3%%).", username),
			SourceIP:    sourceIP,
			DeviceName:  deviceName,
			Evidence: map[string]interface{}{
				"hour":         3,
				"action":       "sudo /bin/bash",
				"baseline_pct": 0.3,
				"simulation":   true,
			},
			DetectedAt: now,
		}
	case "DORMANT_ACCOUNT":
		a = models.UEBAAnomaly{
			TenantSlug:  tenant,
			Username:    username,
			AnomalyType: "DORMANT_ACCOUNT",
			Severity:    "HIGH",
			RiskPoints:  25,
			Title:       fmt.Sprintf("Simulated: Dormant Account Reactivated: %s", username),
			Description: fmt.Sprintf("Identity %s logged in and changed domain policies after 64 days of inactivity.", username),
			SourceIP:    sourceIP,
			DeviceName:  deviceName,
			Evidence: map[string]interface{}{
				"inactive_days": 64,
				"simulation":    true,
			},
			DetectedAt: now,
		}
	default:
		a = models.UEBAAnomaly{
			TenantSlug:  tenant,
			Username:    username,
			AnomalyType: "PRIVILEGE_BURST",
			Severity:    "MEDIUM",
			RiskPoints:  15,
			Title:       fmt.Sprintf("Simulated: Rapid Privilege Escalation by %s", username),
			Description: fmt.Sprintf("User %s acquired 4 elevated roles within a 60-second window.", username),
			SourceIP:    sourceIP,
			DeviceName:  deviceName,
			Evidence: map[string]interface{}{
				"elevation_count": 4,
				"simulation":      true,
			},
			DetectedAt: now,
		}
	}

	e.recordAnomaly(ctx, &a)
	return &a, nil
}
