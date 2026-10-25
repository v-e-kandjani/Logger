package ti

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

// SIEMDispatcher defines an interface for direct SIEM alert emission
type SIEMDispatcher interface {
	DispatchDirectAlert(alert *models.SIEMAlert)
}

// Engine coordinates threat intelligence feed harvesting, memory caching, and stream matching
type Engine struct {
	pgDB       *postgres.DB
	matcher    *Matcher
	harvester  *Harvester
	siemEngine SIEMDispatcher
	syncMu     sync.Mutex
	stopCh     chan struct{}
}

// NewEngine creates a new Threat Intelligence engine
func NewEngine(pgDB *postgres.DB) *Engine {
	return &Engine{
		pgDB:      pgDB,
		matcher:   NewMatcher(),
		harvester: NewHarvester(),
		stopCh:    make(chan struct{}),
	}
}

// SetSIEMEngine attaches the SIEM correlation engine for direct threat alert dispatching
func (e *Engine) SetSIEMEngine(siem SIEMDispatcher) {
	e.siemEngine = siem
}

// GetMatcher returns the fast in-memory matcher instance
func (e *Engine) GetMatcher() *Matcher {
	return e.matcher
}

// Start loads active threat indicators into memory and starts the background sync scheduler
func (e *Engine) Start(ctx context.Context) {
	// 1. Initial in-memory cache population
	if err := e.RebuildCache(ctx); err != nil {
		log.Printf("[Threat Intel] Warning loading initial cache: %v", err)
	}

	// 2. Start background feed sync ticker (checks every 5 minutes)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		// Run an initial quick pass to sync any feed that has never synced
		time.Sleep(10 * time.Second)
		e.syncDueFeeds(context.Background())

		for {
			select {
			case <-ticker.C:
				e.syncDueFeeds(context.Background())
			case <-e.stopCh:
				return
			}
		}
	}()

	log.Println("[Threat Intel] Engine started: in-memory matcher and feed scheduler active")
}

// Stop cleanly terminates background tasks
func (e *Engine) Stop() {
	close(e.stopCh)
}

// RebuildCache queries all active threat indicators from the database and updates the matcher snapshot
func (e *Engine) RebuildCache(ctx context.Context) error {
	indicators, err := e.pgDB.LoadActiveIndicatorsForCache(ctx)
	if err != nil {
		return fmt.Errorf("failed loading indicators for cache: %w", err)
	}

	e.matcher.BuildSnapshot(indicators)
	log.Printf("[Threat Intel] In-memory matcher snapshot updated with %d active indicators", len(indicators))
	return nil
}

// SyncFeed manually or scheduled fetches, parses, and upserts a single threat feed
func (e *Engine) SyncFeed(ctx context.Context, feedID int) (int, error) {
	e.syncMu.Lock()
	defer e.syncMu.Unlock()

	feed, err := e.pgDB.GetTIFeed(ctx, feedID)
	if err != nil {
		return 0, fmt.Errorf("feed not found: %w", err)
	}

	if !feed.IsEnabled {
		return 0, fmt.Errorf("feed %s is disabled", feed.Name)
	}

	_ = e.pgDB.UpdateTIFeedSyncStatus(ctx, feed.ID, "SYNCING", "", feed.IndicatorCount)

	indicators, err := e.harvester.FetchFeed(ctx, feed)
	if err != nil {
		_ = e.pgDB.UpdateTIFeedSyncStatus(ctx, feed.ID, "FAILED", err.Error(), feed.IndicatorCount)
		return 0, err
	}

	inserted, err := e.pgDB.UpsertTIIndicatorsBatch(ctx, feed.ID, indicators)
	if err != nil {
		_ = e.pgDB.UpdateTIFeedSyncStatus(ctx, feed.ID, "FAILED", err.Error(), feed.IndicatorCount)
		return 0, fmt.Errorf("failed persisting indicators: %w", err)
	}

	_ = e.pgDB.UpdateTIFeedSyncStatus(ctx, feed.ID, "SUCCESS", "", inserted)

	// Rebuild matcher cache to include freshly harvested indicators
	_ = e.RebuildCache(ctx)

	log.Printf("[Threat Intel] Feed '%s' successfully synchronized: %d indicators imported", feed.Name, inserted)
	return inserted, nil
}

// SyncAllFeeds synchronizes all enabled threat intelligence feeds
func (e *Engine) SyncAllFeeds(ctx context.Context) (map[int]int, error) {
	feeds, err := e.pgDB.ListTIFeeds(ctx)
	if err != nil {
		return nil, err
	}

	results := make(map[int]int)
	for _, f := range feeds {
		if !f.IsEnabled {
			continue
		}
		count, err := e.SyncFeed(ctx, f.ID)
		if err != nil {
			log.Printf("[Threat Intel] Error syncing feed %s: %v", f.Name, err)
			results[f.ID] = -1
		} else {
			results[f.ID] = count
		}
	}

	return results, nil
}

// syncDueFeeds checks feeds that have exceeded their poll_interval_minutes
func (e *Engine) syncDueFeeds(ctx context.Context) {
	feeds, err := e.pgDB.ListTIFeeds(ctx)
	if err != nil {
		return
	}

	now := time.Now()
	for _, f := range feeds {
		if !f.IsEnabled {
			continue
		}

		shouldSync := false
		if f.LastSyncAt == nil {
			shouldSync = true
		} else {
			elapsed := now.Sub(*f.LastSyncAt)
			if elapsed >= time.Duration(f.PollIntervalMinutes)*time.Minute {
				shouldSync = true
			}
		}

		if shouldSync {
			go func(feedID int, name string) {
				subCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				if _, err := e.SyncFeed(subCtx, feedID); err != nil {
					log.Printf("[Threat Intel] Scheduled sync failed for %s: %v", name, err)
				}
			}(f.ID, f.Name)
		}
	}
}

// ProcessSyslogMatch checks a syslog message against threat intelligence and generates matches/alerts
func (e *Engine) ProcessSyslogMatch(ctx context.Context, tenant, srcIP, dstIP, domain, devName, msg string) *models.IndicatorHit {
	hit := e.matcher.MatchSyslog(srcIP, dstIP, domain, msg)
	if hit == nil {
		return nil
	}

	// Trigger match record and SIEM alert asynchronously to not stall hot ring-buffer workers
	go func(tenantSlug string, h *models.IndicatorHit) {
		matchCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var ruleID, mitreTactic, mitreTech string
		switch strings.ToLower(h.IndicatorType) {
		case "ip":
			ruleID = "IOC-MATCH-MALICIOUS-IP"
			mitreTactic = "Command and Control"
			mitreTech = "T1071"
		case "domain", "url":
			ruleID = "IOC-MATCH-SUSPICIOUS-DOMAIN"
			mitreTactic = "Resource Development"
			mitreTech = "T1584"
		default:
			ruleID = "IOC-MATCH-KNOWN-MALWARE-HASH"
			mitreTactic = "Execution"
			mitreTech = "T1204"
		}

		now := time.Now().UTC()
		var alertID string

		if e.siemEngine != nil {
			siemAlert := &models.SIEMAlert{
				ID:             uuid.New(),
				RuleID:         ruleID,
				RuleName:       fmt.Sprintf("Threat Intel %s Match: %s", strings.ToUpper(h.IndicatorType), h.IndicatorValue),
				Severity:       strings.ToUpper(h.Severity),
				Tenant:         tenantSlug,
				DeviceName:     devName,
				SourceIP:       srcIP,
				DestinationIP:  dstIP,
				Category:       "threat_intel",
				EventCount:     1,
				FirstSeen:      now,
				LastSeen:       now,
				Status:         "NEW",
				MitreTactic:    mitreTactic,
				MitreTechnique: mitreTech,
				RiskScore:      h.Confidence,
				Summary:        fmt.Sprintf("Matched threat feed '%s' (%s): %s in syslog from %s", h.Source, h.ThreatCategory, h.IndicatorValue, devName),
				CreatedAt:      now,
			}
			e.siemEngine.DispatchDirectAlert(siemAlert)
			alertID = siemAlert.ID.String()
		}

		match := &models.TIMatch{
			TenantSlug:      tenantSlug,
			IndicatorID:     &h.IndicatorID,
			IndicatorType:   h.IndicatorType,
			IndicatorValue:  h.IndicatorValue,
			ThreatCategory:  h.ThreatCategory,
			Severity:        h.Severity,
			SourceType:      "syslog",
			SourceIP:        srcIP,
			DestinationIP:   dstIP,
			Domain:          domain,
			DeviceName:      devName,
			MatchedAt:       now,
			SIEMAlertID:     alertID,
			RawEventSummary: msg,
			ActionTaken:     "ALERT",
		}
		_ = e.pgDB.RecordTIMatch(matchCtx, match)
	}(tenant, hit)

	return hit
}

// ProcessNetworkFlowMatch checks agent network connections against threat intelligence
func (e *Engine) ProcessNetworkFlowMatch(ctx context.Context, tenant, hostID, hostname, srcIP, dstIP, domain string) *models.IndicatorHit {
	var hit *models.IndicatorHit
	if dstIP != "" {
		hit = e.matcher.MatchIP(dstIP)
	}
	if hit == nil && domain != "" {
		hit = e.matcher.MatchDomain(domain)
	}
	if hit == nil {
		return nil
	}

	go func(tenantSlug string, h *models.IndicatorHit) {
		matchCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var ruleID, mitreTactic, mitreTech string
		if strings.ToLower(h.IndicatorType) == "ip" {
			ruleID = "IOC-MATCH-MALICIOUS-IP"
			mitreTactic = "Command and Control"
			mitreTech = "T1071"
		} else {
			ruleID = "IOC-MATCH-SUSPICIOUS-DOMAIN"
			mitreTactic = "Resource Development"
			mitreTech = "T1584"
		}

		now := time.Now().UTC()
		var alertID string

		if e.siemEngine != nil {
			siemAlert := &models.SIEMAlert{
				ID:             uuid.New(),
				RuleID:         ruleID,
				RuleName:       fmt.Sprintf("Endpoint Outbound Threat Match: %s", h.IndicatorValue),
				Severity:       strings.ToUpper(h.Severity),
				Tenant:         tenantSlug,
				DeviceName:     hostname,
				SourceIP:       srcIP,
				DestinationIP:  dstIP,
				Category:       "threat_intel",
				EventCount:     1,
				FirstSeen:      now,
				LastSeen:       now,
				Status:         "NEW",
				MitreTactic:    mitreTactic,
				MitreTechnique: mitreTech,
				RiskScore:      h.Confidence,
				Summary:        fmt.Sprintf("Endpoint '%s' connected to known threat %s (%s, feed: %s)", hostname, h.IndicatorValue, h.ThreatCategory, h.Source),
				CreatedAt:      now,
			}
			e.siemEngine.DispatchDirectAlert(siemAlert)
			alertID = siemAlert.ID.String()
		}

		match := &models.TIMatch{
			TenantSlug:      tenantSlug,
			IndicatorID:     &h.IndicatorID,
			IndicatorType:   h.IndicatorType,
			IndicatorValue:  h.IndicatorValue,
			ThreatCategory:  h.ThreatCategory,
			Severity:        h.Severity,
			SourceType:      "agent_network",
			SourceIP:        srcIP,
			DestinationIP:   dstIP,
			Domain:          domain,
			DeviceName:      hostname,
			HostIdentifier:  hostID,
			MatchedAt:       now,
			SIEMAlertID:     alertID,
			RawEventSummary: fmt.Sprintf("Outbound flow to %s (%s)", dstIP, domain),
			ActionTaken:     "ALERT",
		}
		_ = e.pgDB.RecordTIMatch(matchCtx, match)
	}(tenant, hit)

	return hit
}

// ProcessFileHashMatch checks executable or file hashes from agents/FIM
func (e *Engine) ProcessFileHashMatch(ctx context.Context, tenant, hostID, hostname, hash, filePath string) *models.IndicatorHit {
	hit := e.matcher.MatchHash(hash)
	if hit == nil {
		return nil
	}

	go func(tenantSlug string, h *models.IndicatorHit) {
		matchCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		now := time.Now().UTC()
		var alertID string

		if e.siemEngine != nil {
			siemAlert := &models.SIEMAlert{
				ID:             uuid.New(),
				RuleID:         "IOC-MATCH-KNOWN-MALWARE-HASH",
				RuleName:       fmt.Sprintf("Malware Hash Match: %s on %s", h.IndicatorValue[:min(12, len(h.IndicatorValue))], hostname),
				Severity:       "CRITICAL",
				Tenant:         tenantSlug,
				DeviceName:     hostname,
				Category:       "threat_intel",
				EventCount:     1,
				FirstSeen:      now,
				LastSeen:       now,
				Status:         "NEW",
				MitreTactic:    "Execution",
				MitreTechnique: "T1204",
				RiskScore:      95,
				Summary:        fmt.Sprintf("Host '%s': File '%s' matches known malware hash (%s, feed: %s)", hostname, filePath, h.IndicatorValue, h.Source),
				CreatedAt:      now,
			}
			e.siemEngine.DispatchDirectAlert(siemAlert)
			alertID = siemAlert.ID.String()
		}

		match := &models.TIMatch{
			TenantSlug:      tenantSlug,
			IndicatorID:     &h.IndicatorID,
			IndicatorType:   h.IndicatorType,
			IndicatorValue:  h.IndicatorValue,
			ThreatCategory:  h.ThreatCategory,
			Severity:        "critical",
			SourceType:      "agent_process",
			FileHash:        hash,
			DeviceName:      hostname,
			HostIdentifier:  hostID,
			MatchedAt:       now,
			SIEMAlertID:     alertID,
			RawEventSummary: fmt.Sprintf("File execution %s (Hash: %s)", filePath, hash),
			ActionTaken:     "ALERT",
		}
		_ = e.pgDB.RecordTIMatch(matchCtx, match)
	}(tenant, hit)

	return hit
}

// SimulateMatch simulates an IOC match on demand for operator testing
func (e *Engine) SimulateMatch(ctx context.Context, tenant, indType, indValue string) (*models.TIMatch, error) {
	if indValue == "" {
		return nil, fmt.Errorf("indicator value cannot be empty")
	}

	var hit *models.IndicatorHit
	switch strings.ToLower(indType) {
	case "ip":
		hit = e.matcher.MatchIP(indValue)
	case "domain":
		hit = e.matcher.MatchDomain(indValue)
	case "sha256", "md5", "hash":
		hit = e.matcher.MatchHash(indValue)
	case "url":
		hit = e.matcher.MatchURL(indValue)
	}

	if hit == nil {
		// Create a synthetic hit for testing simulation if not in active feed
		hit = &models.IndicatorHit{
			IndicatorType:  indType,
			IndicatorValue: indValue,
			ThreatCategory: "simulated_threat",
			Severity:       "critical",
			Confidence:     99,
			Source:         "Operator Threat Simulation",
			Description:    "Simulated threat intelligence indicator hit",
		}
	}

	now := time.Now().UTC()
	var ruleID, mitreTactic, mitreTech string
	if strings.ToLower(indType) == "ip" {
		ruleID = "IOC-MATCH-MALICIOUS-IP"
		mitreTactic = "Command and Control"
		mitreTech = "T1071"
	} else if strings.ToLower(indType) == "domain" || strings.ToLower(indType) == "url" {
		ruleID = "IOC-MATCH-SUSPICIOUS-DOMAIN"
		mitreTactic = "Resource Development"
		mitreTech = "T1584"
	} else {
		ruleID = "IOC-MATCH-KNOWN-MALWARE-HASH"
		mitreTactic = "Execution"
		mitreTech = "T1204"
	}

	var alertID string
	if e.siemEngine != nil {
		siemAlert := &models.SIEMAlert{
			ID:             uuid.New(),
			RuleID:         ruleID,
			RuleName:       fmt.Sprintf("[SIMULATED] Threat Intel Match: %s", indValue),
			Severity:       "CRITICAL",
			Tenant:         tenant,
			DeviceName:     "threat-intel-simulator",
			SourceIP:       "198.51.100.42",
			DestinationIP:  "203.0.113.88",
			Category:       "threat_intel",
			EventCount:     1,
			FirstSeen:      now,
			LastSeen:       now,
			Status:         "NEW",
			MitreTactic:    mitreTactic,
			MitreTechnique: mitreTech,
			RiskScore:      99,
			Summary:        fmt.Sprintf("Simulated IOC Match against feed '%s': %s (%s)", hit.Source, indValue, hit.ThreatCategory),
			CreatedAt:      now,
		}
		e.siemEngine.DispatchDirectAlert(siemAlert)
		alertID = siemAlert.ID.String()
	}

	match := &models.TIMatch{
		TenantSlug:      tenant,
		IndicatorID:     &hit.IndicatorID,
		IndicatorType:   indType,
		IndicatorValue:  indValue,
		ThreatCategory:  hit.ThreatCategory,
		Severity:        "critical",
		SourceType:      "simulation",
		SourceIP:        "198.51.100.42",
		DestinationIP:   "203.0.113.88",
		Domain:          indValue,
		DeviceName:      "threat-intel-simulator",
		MatchedAt:       now,
		SIEMAlertID:     alertID,
		RawEventSummary: fmt.Sprintf("Operator simulated match for %s: %s", indType, indValue),
		ActionTaken:     "ALERT",
	}

	if err := e.pgDB.RecordTIMatch(ctx, match); err != nil {
		return nil, err
	}

	return match, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
