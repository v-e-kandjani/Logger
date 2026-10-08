package correlation

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/siem/normalizer"
)

// AlertPersister abstracts database persistence for SIEM alerts
type AlertPersister interface {
	CreateOrUpdateSIEMAlert(ctx context.Context, alert *models.SIEMAlert) (*models.SIEMAlert, error)
	ListSIEMRules(ctx context.Context) ([]models.SIEMRule, error)
	ToggleSIEMRule(ctx context.Context, ruleID string, enabled bool) error
}

// WindowEvent tracks an event instance inside a sliding bucket
type WindowEvent struct {
	Timestamp  time.Time
	Username   string
	Port       uint16
	RawMessage string
}

// WindowBucket holds sliding state for a rule + group_by key
type WindowBucket struct {
	RuleID      string
	GroupKey    string
	Events      []WindowEvent
	ActiveAlert *models.SIEMAlert
	LastFired   time.Time
}

// Engine evaluates normalized events against correlation rules
type Engine struct {
	mu              sync.RWMutex
	normalizer      *normalizer.Normalizer
	persister       AlertPersister
	rules           map[string]*models.SIEMRule
	rulesByCategory map[string][]*models.SIEMRule
	catchAllRules   []*models.SIEMRule
	buckets         map[string]*WindowBucket
	subscribers     map[chan *models.SIEMAlert]struct{}
	stopCh          chan struct{}
}

// DefaultRules returns the complete 72-rule detection catalog
func DefaultRules() []models.SIEMRule {
	return CatalogRules()
}

// NewEngine creates and initializes the SIEM correlation engine
func NewEngine(norm *normalizer.Normalizer, persister AlertPersister) *Engine {
	e := &Engine{
		normalizer:      norm,
		persister:       persister,
		rules:           make(map[string]*models.SIEMRule),
		rulesByCategory: make(map[string][]*models.SIEMRule),
		buckets:         make(map[string]*WindowBucket),
		subscribers:     make(map[chan *models.SIEMAlert]struct{}),
		stopCh:          make(chan struct{}),
	}

	// Initialize default rules
	for _, r := range DefaultRules() {
		ruleCopy := r
		e.rules[r.ID] = &ruleCopy
	}
	e.rebuildRuleIndexLocked()

	// Start pruning loop
	go e.pruningLoop()

	return e
}

func (e *Engine) rebuildRuleIndexLocked() {
	e.rulesByCategory = make(map[string][]*models.SIEMRule)
	e.catchAllRules = nil
	for _, rule := range e.rules {
		if !rule.IsEnabled {
			continue
		}
		if rule.MatchCategory == "" {
			e.catchAllRules = append(e.catchAllRules, rule)
		} else {
			e.rulesByCategory[rule.MatchCategory] = append(e.rulesByCategory[rule.MatchCategory], rule)
		}
	}
}

// LoadRulesFromDB synchronizes rules from persistent database
func (e *Engine) LoadRulesFromDB(ctx context.Context) error {
	if e.persister == nil {
		return nil
	}
	dbRules, err := e.persister.ListSIEMRules(ctx)
	if err != nil {
		return err
	}
	if len(dbRules) == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range dbRules {
		ruleCopy := r
		e.rules[r.ID] = &ruleCopy
	}
	e.rebuildRuleIndexLocked()
	return nil
}

// ProcessLogEvent normalizes a raw LogEvent and routes it through correlation
func (e *Engine) ProcessLogEvent(rawEvent *models.LogEvent) *models.NormalizedEvent {
	norm := e.normalizer.Normalize(rawEvent)
	e.Evaluate(norm)
	return norm
}

// Evaluate checks a normalized event against all active correlation rules
func (e *Engine) Evaluate(event *models.NormalizedEvent) {
	if event == nil {
		return
	}

	// High-performance fast path:
	// Benign allowed network traffic matches 0 rules in the SIEM catalog.
	// Bypassing locks and rule iteration saves ~95% of SIEM CPU overhead.
	if event.EventCategory == "network" {
		switch event.EventAction {
		case "connection-allowed", "app-control-allowed", "web-filter-allowed", "dns-allowed":
			return
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Only iterate over rules indexed for this event's category, plus any catch-all rules
	candidateRules := e.rulesByCategory[event.EventCategory]
	if len(candidateRules) == 0 && len(e.catchAllRules) == 0 {
		return
	}

	now := time.Now().UTC()

	processRule := func(rule *models.SIEMRule) {
		if !rule.IsEnabled {
			return
		}

		if !e.matchesRule(rule, event) {
			return
		}

		groupVal := e.extractGroupValue(rule, event)
		if groupVal == "" {
			groupVal = "global"
		}

		bucketKey := fmt.Sprintf("%s::%s", rule.ID, groupVal)
		bucket, exists := e.buckets[bucketKey]
		if !exists {
			bucket = &WindowBucket{
				RuleID:   rule.ID,
				GroupKey: groupVal,
				Events:   make([]WindowEvent, 0, rule.Threshold*2),
			}
			e.buckets[bucketKey] = bucket
		}

		// Append window event
		bucket.Events = append(bucket.Events, WindowEvent{
			Timestamp:  event.Timestamp,
			Username:   event.Username,
			Port:       event.SourcePort,
			RawMessage: event.RawMessage,
		})

		// Prune events outside sliding window
		cutoff := now.Add(-time.Duration(rule.TimeframeSeconds) * time.Second)
		validIdx := 0
		for i, ev := range bucket.Events {
			if ev.Timestamp.After(cutoff) {
				validIdx = i
				break
			}
		}
		if validIdx > 0 {
			bucket.Events = bucket.Events[validIdx:]
		}

		// Check trigger condition
		shouldTrigger := false
		if rule.ID == "AUTH-004" {
			// Distributed password spraying: threshold distinct usernames
			users := make(map[string]struct{})
			for _, ev := range bucket.Events {
				if ev.Username != "" {
					users[ev.Username] = struct{}{}
				}
			}
			if len(users) >= rule.Threshold {
				shouldTrigger = true
			}
		} else {
			if len(bucket.Events) >= rule.Threshold {
				shouldTrigger = true
			}
		}

		if shouldTrigger {
			// Throttle firing to avoid flooding duplicate alerts within 30 seconds
			if time.Since(bucket.LastFired) > 30*time.Second || bucket.ActiveAlert == nil {
				e.triggerAlert(rule, bucket, event)
				bucket.LastFired = now
			} else {
				// Update existing active alert event count and last seen
				if bucket.ActiveAlert != nil {
					bucket.ActiveAlert.EventCount = len(bucket.Events)
					bucket.ActiveAlert.LastSeen = now
					if len(bucket.ActiveAlert.EvidenceLogs) < 10 && event.RawMessage != "" {
						bucket.ActiveAlert.EvidenceLogs = append(bucket.ActiveAlert.EvidenceLogs, event.RawMessage)
					}
					// Persist async
					go e.persistAlert(bucket.ActiveAlert)
				}
			}
		}
	}

	for _, rule := range candidateRules {
		processRule(rule)
	}
	for _, rule := range e.catchAllRules {
		processRule(rule)
	}
}

func (e *Engine) matchesRule(rule *models.SIEMRule, event *models.NormalizedEvent) bool {
	if rule.MatchCategory != "" && rule.MatchCategory != event.EventCategory {
		return false
	}
	if rule.MatchAction != "" && rule.MatchAction != event.EventAction {
		if rule.ID == "PERIM-004" && (event.EventAction == "intrusion-high-priority" || event.EventAction == "malware-blocked") {
			// matches either action name
		} else {
			return false
		}
	}
	if rule.MatchOutcome != "" && rule.MatchOutcome != event.EventOutcome {
		if rule.ID == "PERIM-004" && event.EventOutcome == "detected" {
			// high-priority intrusion that passed the sensor (monitor mode) must still alert
		} else {
			return false
		}
	}
	return true
}

func (e *Engine) extractGroupValue(rule *models.SIEMRule, event *models.NormalizedEvent) string {
	if len(rule.GroupBy) == 0 {
		return event.SourceIP
	}
	for _, g := range rule.GroupBy {
		switch g {
		case "source_ip":
			if event.SourceIP != "" {
				return event.SourceIP
			}
		case "username":
			if event.Username != "" {
				return event.Username
			}
		case "device_name":
			if event.DeviceName != "" {
				return event.DeviceName
			}
		}
	}
	return event.SourceIP
}

func (e *Engine) triggerAlert(rule *models.SIEMRule, bucket *WindowBucket, event *models.NormalizedEvent) {
	now := time.Now().UTC()

	evidence := make([]string, 0, len(bucket.Events))
	for _, ev := range bucket.Events {
		if ev.RawMessage != "" {
			evidence = append(evidence, ev.RawMessage)
			if len(evidence) >= 10 {
				break
			}
		}
	}

	summary := fmt.Sprintf("[%s] %s triggered by %s (%d events in %ds)",
		rule.Severity, rule.Name, bucket.GroupKey, len(bucket.Events), rule.TimeframeSeconds)

	alert := &models.SIEMAlert{
		ID:             uuid.New(),
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		Severity:       rule.Severity,
		RiskScore:      rule.RiskScore,
		Category:       rule.Category,
		Status:         "NEW",
		SourceIP:       event.SourceIP,
		DestinationIP:  event.DestinationIP,
		Username:       event.Username,
		DeviceName:     event.DeviceName,
		EventCount:     len(bucket.Events),
		FirstSeen:      bucket.Events[0].Timestamp,
		LastSeen:       now,
		MitreTactic:    rule.MitreTactic,
		MitreTechnique: rule.MitreTechnique,
		Summary:        summary,
		EvidenceLogs:   evidence,
		AssignedTo:     "Unassigned",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	bucket.ActiveAlert = alert

	// Asynchronously save to DB
	go e.persistAlert(alert)

	// Broadcast alert to live subscribers
	e.broadcastAlert(alert)
}

func (e *Engine) persistAlert(alert *models.SIEMAlert) {
	if e.persister == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := e.persister.CreateOrUpdateSIEMAlert(ctx, alert); err != nil {
		log.Printf("[SIEM Engine] Warning persisting alert: %v", err)
	}
}

// SubscribeAlerts attaches a live alert subscription channel
func (e *Engine) SubscribeAlerts() chan *models.SIEMAlert {
	ch := make(chan *models.SIEMAlert, 128)
	e.mu.Lock()
	e.subscribers[ch] = struct{}{}
	e.mu.Unlock()
	return ch
}

// UnsubscribeAlerts removes a channel
func (e *Engine) UnsubscribeAlerts(ch chan *models.SIEMAlert) {
	e.mu.Lock()
	delete(e.subscribers, ch)
	e.mu.Unlock()
	close(ch)
}

func (e *Engine) broadcastAlert(alert *models.SIEMAlert) {
	for ch := range e.subscribers {
		select {
		case ch <- alert:
		default:
		}
	}
}

// pruningLoop clears old sliding buckets
func (e *Engine) pruningLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.mu.Lock()
			now := time.Now().UTC()
			for k, b := range e.buckets {
				if len(b.Events) == 0 || now.Sub(b.Events[len(b.Events)-1].Timestamp) > 10*time.Minute {
					delete(e.buckets, k)
				}
			}
			e.mu.Unlock()
		}
	}
}

// Stop cleanly terminates background tasks
func (e *Engine) Stop() {
	close(e.stopCh)
}

// ToggleRule enables or disables a rule
func (e *Engine) ToggleRule(ruleID string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule, ok := e.rules[ruleID]
	if !ok {
		return fmt.Errorf("rule not found: %s", ruleID)
	}
	rule.IsEnabled = enabled
	rule.UpdatedAt = time.Now().UTC()
	e.rebuildRuleIndexLocked()

	if e.persister != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = e.persister.ToggleSIEMRule(ctx, ruleID, enabled)
		}()
	}
	return nil
}

// GetRules returns all loaded detection rules
func (e *Engine) GetRules() []models.SIEMRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]models.SIEMRule, 0, len(e.rules))
	for _, r := range e.rules {
		list = append(list, *r)
	}
	return list
}

// SimulateScenario generates synthetic normalized logs to trigger a security alert for testing/demo
func (e *Engine) SimulateScenario(scenario string) (*models.SIEMAlert, error) {
	now := time.Now().UTC()

	switch scenario {
	case "brute-force", "ssh-brute-force":
		attackerIP := "185.220.101.45"
		targetUser := "admin"
		for i := 0; i < 6; i++ {
			rawMsg := fmt.Sprintf("Failed password for %s from %s port %d ssh2", targetUser, attackerIP, 41000+i)
			event := &models.NormalizedEvent{
				EventID:         uuid.New(),
				Timestamp:       now.Add(time.Duration(i) * time.Second),
				ReceivedAt:      now,
				SourceIP:        attackerIP,
				SourcePort:      uint16(41000 + i),
				DestinationIP:   "10.0.0.10",
				DestinationPort: 22,
				DeviceName:      "edge-fw-01",
				Vendor:          "Linux",
				Product:         "OS/Auth",
				EventCategory:   "authentication",
				EventAction:     "login-failed",
				EventOutcome:    "failure",
				Username:        targetUser,
				Severity:        "HIGH",
				RiskScore:       75,
				MitreTactic:     "Credential Access",
				MitreTechnique:  "T1110",
				Message:         rawMsg,
				RawMessage:      rawMsg,
			}
			e.Evaluate(event)
		}
	case "port-scan":
		attackerIP := "45.33.32.156"
		for port := 80; port < 132; port++ {
			rawMsg := fmt.Sprintf("firewall: disp=\"Deny\" src=\"%s\" dst=\"10.0.0.1\" src_port=\"52100\" dst_port=\"%d\"", attackerIP, port)
			event := &models.NormalizedEvent{
				EventID:         uuid.New(),
				Timestamp:       now.Add(time.Duration(port-80) * time.Second),
				ReceivedAt:      now,
				SourceIP:        attackerIP,
				SourcePort:      52100,
				DestinationIP:   "10.0.0.1",
				DestinationPort: uint16(port),
				DeviceName:      "WatchGuard-Firebox-01",
				Vendor:          "WatchGuard",
				Product:         "Firebox",
				EventCategory:   "network",
				EventAction:     "connection-denied",
				EventOutcome:    "blocked",
				Severity:        "MEDIUM",
				RiskScore:       55,
				MitreTactic:     "Discovery",
				MitreTechnique:  "T1046",
				Message:         rawMsg,
				RawMessage:      rawMsg,
			}
			e.Evaluate(event)
		}
	case "priv-esc":
		targetUser := "app-deployer"
		rawMsg := fmt.Sprintf("sudo: pam_unix(sudo:auth): %s added ALL=(ALL) NOPASSWD: ALL in /etc/sudoers", targetUser)
		event := &models.NormalizedEvent{
			EventID:        uuid.New(),
			Timestamp:      now,
			ReceivedAt:     now,
			SourceIP:       "127.0.0.1",
			DeviceName:     "app-srv-01",
			Vendor:         "Linux",
			Product:        "OS/Auth",
			EventCategory:  "linux",
			EventAction:    "sudoers-nopasswd-added",
			EventOutcome:   "success",
			Username:       targetUser,
			Severity:       "HIGH",
			RiskScore:      85,
			MitreTactic:    "Privilege Escalation",
			MitreTechnique: "T1548.003",
			Message:        rawMsg,
			RawMessage:     rawMsg,
		}
		e.Evaluate(event)
	case "threat", "malware":
		attackerIP := "194.26.29.112"
		rawMsg := fmt.Sprintf("date=2026-10-08 time=20:15:00 devname=\"FGT100F\" type=utm subtype=ips action=blocked srcip=%s dstip=10.0.0.50 attack=\"CVE-2024-21762 FortiOS SSL-VPN RCE\"", attackerIP)
		event := &models.NormalizedEvent{
			EventID:         uuid.New(),
			Timestamp:       now,
			ReceivedAt:      now,
			SourceIP:        attackerIP,
			SourcePort:      44391,
			DestinationIP:   "10.0.0.50",
			DestinationPort: 443,
			DeviceName:      "FGT100F-Core",
			Vendor:          "Fortinet",
			Product:         "FortiGate",
			EventCategory:   "threat",
			EventAction:     "malware-blocked",
			EventOutcome:    "blocked",
			Severity:        "CRITICAL",
			RiskScore:       95,
			MitreTactic:     "Initial Access",
			MitreTechnique:  "T1190",
			Message:         rawMsg,
			RawMessage:      rawMsg,
		}
		e.Evaluate(event)
	default:
		return nil, fmt.Errorf("unknown simulation scenario: %s", scenario)
	}

	return nil, nil
}
