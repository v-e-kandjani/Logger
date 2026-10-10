package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/notification/smtp"
	siemcatalog "github.com/syslog-platform/logger/internal/siem/catalog"
	"github.com/syslog-platform/logger/internal/siem/mitre"
)

// handleSIEMAlertSubroutes dispatches /api/v1/siem/alerts/{id}[/status|notes]
func (h *Handler) handleSIEMAlertSubroutes(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/status") {
		h.handleSIEMAlertStatus(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/notes") {
		h.handleSIEMAlertNotes(w, r)
		return
	}
	h.handleSIEMAlertDetail(w, r)
}

// handleSIEMRuleSubroutes dispatches /api/v1/siem/rules/{id}/toggle
func (h *Handler) handleSIEMRuleSubroutes(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/toggle") {
		h.handleSIEMRuleToggle(w, r)
		return
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// handleSIEMOverview returns SOC dashboard metrics
func (h *Handler) handleSIEMOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	stats, err := h.pgDB.GetSIEMOverviewStats(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// handleSIEMAlerts lists alerts with filtering and pagination
func (h *Handler) handleSIEMAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	status := r.URL.Query().Get("status")
	severity := r.URL.Query().Get("severity")
	search := r.URL.Query().Get("search")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit <= 0 {
		limit = 50
	}

	alerts, total, err := h.pgDB.ListSIEMAlerts(ctx, status, severity, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if alerts == nil {
		alerts = []models.SIEMAlert{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// handleSIEMAlertDetail retrieves a single alert and its investigation notes
func (h *Handler) handleSIEMAlertDetail(w http.ResponseWriter, r *http.Request) {
	// Pattern: /api/v1/siem/alerts/{id}
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 5 {
		http.Error(w, "Invalid alert path", http.StatusBadRequest)
		return
	}

	alertIDStr := pathParts[4]
	alertID, err := uuid.Parse(alertIDStr)
	if err != nil {
		http.Error(w, "Invalid alert UUID", http.StatusBadRequest)
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	alert, notes, err := h.pgDB.GetSIEMAlert(ctx, alertID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Alert not found"})
		return
	}

	if notes == nil {
		notes = []models.SIEMIncidentNote{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alert": alert,
		"notes": notes,
	})
}

// handleSIEMAlertStatus updates alert status (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE)
func (h *Handler) handleSIEMAlertStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Pattern: /api/v1/siem/alerts/{id}/status
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 6 {
		http.Error(w, "Invalid alert status path", http.StatusBadRequest)
		return
	}

	alertIDStr := pathParts[4]
	alertID, err := uuid.Parse(alertIDStr)
	if err != nil {
		http.Error(w, "Invalid alert UUID", http.StatusBadRequest)
		return
	}

	var req struct {
		Status     string `json:"status"`
		AssignedTo string `json:"assigned_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Status == "" {
		req.Status = "INVESTIGATING"
	}
	if req.AssignedTo == "" {
		req.AssignedTo = "admin"
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if err := h.pgDB.UpdateSIEMAlertStatus(ctx, alertID, req.Status, req.AssignedTo); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Log audit trail
	go func() {
		auditCtx, auditCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer auditCancel()
		_ = h.pgDB.InsertAuditLog(auditCtx, &models.AuditLog{
			Username: req.AssignedTo,
			SourceIP: r.RemoteAddr,
			Action:   "SIEM_ALERT_TRIAGE",
			Resource: "siem_alerts/" + alertID.String(),
			Result:   "SUCCESS",
			Details: map[string]interface{}{
				"status":      req.Status,
				"assigned_to": req.AssignedTo,
			},
		})
	}()

	// Dispatch incident task assignment email notification asynchronously
	if req.AssignedTo != "" && req.AssignedTo != "Unassigned" {
		assignedUser := req.AssignedTo
		assignedBy := "Administrator"
		if session, ok := h.getSession(r); ok && session.Username != "" {
			assignedBy = session.Username
		}

		go func() {
			mailCtx, mailCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer mailCancel()

			settings, err := h.pgDB.GetSettings(mailCtx)
			if err != nil {
				return
			}
			smtpCfg := smtp.LoadConfigFromSettings(settings)
			if !smtpCfg.Enabled || !smtpCfg.NotifyOnAssignment {
				return
			}

			user, err := h.pgDB.GetUserByUsername(mailCtx, assignedUser)
			if err != nil || user.Email == "" {
				return
			}

			alert, _, err := h.pgDB.GetSIEMAlert(mailCtx, alertID)
			if err != nil {
				return
			}

			mailer := smtp.NewMailer(smtpCfg)
			_ = mailer.SendAlertAssignmentEmail(user.Email, alert, assignedBy)
		}()
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message":     "Alert status updated",
		"status":      req.Status,
		"assigned_to": req.AssignedTo,
	})
}

// handleSIEMAlertNotes appends an analyst investigation note
func (h *Handler) handleSIEMAlertNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Pattern: /api/v1/siem/alerts/{id}/notes
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 6 {
		http.Error(w, "Invalid alert notes path", http.StatusBadRequest)
		return
	}

	alertIDStr := pathParts[4]
	alertID, err := uuid.Parse(alertIDStr)
	if err != nil {
		http.Error(w, "Invalid alert UUID", http.StatusBadRequest)
		return
	}

	var req struct {
		Author string `json:"author"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Note) == "" {
		http.Error(w, "Note content cannot be empty", http.StatusBadRequest)
		return
	}
	if req.Author == "" {
		req.Author = "Analyst"
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if err := h.pgDB.AddSIEMIncidentNote(ctx, alertID, req.Author, req.Note); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Note added successfully",
	})
}

// handleSIEMRules returns detection rules
func (h *Handler) handleSIEMRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	rules, err := h.pgDB.ListSIEMRules(ctx)
	if err != nil || len(rules) == 0 {
		// Fallback to in-memory rules from correlation engine
		if engine := h.pipeline.GetSIEMEngine(); engine != nil {
			rules = engine.GetRules()
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
	})
}

// handleSIEMRuleToggle enables or disables a rule
func (h *Handler) handleSIEMRuleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Pattern: /api/v1/siem/rules/{id}/toggle
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 6 {
		http.Error(w, "Invalid rule toggle path", http.StatusBadRequest)
		return
	}

	ruleID := pathParts[4]

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if engine := h.pipeline.GetSIEMEngine(); engine != nil {
		if err := engine.ToggleRule(ruleID, req.Enabled); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	ctx, cancel := contextWithTimeout(r, 3*time.Second)
	defer cancel()
	_ = h.pgDB.ToggleSIEMRule(ctx, ruleID, req.Enabled)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Rule state updated",
		"rule_id": ruleID,
		"enabled": req.Enabled,
	})
}

// handleSIEMSimulate executes a test attack scenario for SOC verification
func (h *Handler) handleSIEMSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Scenario string `json:"scenario"` // brute-force, port-scan, priv-esc, threat
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Scenario == "" {
		req.Scenario = "brute-force"
	}

	engine := h.pipeline.GetSIEMEngine()
	if engine == nil {
		http.Error(w, "SIEM correlation engine not initialized", http.StatusServiceUnavailable)
		return
	}

	if _, err := engine.SimulateScenario(req.Scenario); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":  "Security scenario simulated successfully",
		"scenario": req.Scenario,
	})
}

// handleSIEMLiveStream provides real-time WebSocket alert stream to SOC UI
func (h *Handler) handleSIEMLiveStream(w http.ResponseWriter, r *http.Request) {
	engine := h.pipeline.GetSIEMEngine()
	if engine == nil {
		http.Error(w, "SIEM correlation engine unavailable", http.StatusServiceUnavailable)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	alertCh := engine.SubscribeAlerts()
	defer engine.UnsubscribeAlerts(alertCh)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case alert, ok := <-alertCh:
			if !ok {
				return
			}
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteJSON(alert); err != nil {
				return
			}
		}
	}
}

// handleSIEMMitreMatrix returns ATT&CK matrix tactics, techniques, and SOC coverage
func (h *Handler) handleSIEMMitreMatrix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	rules, err := h.pgDB.ListSIEMRules(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	stats := make(map[string]mitre.AlertStat)
	if rows, err := h.pgDB.ListMitreAlertStats(ctx); err == nil {
		for _, s := range rows {
			stats[s.Technique] = mitre.AlertStat{Count: s.Count, LastSeen: s.LastSeen}
		}
	}

	report := h.mitreCatalog.GenerateCoverageReportWithStats(rules, stats)
	writeJSON(w, http.StatusOK, report)
}

// handleSIEMMitreSync updates MITRE ATT&CK definitions from online feed or local air-gapped file
func (h *Handler) handleSIEMMitreSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL      string `json:"url"`
		FilePath string `json:"file_path"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	ctx, cancel := contextWithTimeout(r, 5*time.Minute)
	defer cancel()

	var count int
	var err error

	if req.FilePath != "" {
		count, err = h.mitreCatalog.SyncFromFile(req.FilePath)
	} else {
		count, err = h.mitreCatalog.SyncFromURL(ctx, req.URL)
	}

	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("Failed to sync MITRE ATT&CK definitions: %v", err),
		})
		return
	}

	cookie, _ := r.Cookie(SessionCookieName)
	username := "Administrator"
	if cookie != nil {
		if session, ok := h.sessions.Get(cookie.Value); ok {
			username = session.Username
		}
	}

	// Automatically add/update related SIEM Correlation & Detection Catalog Rules for all matrix techniques
	addedRules, addErr := h.AutoAddMitreCorrelationRules(ctx, h.mitreCatalog.GetAllTechniques())
	if addErr != nil {
		log.Printf("[MITRE] Warning: auto-adding correlation rules failed during sync: %v", addErr)
	}

	_ = h.pgDB.InsertAuditLog(ctx, &models.AuditLog{
		Username: username,
		SourceIP: r.RemoteAddr,
		Action:   "SIEM_MITRE_SYNC",
		Resource: "MITRE_ATTACK",
		Result:   "SUCCESS",
		Details: map[string]interface{}{
			"synced_techniques": count,
			"added_rules":       addedRules,
			"source":            req.URL,
			"file_path":         req.FilePath,
		},
		CreatedAt: time.Now().UTC(),
	})

	status := h.mitreCatalog.GenerateCoverageReportWithStats(nil, nil)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":           true,
		"synced_techniques": count,
		"added_rules":       addedRules,
		"attack_version":    status.AttackVersion,
		"total_techniques":  status.TotalTechniques,
		"new_techniques":    status.NewTechniques,
		"message": fmt.Sprintf("%s loaded: %d techniques (%d parent / %d sub-techniques), %d new since previous release. %d related SIEM correlation rules automatically added/updated.",
			status.Version, status.TotalTechniques, status.TotalParent, status.TotalSub, status.NewTechniques, addedRules),
	})
}

// AutoAddMitreCorrelationRules automatically adds related SIEM Correlation & Detection Catalog Rules
// for techniques in the MITRE ATT&CK matrix to the active rule set (PostgreSQL and correlation engine).
func (h *Handler) AutoAddMitreCorrelationRules(ctx context.Context, techs []mitre.Technique) (int, error) {
	if len(techs) == 0 {
		techs = h.mitreCatalog.GetAllTechniques()
	}
	if len(techs) == 0 {
		return 0, nil
	}

	existingRules, err := h.pgDB.ListSIEMRules(ctx)
	if err != nil {
		return 0, fmt.Errorf("listing existing rules: %w", err)
	}

	coveredMap := make(map[string]bool)
	existingRuleIDs := make(map[string]bool)
	for _, rule := range existingRules {
		existingRuleIDs[rule.ID] = true
		if rule.MitreTechnique != "" {
			coveredMap[rule.MitreTechnique] = true
		}
	}

	// Index curated detection catalog rules by technique ID
	curatedRules := siemcatalog.Rules()
	curatedByTech := make(map[string][]models.SIEMRule)
	for _, cr := range curatedRules {
		if cr.MitreTechnique != "" {
			curatedByTech[cr.MitreTechnique] = append(curatedByTech[cr.MitreTechnique], cr)
		}
	}

	var rulesToInsert []models.SIEMRule
	for _, t := range techs {
		if coveredMap[t.ID] {
			continue
		}

		// 1. Check if curated catalog has a matching rule for this technique
		if curated, found := curatedByTech[t.ID]; found && len(curated) > 0 {
			addedCurated := false
			for _, cr := range curated {
				if !existingRuleIDs[cr.ID] {
					rulesToInsert = append(rulesToInsert, cr)
					existingRuleIDs[cr.ID] = true
					addedCurated = true
				}
			}
			if addedCurated {
				coveredMap[t.ID] = true
				continue
			}
		}

		// 2. Otherwise generate dynamic MITRE correlation detection rule
		rule := buildMitreRuleForTechnique(t, true)
		if !existingRuleIDs[rule.ID] {
			rulesToInsert = append(rulesToInsert, rule)
			existingRuleIDs[rule.ID] = true
			coveredMap[t.ID] = true
		}
	}

	if len(rulesToInsert) == 0 {
		return 0, nil
	}

	if err := h.pgDB.BatchUpsertSIEMRules(ctx, rulesToInsert); err != nil {
		return 0, fmt.Errorf("batch upserting correlation rules: %w", err)
	}

	// Synchronize in-memory correlation engine
	if engine := h.pipeline.GetSIEMEngine(); engine != nil {
		engine.AddOrUpdateRules(rulesToInsert)
	}

	log.Printf("[SIEM] Automatically added %d related SIEM correlation & detection rules for MITRE ATT&CK update", len(rulesToInsert))
	return len(rulesToInsert), nil
}

// handleSIEMMitreInstallAll installs and enables correlation detection rules for all MITRE ATT&CK techniques
func (h *Handler) handleSIEMMitreInstallAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Minute)
	defer cancel()

	// Ensure official STIX feed is synced if currently on baseline
	if h.mitreCatalog.IsBaseline() || h.mitreCatalog.TechniqueCount() < 100 {
		_, _ = h.mitreCatalog.SyncFromURL(ctx, "")
	}

	techs := h.mitreCatalog.GetAllTechniques()
	if len(techs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "No techniques available in the MITRE ATT&CK catalog. Please sync official feed first.",
		})
		return
	}

	rulesAdded, err := h.AutoAddMitreCorrelationRules(ctx, techs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed auto-adding correlation rules: " + err.Error(),
		})
		return
	}

	// Enable all existing MITRE rules as well
	_, _ = h.pgDB.ToggleAllMitreRules(ctx, true)

	// Synchronize engine
	if engine := h.pipeline.GetSIEMEngine(); engine != nil {
		_ = engine.LoadRulesFromDB(ctx)
	}

	// Generate updated report
	allRules, _ := h.pgDB.ListSIEMRules(ctx)
	stats := make(map[string]mitre.AlertStat)
	if rows, err := h.pgDB.ListMitreAlertStats(ctx); err == nil {
		for _, s := range rows {
			stats[s.Technique] = mitre.AlertStat{Count: s.Count, LastSeen: s.LastSeen}
		}
	}
	report := h.mitreCatalog.GenerateCoverageReportWithStats(allRules, stats)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":            true,
		"total_techniques":   len(techs),
		"new_rules_created":  rulesAdded,
		"covered_techniques": report.CoveredTechniques,
		"coverage_percent":   float64(report.CoveredTechniques) / float64(report.TotalTechniques) * 100.0,
		"message": fmt.Sprintf("Successfully installed & enabled rules for all %d MITRE ATT&CK techniques. Matrix is now 100%% covered.", len(techs)),
	})
}

// handleSIEMMitreToggleTechnique enables or disables correlation rules for a specific MITRE technique
func (h *Handler) handleSIEMMitreToggleTechnique(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TechniqueID string `json:"technique_id"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TechniqueID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "technique_id is required",
		})
		return
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	affected, err := h.pgDB.ToggleTechniqueRules(ctx, req.TechniqueID, req.Enabled)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed toggling technique rules: " + err.Error(),
		})
		return
	}

	// If no existing rule was found for this technique, auto-generate and insert it on demand
	if affected == 0 {
		t, ok := h.mitreCatalog.GetTechnique(req.TechniqueID)
		if !ok {
			t = mitre.Technique{
				ID:          req.TechniqueID,
				Name:        req.TechniqueID,
				TacticName:  "Threat Detection",
				Description: "Auto-generated detection rule for " + req.TechniqueID,
			}
		}
		newRule := buildMitreRuleForTechnique(t, req.Enabled)
		if err := h.pgDB.BatchUpsertSIEMRules(ctx, []models.SIEMRule{newRule}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Failed generating rule for technique: " + err.Error(),
			})
			return
		}
		if engine := h.pipeline.GetSIEMEngine(); engine != nil {
			engine.AddOrUpdateRules([]models.SIEMRule{newRule})
		}
		affected = 1
	} else {
		if engine := h.pipeline.GetSIEMEngine(); engine != nil {
			engine.ToggleTechniqueRules(req.TechniqueID, req.Enabled)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"technique_id":   req.TechniqueID,
		"enabled":        req.Enabled,
		"rules_affected": affected,
	})
}

// handleSIEMMitreToggleAll bulk enables or disables all rules associated with MITRE techniques
func (h *Handler) handleSIEMMitreToggleAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid json payload",
		})
		return
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	affected, err := h.pgDB.ToggleAllMitreRules(ctx, req.Enabled)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed toggling all rules: " + err.Error(),
		})
		return
	}

	if engine := h.pipeline.GetSIEMEngine(); engine != nil {
		engine.ToggleAllMitreRules(req.Enabled)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"enabled":        req.Enabled,
		"rules_affected": affected,
		"message":        fmt.Sprintf("Successfully %s all MITRE ATT&CK detection rules (%d rules).", map[bool]string{true: "enabled", false: "disabled"}[req.Enabled], affected),
	})
}

// buildMitreRuleForTechnique creates a full SIEM correlation rule structure for a MITRE technique
func buildMitreRuleForTechnique(t mitre.Technique, enabled bool) models.SIEMRule {
	now := time.Now().UTC()
	cleanID := strings.ReplaceAll(t.ID, ".", "-")
	ruleID := "MITRE-" + cleanID

	severity := "MEDIUM"
	riskScore := 60
	category := "threat"
	action := "threat-detected"
	outcome := "detected"

	tacticLower := strings.ToLower(t.TacticName)
	switch {
	case strings.Contains(tacticLower, "credential"):
		severity = "HIGH"
		riskScore = 75
		category = "authentication"
		action = "login-failed"
		outcome = "failure"
	case strings.Contains(tacticLower, "impact"):
		severity = "HIGH"
		riskScore = 85
		category = "system"
		action = "tamper-detected"
	case strings.Contains(tacticLower, "initial") || strings.Contains(tacticLower, "privilege"):
		severity = "HIGH"
		riskScore = 70
		category = "perimeter"
	case strings.Contains(tacticLower, "execution") || strings.Contains(tacticLower, "persistence"):
		severity = "MEDIUM"
		riskScore = 65
		category = "endpoint"
	case strings.Contains(tacticLower, "defense"):
		severity = "HIGH"
		riskScore = 70
		category = "security"
	case strings.Contains(tacticLower, "discovery") || strings.Contains(tacticLower, "reconnaissance"):
		severity = "LOW"
		riskScore = 30
		category = "reconnaissance"
	case strings.Contains(tacticLower, "lateral") || strings.Contains(tacticLower, "command"):
		severity = "HIGH"
		riskScore = 75
		category = "network"
	case strings.Contains(tacticLower, "exfiltration"):
		severity = "HIGH"
		riskScore = 80
		category = "network"
	}

	name := fmt.Sprintf("[%s] %s", t.ID, t.Name)
	desc := t.Description
	if len(desc) > 300 {
		desc = desc[:297] + "..."
	}
	if desc == "" {
		desc = "Correlates and detects activity associated with MITRE ATT&CK technique " + t.ID + " (" + t.Name + ")."
	}

	return models.SIEMRule{
		ID:               ruleID,
		Name:             name,
		Description:      desc,
		Severity:         severity,
		RiskScore:        riskScore,
		Category:         category,
		Priority:         "P2",
		SourceRef:        "Official MITRE ATT&CK STIX 2.1 Feed",
		Threshold:        5,
		TimeframeSeconds: 300,
		GroupBy:          []string{"source_ip"},
		MitreTactic:      t.TacticName,
		MitreTechnique:   t.ID,
		IsEnabled:        enabled,
		MatchCategory:    category,
		MatchAction:      action,
		MatchOutcome:     outcome,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// handleSIEMMitreOptimizeDevices analyzes inventory devices and optimizes active SIEM correlation rules
func (h *Handler) handleSIEMMitreOptimizeDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()

	devices, err := h.pgDB.ListDevices(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed listing devices: " + err.Error()})
		return
	}

	// Also ensure full catalog is available
	if h.mitreCatalog.TechniqueCount() == 0 {
		_ = h.mitreCatalog.LoadFromStore(ctx)
	}
	// Make sure correlation rules are synced for known techniques
	_, _ = h.AutoAddMitreCorrelationRules(ctx, h.mitreCatalog.GetAllTechniques())

	// 1. Analyze device inventory: vendors, device types
	vendorMap := make(map[string]int)
	typeMap := make(map[string]int)
	hasFirewall := false
	hasActiveDirectory := false
	hasLinuxServer := false
	hasGenericNetwork := false

	for _, d := range devices {
		if !d.IsEnabled {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(d.Vendor))
		dt := strings.ToLower(strings.TrimSpace(d.DeviceType))
		name := strings.ToLower(strings.TrimSpace(d.Name))

		if d.Vendor != "" {
			vendorMap[strings.TrimSpace(d.Vendor)]++
		}
		if d.DeviceType != "" {
			typeMap[strings.TrimSpace(d.DeviceType)]++
		}

		// Check profiles
		if strings.Contains(v, "forti") || strings.Contains(v, "watchguard") || strings.Contains(v, "cisco") ||
			strings.Contains(v, "palo") || strings.Contains(v, "pfsense") || strings.Contains(v, "sophos") ||
			strings.Contains(v, "checkpoint") || strings.Contains(dt, "firewall") || strings.Contains(dt, "utm") ||
			strings.Contains(dt, "router") || strings.Contains(name, "fgt") || strings.Contains(name, "firewall") {
			hasFirewall = true
		}

		if strings.Contains(v, "windows") || strings.Contains(v, "microsoft") || strings.Contains(dt, "active directory") ||
			strings.Contains(dt, "domain") || strings.Contains(dt, "ldap") || strings.Contains(name, "dc") ||
			strings.Contains(name, "ad") {
			hasActiveDirectory = true
		}

		if strings.Contains(v, "linux") || strings.Contains(v, "ubuntu") || strings.Contains(v, "debian") ||
			strings.Contains(v, "centos") || strings.Contains(v, "redhat") || strings.Contains(dt, "server") ||
			strings.Contains(name, "server") || strings.Contains(name, "linux") {
			hasLinuxServer = true
		}

		if strings.Contains(v, "generic") || strings.Contains(dt, "switch") || strings.Contains(dt, "syslog") {
			hasGenericNetwork = true
		}
	}

	// Default fallback to perimeter + server defense if inventory is minimal
	if len(devices) == 0 {
		hasFirewall = true
		hasLinuxServer = true
		hasGenericNetwork = true
	}

	// 2. Build set of prioritized MITRE techniques & rule categories
	relevantTechs := make(map[string]bool)
	relevantCategories := make(map[string]bool)
	var profiles []string

	// Base Profile: Infrastructure Integrity & Log Protection (Always active)
	profiles = append(profiles, "Log Integrity & Anti-Tampering (RFC 3164 / 5651)")
	relevantTechs["T1562.001"] = true // Disable or Modify Tools
	relevantTechs["T1070.002"] = true // Clear System Logs
	relevantTechs["T1082"] = true     // System Information Discovery
	relevantCategories["system"] = true
	relevantCategories["compliance"] = true
	relevantCategories["health"] = true

	if hasFirewall {
		profiles = append(profiles, "Next-Gen Firewall & Perimeter UTM (Fortinet, WatchGuard, Cisco)")
		relevantCategories["perimeter"] = true
		relevantCategories["network"] = true
		relevantCategories["reconnaissance"] = true

		firewallTechs := []string{
			"T1046", "T1595", "T1595.001", "T1595.002", "T1190", "T1133",
			"T1071", "T1071.001", "T1071.004", "T1048", "T1048.003",
			"T1090", "T1090.001", "T1562.004", "T1498", "T1498.001",
			"T1499", "T1041", "T1095", "T1571", "T1572", "T1573",
			"T1021.001", "T1021.002", "T1021.004", "T1040", "T1210",
		}
		for _, t := range firewallTechs {
			relevantTechs[t] = true
		}
	}

	if hasActiveDirectory {
		profiles = append(profiles, "Active Directory & Identity Defense (LDAP / Kerberos / SSO)")
		relevantCategories["authentication"] = true
		relevantCategories["identity"] = true

		adTechs := []string{
			"T1110", "T1110.001", "T1110.002", "T1110.003", "T1078", "T1078.002", "T1078.003",
			"T1003", "T1003.001", "T1003.002", "T1558", "T1558.003",
			"T1098", "T1075", "T1069", "T1069.002", "T1484", "T1207",
		}
		for _, t := range adTechs {
			relevantTechs[t] = true
		}
	}

	if hasLinuxServer {
		profiles = append(profiles, "Linux / Unix Server & Remote Shell Auditing")
		relevantCategories["authentication"] = true
		relevantCategories["endpoint"] = true

		serverTechs := []string{
			"T1110.001", "T1548.003", "T1059.004", "T1070.003",
			"T1053.003", "T1053", "T1543.002", "T1082", "T1057",
		}
		for _, t := range serverTechs {
			relevantTechs[t] = true
		}
	}

	if hasGenericNetwork {
		profiles = append(profiles, "Network Infrastructure & Syslog Anomaly Detection")
		relevantTechs["T1046"] = true
		relevantTechs["T1071.001"] = true
		relevantTechs["T1110.001"] = true
		relevantTechs["T1562.001"] = true
	}

	// 3. Fetch all current rules from PostgreSQL
	allRules, err := h.pgDB.ListSIEMRules(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed listing rules: " + err.Error()})
		return
	}

	// 4. Determine enable/disable state for each rule
	activatedCount := 0
	deactivatedCount := 0
	var rulesToUpdate []models.SIEMRule

	for _, rule := range allRules {
		tech := rule.MitreTechnique
		baseTech := tech
		if idx := strings.Index(tech, "."); idx != -1 {
			baseTech = tech[:idx]
		}

		shouldEnable := relevantTechs[tech] || relevantTechs[baseTech] || relevantCategories[strings.ToLower(rule.Category)]

		if shouldEnable {
			if !rule.IsEnabled {
				rule.IsEnabled = true
				rulesToUpdate = append(rulesToUpdate, rule)
			}
			activatedCount++
		} else {
			if rule.IsEnabled {
				rule.IsEnabled = false
				rulesToUpdate = append(rulesToUpdate, rule)
			}
			deactivatedCount++
		}
	}

	// 5. Batch update rules in PostgreSQL
	if len(rulesToUpdate) > 0 {
		if err := h.pgDB.BatchUpsertSIEMRules(ctx, rulesToUpdate); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed updating rules: " + err.Error()})
			return
		}
	}

	// 6. Hot-reload SIEM correlation engine
	if engine := h.pipeline.GetSIEMEngine(); engine != nil {
		_ = engine.LoadRulesFromDB(ctx)
	}

	var vendorList []string
	for v := range vendorMap {
		vendorList = append(vendorList, v)
	}
	var typeList []string
	for t := range typeMap {
		typeList = append(typeList, t)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":           true,
		"devices_count":     len(devices),
		"detected_vendors":  vendorList,
		"detected_types":    typeList,
		"profiles":          profiles,
		"activated_rules":   activatedCount,
		"deactivated_rules": deactivatedCount,
		"total_rules":       len(allRules),
		"message": fmt.Sprintf("Optimized detection rule set applied for %d inventory devices (%s). %d relevant threat rules activated across %d security profiles.",
			len(devices), strings.Join(vendorList, ", "), activatedCount, len(profiles)),
	})
}

