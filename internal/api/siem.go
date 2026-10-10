package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/notification/smtp"
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

	_ = h.pgDB.InsertAuditLog(ctx, &models.AuditLog{
		Username: username,
		SourceIP: r.RemoteAddr,
		Action:   "SIEM_MITRE_SYNC",
		Resource: "MITRE_ATTACK",
		Result:   "SUCCESS",
		Details: map[string]interface{}{
			"synced_techniques": count,
			"source":            req.URL,
			"file_path":         req.FilePath,
		},
		CreatedAt: time.Now().UTC(),
	})

	status := h.mitreCatalog.GenerateCoverageReportWithStats(nil, nil)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":           true,
		"synced_techniques": count,
		"attack_version":    status.AttackVersion,
		"total_techniques":  status.TotalTechniques,
		"new_techniques":    status.NewTechniques,
		"message": fmt.Sprintf("%s loaded: %d techniques (%d parent / %d sub-techniques), %d new since previous release. Saved to database.",
			status.Version, status.TotalTechniques, status.TotalParent, status.TotalSub, status.NewTechniques),
	})
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

	existingRules, err := h.pgDB.ListSIEMRules(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed listing existing rules: " + err.Error(),
		})
		return
	}

	coveredMap := make(map[string]bool)
	for _, rule := range existingRules {
		if rule.MitreTechnique != "" {
			coveredMap[rule.MitreTechnique] = true
		}
	}

	var rulesToInsert []models.SIEMRule
	for _, t := range techs {
		if !coveredMap[t.ID] {
			rule := buildMitreRuleForTechnique(t, true)
			rulesToInsert = append(rulesToInsert, rule)
		}
	}

	if len(rulesToInsert) > 0 {
		if err := h.pgDB.BatchUpsertSIEMRules(ctx, rulesToInsert); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Failed batch upserting rules: " + err.Error(),
			})
			return
		}
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
		"new_rules_created":  len(rulesToInsert),
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

