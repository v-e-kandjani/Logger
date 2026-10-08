package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
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
