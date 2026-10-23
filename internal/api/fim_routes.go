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

// handleAgentFIM processes batched FIM deviations and baselines submitted by native agents
func (h *Handler) handleAgentFIM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentFIMSubmission
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
	agentID, tenantSlug, hostname, ipAddress, osType, err := h.pgDB.ResolveAgentByUUID(r.Context(), agentUUID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent not found or unenrolled"})
		return
	}

	// Enrich events with agent identity if omitted
	for i := range req.Events {
		req.Events[i].AgentID = agentID
		req.Events[i].TenantSlug = tenantSlug
		if req.Events[i].AgentHostname == "" {
			req.Events[i].AgentHostname = hostname
		}
		if req.Events[i].AgentIP == "" {
			req.Events[i].AgentIP = ipAddress
		}
		if req.Events[i].AgentOS == "" {
			req.Events[i].AgentOS = osType
		}
		if req.Events[i].Timestamp.IsZero() {
			req.Events[i].Timestamp = time.Now().UTC()
		}

		// MITRE ATT&CK Enrichment if not set
		if req.Events[i].MITRETactic == "" {
			switch strings.ToLower(req.Events[i].TargetType) {
			case "registry":
				req.Events[i].MITRETactic = "Persistence"
				req.Events[i].MITRETechnique = "T1547.001" // Registry Run Keys / Startup Folder
			default:
				if strings.Contains(req.Events[i].TargetPath, "cron") || strings.Contains(req.Events[i].TargetPath, "systemd") {
					req.Events[i].MITRETactic = "Persistence"
					req.Events[i].MITRETechnique = "T1053" // Scheduled Task/Job
				} else if strings.Contains(req.Events[i].TargetPath, "passwd") || strings.Contains(req.Events[i].TargetPath, "shadow") || strings.Contains(req.Events[i].TargetPath, "sudoers") {
					req.Events[i].MITRETactic = "Privilege Escalation"
					req.Events[i].MITRETechnique = "T1548" // Abuse Elevation Control Mechanism
				} else {
					req.Events[i].MITRETactic = "Defense Evasion"
					req.Events[i].MITRETechnique = "T1565.001" // Stored Data Manipulation
				}
			}
		}
	}

	// Save events to PostgreSQL
	if len(req.Events) > 0 {
		if err := h.pgDB.SaveFIMEvents(r.Context(), tenantSlug, agentID, req.Events); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "saving fim events: " + err.Error()})
			return
		}

		// Correlate Critical and High FIM deviations directly into SIEM & SOAR Engine
		if h.siemEngine != nil {
			for _, ev := range req.Events {
				if ev.Severity == "CRITICAL" || ev.Severity == "HIGH" {
					alertID := uuid.New()
					alert := &models.SIEMAlert{
						ID:             alertID,
						RuleID:         "FIM-INTEGRITY-BREACH",
						RuleName:       fmt.Sprintf("FIM Integrity Deviation: %s %s", strings.ToUpper(ev.EventType), ev.TargetPath),
						Severity:       ev.Severity,
						Tenant:         tenantSlug,
						DeviceName:     hostname,
						SourceIP:       ipAddress,
						Category:       "endpoint_fim",
						EventCount:     1,
						FirstSeen:      ev.Timestamp,
						LastSeen:       ev.Timestamp,
						Status:         "NEW",
						MitreTactic:    ev.MITRETactic,
						MitreTechnique: ev.MITRETechnique,
						RiskScore:      90,
						Summary:        fmt.Sprintf("Host '%s' reported unauthorized %s of critical %s: %s (SHA256: %s)", hostname, ev.EventType, ev.TargetType, ev.TargetPath, ev.CurrentHash),
						CreatedAt:      ev.Timestamp,
					}
					h.siemEngine.DispatchDirectAlert(alert)
				}
			}
		}
	}

	// Save baselines if provided
	if len(req.BaselineItems) > 0 {
		_ = h.pgDB.SaveFIMBaselines(r.Context(), tenantSlug, agentID, req.BaselineItems)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "ok",
		"events_saved":    len(req.Events),
		"baselines_saved": len(req.BaselineItems),
	})
}

// handleEndpointFIMSummary returns high-level metrics for File & Registry Integrity Monitoring
func (h *Handler) handleEndpointFIMSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	summary, err := h.pgDB.GetFIMSummary(r.Context(), tenant)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

// handleEndpointFIMEvents queries FIM deviation history with filters
func (h *Handler) handleEndpointFIMEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	eventType := strings.TrimSpace(r.URL.Query().Get("event_type"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 && val <= 200 {
			limit = val
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 {
			offset = val
		}
	}

	events, total, err := h.pgDB.ListFIMEvents(r.Context(), tenant, agentID, severity, eventType, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if events == nil {
		events = []models.FIMEvent{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// handleEndpointFIMEventDetail returns single FIM event details
func (h *Handler) handleEndpointFIMEventDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/endpoint/fim/events/")
	idStr := strings.TrimSpace(path)
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid event uuid", http.StatusBadRequest)
		return
	}

	tenant := h.tenantScope(r)
	event, err := h.pgDB.GetFIMEventByID(r.Context(), id, tenant)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "fim event not found"})
		return
	}

	writeJSON(w, http.StatusOK, event)
}

// handleEndpointFIMBaselines returns current hash baselines for an endpoint
func (h *Handler) handleEndpointFIMBaselines(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	agentIDStr := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	if agentIDStr == "" {
		http.Error(w, "agent_id query parameter required", http.StatusBadRequest)
		return
	}

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		http.Error(w, "invalid agent_id uuid", http.StatusBadRequest)
		return
	}

	baselines, err := h.pgDB.ListFIMBaselines(r.Context(), tenant, agentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if baselines == nil {
		baselines = []models.FIMBaselineItem{}
	}

	writeJSON(w, http.StatusOK, baselines)
}
