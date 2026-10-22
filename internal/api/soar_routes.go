package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// handleSOARStats returns overview statistics for SOAR dashboard cards
func (h *Handler) handleSOARStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant := h.tenantScope(r)
	stats, err := h.pgDB.GetSOARStats(r.Context(), tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed retrieving SOAR stats: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleSOARPlaybooks lists all playbooks or creates a new one
func (h *Handler) handleSOARPlaybooks(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)

	switch r.Method {
	case http.MethodGet:
		playbooks, err := h.pgDB.ListPlaybooks(r.Context(), tenant)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed retrieving playbooks: "+err.Error())
			return
		}
		if playbooks == nil {
			playbooks = []*models.SOARPlaybook{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"playbooks": playbooks,
			"total":     len(playbooks),
		})

	case http.MethodPost:
		var pb models.SOARPlaybook
		if err := json.NewDecoder(r.Body).Decode(&pb); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid playbook JSON payload")
			return
		}
		if strings.TrimSpace(pb.Name) == "" {
			writeError(w, http.StatusBadRequest, "Playbook name is required")
			return
		}
		if pb.ExecutionMode != "autonomous" && pb.ExecutionMode != "manual_approval" {
			pb.ExecutionMode = "manual_approval"
		}
		if tenant != "" && tenant != "all" {
			pb.TenantSlug = tenant
		} else if pb.TenantSlug == "" {
			pb.TenantSlug = "default"
		}
		if pb.CooldownMinutes <= 0 {
			pb.CooldownMinutes = 5
		}

		if err := h.pgDB.CreatePlaybook(r.Context(), &pb); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed saving playbook: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pb)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSOARPlaybookDetail handles GET, PUT, and DELETE for /api/v1/soar/playbooks/{id}
func (h *Handler) handleSOARPlaybookDetail(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "Missing playbook ID", http.StatusBadRequest)
		return
	}

	idStr := parts[4]
	pbID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid playbook UUID")
		return
	}

	switch r.Method {
	case http.MethodGet:
		pb, err := h.pgDB.GetPlaybookByID(r.Context(), tenant, pbID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error: "+err.Error())
			return
		}
		if pb == nil {
			writeError(w, http.StatusNotFound, "Playbook not found")
			return
		}
		writeJSON(w, http.StatusOK, pb)

	case http.MethodPut:
		var pb models.SOARPlaybook
		if err := json.NewDecoder(r.Body).Decode(&pb); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid payload")
			return
		}
		pb.ID = pbID
		if pb.ExecutionMode != "autonomous" && pb.ExecutionMode != "manual_approval" {
			pb.ExecutionMode = "manual_approval"
		}
		if err := h.pgDB.UpdatePlaybook(r.Context(), &pb); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed updating playbook: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pb)

	case http.MethodDelete:
		if err := h.pgDB.DeletePlaybook(r.Context(), tenant, pbID); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed deleting playbook: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSOARPlaybookToggle toggles is_enabled on a playbook
func (h *Handler) handleSOARPlaybookToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant := h.tenantScope(r)

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	pbID, err := uuid.Parse(req.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid playbook UUID")
		return
	}

	isEnabled, err := h.pgDB.TogglePlaybook(r.Context(), tenant, pbID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed toggling playbook: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         pbID,
		"is_enabled": isEnabled,
	})
}

// handleSOARExecutions lists execution logs with pagination and status filters
func (h *Handler) handleSOARExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant := h.tenantScope(r)

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}
	status := r.URL.Query().Get("status")

	executions, err := h.pgDB.ListExecutions(r.Context(), tenant, limit, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed retrieving executions: "+err.Error())
		return
	}
	if executions == nil {
		executions = []*models.SOARPlaybookExecution{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"executions": executions,
		"total":      len(executions),
	})
}

// handleSOARExecutionDetail retrieves a single execution record
func (h *Handler) handleSOARExecutionDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant := h.tenantScope(r)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "Missing execution ID", http.StatusBadRequest)
		return
	}

	execID, err := uuid.Parse(parts[4])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid execution UUID")
		return
	}

	exec, err := h.pgDB.GetExecutionByID(r.Context(), tenant, execID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error: "+err.Error())
		return
	}
	if exec == nil {
		writeError(w, http.StatusNotFound, "Execution record not found")
		return
	}
	writeJSON(w, http.StatusOK, exec)
}

// handleSOARExecutionApprove approves and triggers a pending execution
func (h *Handler) handleSOARExecutionApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant := h.tenantScope(r)
	username := h.currentUsername(r)

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	execID, err := uuid.Parse(req.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid execution UUID")
		return
	}

	if h.soarEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "SOAR engine is not active")
		return
	}

	exec, err := h.soarEngine.ApproveAndExecute(r.Context(), tenant, execID, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed approving execution: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"execution": exec,
	})
}

// handleSOARExecutionReject rejects a pending execution
func (h *Handler) handleSOARExecutionReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant := h.tenantScope(r)
	username := h.currentUsername(r)

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	execID, err := uuid.Parse(req.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid execution UUID")
		return
	}

	if h.soarEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "SOAR engine is not active")
		return
	}

	exec, err := h.soarEngine.RejectExecution(r.Context(), tenant, execID, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed rejecting execution: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"execution": exec,
	})
}

// handleSOARPlaybookRun manually dispatches a playbook against a target agent or alert
func (h *Handler) handleSOARPlaybookRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant := h.tenantScope(r)
	username := h.currentUsername(r)

	var req struct {
		PlaybookID string `json:"playbook_id"`
		AgentID    string `json:"agent_id"`
		AlertID    string `json:"alert_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	pbUUID, err := uuid.Parse(req.PlaybookID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid playbook UUID")
		return
	}

	pb, err := h.pgDB.GetPlaybookByID(r.Context(), tenant, pbUUID)
	if err != nil || pb == nil {
		writeError(w, http.StatusNotFound, "Playbook not found")
		return
	}

	var alert *models.SIEMAlert
	if req.AlertID != "" {
		if alUUID, err := uuid.Parse(req.AlertID); err == nil {
			alert, _, _ = h.pgDB.GetSIEMAlert(r.Context(), alUUID)
		}
	}

	var agent *models.EndpointAgent
	if req.AgentID != "" {
		if agUUID, err := uuid.Parse(req.AgentID); err == nil {
			agent, _ = h.pgDB.GetAgentByID(r.Context(), agUUID, tenant)
		}
	}

	// Fallback: match agent from alert if not provided explicitly
	if agent == nil && alert != nil {
		agent, _ = h.pgDB.FindAgentForAlert(r.Context(), tenant, alert.DeviceName, alert.SourceIP, alert.DestinationIP)
	}

	if h.soarEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "SOAR engine is not active")
		return
	}

	triggeredBy := "Manual Run by " + username
	if alert != nil {
		triggeredBy = "Manual Incident Run by " + username + " (" + alert.RuleName + ")"
	}

	exec, err := h.soarEngine.ExecutePlaybook(r.Context(), pb, alert, agent, triggeredBy, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Execution failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"execution": exec,
	})
}
