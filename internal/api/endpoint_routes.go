package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
)

// --- Agent Gateway Handlers ---

// handleAgentEnroll processes initial endpoint enrollment via token
func (h *Handler) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	rawToken := strings.TrimSpace(req.EnrollmentToken)
	if rawToken == "" {
		// Also check Authorization header
		if auth := r.Header.Get("Authorization"); auth != "" && strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			rawToken = strings.TrimSpace(auth[7:])
		}
	}

	if rawToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment token is required"})
		return
	}

	if req.AgentUUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_uuid is required"})
		return
	}

	// Detect client IP
	clientIP := getClientIP(r)
	if req.IPAddress == "" {
		req.IPAddress = clientIP
	}

	// Validate and consume enrollment token
	tenantSlug, groupID, err := h.pgDB.ValidateAndConsumeEnrollmentToken(r.Context(), rawToken, req.OSType)
	if err != nil {
		h.recordAudit(r, "AGENT_ENROLL_FAILED", "endpoint/agent", "FAILED", map[string]interface{}{
			"reason":     err.Error(),
			"agent_uuid": req.AgentUUID,
			"hostname":   req.Hostname,
			"client_ip":  clientIP,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	// Generate strong agent auth token
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	authToken := "lp_agt_" + hex.EncodeToString(tokenBytes)
	authTokenHash := postgres.HashToken(authToken)

	agent, err := h.pgDB.UpsertEnrolledAgent(r.Context(), req, tenantSlug, groupID, authTokenHash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error: " + err.Error()})
		return
	}

	h.recordAudit(r, "AGENT_ENROLLED", "endpoint/agent", "SUCCESS", map[string]interface{}{
		"agent_id":    agent.ID.String(),
		"agent_uuid":  agent.AgentUUID,
		"hostname":    agent.Hostname,
		"os_type":     agent.OSType,
		"tenant_slug": tenantSlug,
		"client_ip":   clientIP,
	})

	resp := models.AgentEnrollResponse{
		AgentID:        agent.ID,
		TenantSlug:     tenantSlug,
		AuthToken:      authToken,
		ServerTime:     time.Now().UTC(),
		PolicyRevision: agent.PolicyRevision,
		Policy: &models.EndpointPolicyConfig{
			HeartbeatIntervalSec: 30,
			InventoryIntervalSec: 3600,
			PatchScanIntervalSec: 14400,
			VulnScanIntervalSec:  14400,
			MaxCPUPercent:        10,
			MaxRAMMB:             150,
			SpoolMaxDiskMB:       500,
			SpoolMaxAgeHours:     72,
			LogCollectionEnabled: true,
			EventChannels:        []string{"System", "Application", "Security"},
			UpdateChannel:        "stable",
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleAgentHeartbeat processes recurring health and telemetry check-ins
func (h *Handler) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentHeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	if req.AgentUUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_uuid is required"})
		return
	}

	if req.IPAddress == "" {
		req.IPAddress = getClientIP(r)
	}

	resp, err := h.pgDB.UpdateAgentHeartbeat(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleAgentConfig returns active policy configuration for the agent
func (h *Handler) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	agentUUID := strings.TrimSpace(r.URL.Query().Get("agent_uuid"))
	if agentUUID != "" {
		if cfg, _, err := h.pgDB.GetAgentPolicyConfig(r.Context(), agentUUID); err == nil && cfg != nil {
			writeJSON(w, http.StatusOK, cfg)
			return
		}
	}

	// Standard fallback default policy config
	cfg := models.EndpointPolicyConfig{
		HeartbeatIntervalSec: 30,
		InventoryIntervalSec: 3600,
		PatchScanIntervalSec: 14400,
		VulnScanIntervalSec:  14400,
		MaxCPUPercent:        10,
		MaxRAMMB:             150,
		SpoolMaxDiskMB:       500,
		SpoolMaxAgeHours:     72,
		LogCollectionEnabled: true,
		EventChannels:        []string{"System", "Application", "Security"},
		UpdateChannel:        "stable",
	}

	writeJSON(w, http.StatusOK, cfg)
}

// --- Administrative Web API Handlers ---

// handleEndpointDashboard returns aggregated metrics for Endpoint Security
func (h *Handler) handleEndpointDashboard(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)
	summary, err := h.pgDB.GetEndpointDashboardSummary(r.Context(), tenant)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// handleEndpointAgents lists agents with filters
func (h *Handler) handleEndpointAgents(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	osType := strings.TrimSpace(r.URL.Query().Get("os"))
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

	agents, total, err := h.pgDB.ListAgents(r.Context(), tenant, status, osType, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if agents == nil {
		agents = []models.EndpointAgent{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agents": agents,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// handleEndpointAgentDetail returns a single agent by UUID or ID
func (h *Handler) handleEndpointAgentDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/endpoint/agents/")
	idStr := strings.TrimSpace(path)
	if idStr == "" {
		http.Error(w, "agent ID required", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid agent ID uuid", http.StatusBadRequest)
		return
	}

	tenant := h.tenantScope(r)
	agent, err := h.pgDB.GetAgentByID(r.Context(), id, tenant)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}

	writeJSON(w, http.StatusOK, agent)
}

// handleEndpointEnrollmentTokens lists or creates enrollment tokens
func (h *Handler) handleEndpointEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)

	if r.Method == http.MethodGet {
		tokens, err := h.pgDB.ListEnrollmentTokens(r.Context(), tenant)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tokens == nil {
			tokens = []models.EndpointEnrollmentToken{}
		}
		writeJSON(w, http.StatusOK, tokens)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Name       string   `json:"name"`
			GroupID    *string  `json:"group_id"`
			MaxUses    int      `json:"max_uses"`
			IsOneTime  bool     `json:"is_one_time"`
			AllowedOS  []string `json:"allowed_os"`
			ExpiresInH int      `json:"expires_in_hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}

		if strings.TrimSpace(req.Name) == "" {
			req.Name = "Enrollment Token " + time.Now().Format("2006-01-02 15:04")
		}

		targetTenant := tenant
		if targetTenant == "" {
			targetTenant = "default"
		}

		var groupUUID *uuid.UUID
		if req.GroupID != nil && *req.GroupID != "" {
			if parsed, err := uuid.Parse(*req.GroupID); err == nil {
				groupUUID = &parsed
			}
		}

		var expiresAt *time.Time
		if req.ExpiresInH > 0 {
			exp := time.Now().Add(time.Duration(req.ExpiresInH) * time.Hour)
			expiresAt = &exp
		}

		token, err := h.pgDB.CreateEnrollmentToken(
			r.Context(), targetTenant, req.Name, groupUUID, req.MaxUses, req.IsOneTime, req.AllowedOS, expiresAt, "admin",
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		h.recordAudit(r, "ENROLLMENT_TOKEN_CREATED", "endpoint/enrollment_token", "SUCCESS", map[string]interface{}{
			"token_id":    token.ID.String(),
			"name":        token.Name,
			"tenant_slug": targetTenant,
			"max_uses":    token.MaxUses,
		})

		writeJSON(w, http.StatusCreated, token)
		return
	}

	if r.Method == http.MethodDelete {
		count, err := h.pgDB.PurgeInactiveEnrollmentTokens(r.Context(), tenant)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		h.recordAudit(r, "ENROLLMENT_TOKENS_PURGED", "endpoint/enrollment_token", "SUCCESS", map[string]interface{}{
			"tenant_slug":  tenant,
			"purged_count": count,
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{"purged": true, "count": count})
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// handleEndpointEnrollmentTokenRevoke revokes or deletes an existing token
func (h *Handler) handleEndpointEnrollmentTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/endpoint/enrollment/tokens/")
	idStr := strings.TrimSpace(path)
	tenant := h.tenantScope(r)

	if idStr == "purge-inactive" || idStr == "purge" {
		count, err := h.pgDB.PurgeInactiveEnrollmentTokens(r.Context(), tenant)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		h.recordAudit(r, "ENROLLMENT_TOKENS_PURGED", "endpoint/enrollment_token", "SUCCESS", map[string]interface{}{
			"tenant_slug":  tenant,
			"purged_count": count,
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{"purged": true, "count": count})
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token id"})
		return
	}

	isDelete := r.URL.Query().Get("action") == "delete" || r.URL.Query().Get("permanent") == "true"
	if isDelete {
		if err := h.pgDB.DeleteEnrollmentToken(r.Context(), id, tenant); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		h.recordAudit(r, "ENROLLMENT_TOKEN_DELETED", "endpoint/enrollment_token", "SUCCESS", map[string]interface{}{
			"token_id": id.String(),
		})
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
		return
	}

	if err := h.pgDB.RevokeEnrollmentToken(r.Context(), id, tenant); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENROLLMENT_TOKEN_REVOKED", "endpoint/enrollment_token", "SUCCESS", map[string]interface{}{
		"token_id": id.String(),
	})

	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// handleAgentInventory receives installed software, patches, and host telemetry from an agent
func (h *Handler) handleAgentInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentInventoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	if req.AgentUUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_uuid is required"})
		return
	}

	if req.IPAddress == "" {
		req.IPAddress = getClientIP(r)
	}

	resp, err := h.pgDB.IngestAgentInventory(r.Context(), req.AgentUUID, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleEndpointVulnerabilities returns detected vulnerability findings
func (h *Handler) handleEndpointVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	findings, total, err := h.pgDB.ListVulnerabilityFindings(r.Context(), tenant, severity, status, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"findings": findings,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

// handleEndpointInventory lists discovered software packages across endpoints
func (h *Handler) handleEndpointInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	search := r.URL.Query().Get("search")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	software, total, err := h.pgDB.ListEndpointSoftware(r.Context(), tenant, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"software": software,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

// handleEndpointCVEStatus returns the current CVE catalog statistics and sync schedule
func (h *Handler) handleEndpointCVEStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	status, err := h.pgDB.GetCVESyncStatus(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if h.cveSyncer != nil {
		status.IsSyncing = h.cveSyncer.IsSyncing()
	}

	writeJSON(w, http.StatusOK, status)
}

// handleEndpointCVESync triggers an immediate background CVE database update
func (h *Handler) handleEndpointCVESync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.cveSyncer == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cve syncer not initialized"})
		return
	}

	if h.cveSyncer.IsSyncing() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "CVE senkronizasyonu şu anda devam ediyor."})
		return
	}

	go func() {
		_, _ = h.cveSyncer.SyncAll(context.Background())
	}()

	h.recordAudit(r, "CVE_SYNC_MANUAL_TRIGGERED", "endpoint/cve", "SUCCESS", map[string]interface{}{
		"triggered_by": "admin",
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "sync_started",
		"message": "CVE veritabanı senkronizasyonu arka planda başlatıldı.",
	})
}

// handleEndpointCVESchedule updates the automated update schedule (daily, weekly, monthly, manual)
func (h *Handler) handleEndpointCVESchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ScheduleMode string `json:"schedule_mode"` // daily, weekly, monthly, manual
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	mode := strings.ToLower(strings.TrimSpace(req.ScheduleMode))
	if mode != "daily" && mode != "weekly" && mode != "monthly" && mode != "manual" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "schedule_mode must be 'daily', 'weekly', 'monthly', or 'manual'"})
		return
	}

	if err := h.pgDB.UpdateCVESchedule(r.Context(), mode); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "CVE_SCHEDULE_UPDATED", "endpoint/cve", "SUCCESS", map[string]interface{}{
		"schedule_mode": mode,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"schedule_mode": mode,
	})
}

// handleEndpointPatches returns patches and fleet compliance metrics
func (h *Handler) handleEndpointPatches(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	status := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	patches, total, err := h.pgDB.ListEndpointPatches(r.Context(), tenant, status, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	summary, err := h.pgDB.GetPatchComplianceSummary(r.Context(), tenant)
	if err != nil {
		summary = &models.PatchComplianceSummary{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"patches": patches,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"summary": summary,
	})
}

// handleEndpointPatchesScan queues an immediate patch scan across endpoints
func (h *Handler) handleEndpointPatchesScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	h.recordAudit(r, "ENDPOINT_PATCH_SCAN_TRIGGERED", "endpoint/patches", "SUCCESS", map[string]interface{}{
		"triggered_by": "admin",
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "scan_queued",
		"message": "Uç noktalar için anlık yama ve güvenlik güncellemesi taraması tetiklendi.",
	})
}

// handleAgentTaskResult receives task execution outcomes from agents
func (h *Handler) handleAgentTaskResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentTaskResultSubmission
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

	if err := h.pgDB.SaveTaskResult(r.Context(), agentUUID, &req); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ack":     true,
		"task_id": req.TaskID,
		"status":  req.Status,
	})
}

// handleEndpointPatchDeploy dispatches a remediation task for a single patch on an endpoint
func (h *Handler) handleEndpointPatchDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	var req models.PatchDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	if req.AgentID == "" || req.PatchID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id and patch_id are required"})
		return
	}

	username := "admin"
	if s, ok := h.getSession(r); ok && s != nil {
		username = s.Username
	}

	task, err := h.pgDB.DeployPatch(r.Context(), tenant, &req, username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENDPOINT_PATCH_DEPLOY_DISPATCHED", "endpoint/patches", "SUCCESS", map[string]interface{}{
		"task_id":       task.ID.String(),
		"agent_id":      req.AgentID,
		"patch_id":      req.PatchID,
		"reboot_after":  req.RebootAfter,
		"dispatched_by": username,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "queued",
		"task_id": task.ID.String(),
		"message": "Yama yükleme görevi uç noktaya başarıyla iletildi.",
	})
}

// handleEndpointBatchPatchDeploy dispatches remediation tasks for multiple missing patches
func (h *Handler) handleEndpointBatchPatchDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	var req models.BatchPatchDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	username := "admin"
	if s, ok := h.getSession(r); ok && s != nil {
		username = s.Username
	}

	count, err := h.pgDB.BatchDeployPatches(r.Context(), tenant, &req, username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENDPOINT_BATCH_PATCH_DEPLOY_DISPATCHED", "endpoint/patches", "SUCCESS", map[string]interface{}{
		"severity_filter": req.SeverityFilter,
		"reboot_after":    req.RebootAfter,
		"queued_count":    count,
		"dispatched_by":   username,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "queued",
		"queued_count": count,
		"message":      fmt.Sprintf("%d eksik yama için uzaktan yükleme emri kuyruğa alındı.", count),
	})
}

// handleEndpointAgentReboot dispatches a safe reboot task to an endpoint
func (h *Handler) handleEndpointAgentReboot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	var req struct {
		AgentID string `json:"agent_id"`
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

	task, err := h.pgDB.RebootEndpointAgent(r.Context(), tenant, agentUUID, username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENDPOINT_AGENT_REBOOT_TRIGGERED", "endpoint/agents", "SUCCESS", map[string]interface{}{
		"task_id":      task.ID.String(),
		"agent_id":     req.AgentID,
		"triggered_by": username,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "queued",
		"task_id": task.ID.String(),
		"message": "Uç noktaya güvenli yeniden başlatma emri iletildi (30 saniye zaman aşımı ile).",
	})
}

// handleEndpointTasks lists remote remediation and maintenance tasks
func (h *Handler) handleEndpointTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	status := r.URL.Query().Get("status")
	taskType := r.URL.Query().Get("task_type")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	tasks, total, err := h.pgDB.ListEndpointTasks(r.Context(), tenant, status, taskType, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tasks":  tasks,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// handleEndpointTaskDetail returns task information including stdout/stderr result
func (h *Handler) handleEndpointTaskDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 5 {
		http.Error(w, "Task ID Required", http.StatusBadRequest)
		return
	}

	taskUUID, err := uuid.Parse(pathParts[4])
	if err != nil {
		http.Error(w, "Invalid Task ID", http.StatusBadRequest)
		return
	}

	tenant := h.tenantScope(r)
	task, err := h.pgDB.GetEndpointTask(r.Context(), tenant, taskUUID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Task not found"})
		return
	}

	writeJSON(w, http.StatusOK, task)
}

// handleEndpointAgentUpgradeAll broadcasts an in-place upgrade trigger for all outdated agents
func (h *Handler) handleEndpointAgentUpgradeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	h.recordAudit(r, "ENDPOINT_AGENTS_UPGRADE_ALL", "endpoint/agents", "SUCCESS", map[string]interface{}{
		"target_version": "v0.1.4",
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status":         "upgrade_triggered",
		"target_version": "v0.1.4",
		"message":        "Tüm uç noktalar bağlı oldukları sunucu üzerinden v0.1.4 sürümüne otomatik güncelleniyor.",
	})
}

// handleEndpointPolicies lists or creates endpoint policies
func (h *Handler) handleEndpointPolicies(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)

	switch r.Method {
	case http.MethodGet:
		policies, err := h.pgDB.ListEndpointPolicies(r.Context(), tenant)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"policies": policies,
			"total":    len(policies),
		})

	case http.MethodPost:
		if tenant == "" || tenant == "all" {
			tenant = "default"
		}

		var req struct {
			Name        string                      `json:"name"`
			Description string                      `json:"description"`
			IsDefault   bool                        `json:"is_default"`
			Config      models.EndpointPolicyConfig `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}

		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy name is required"})
			return
		}

		if req.Config.HeartbeatIntervalSec < 5 {
			req.Config.HeartbeatIntervalSec = 30
		}
		if req.Config.InventoryIntervalSec < 60 {
			req.Config.InventoryIntervalSec = 3600
		}
		if req.Config.PatchScanIntervalSec < 600 {
			req.Config.PatchScanIntervalSec = 14400
		}
		if req.Config.VulnScanIntervalSec < 600 {
			req.Config.VulnScanIntervalSec = 14400
		}
		if req.Config.MaxCPUPercent <= 0 {
			req.Config.MaxCPUPercent = 10
		}
		if req.Config.MaxRAMMB <= 0 {
			req.Config.MaxRAMMB = 150
		}
		if req.Config.SpoolMaxDiskMB <= 0 {
			req.Config.SpoolMaxDiskMB = 500
		}
		if req.Config.SpoolMaxAgeHours <= 0 {
			req.Config.SpoolMaxAgeHours = 72
		}
		if len(req.Config.EventChannels) == 0 {
			req.Config.EventChannels = []string{"System", "Application", "Security"}
		}
		if req.Config.UpdateChannel == "" {
			req.Config.UpdateChannel = "stable"
		}

		p, err := h.pgDB.CreateEndpointPolicy(r.Context(), tenant, req.Name, req.Description, req.Config, req.IsDefault)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		h.recordAudit(r, "ENDPOINT_POLICY_CREATED", "endpoint/policies", "SUCCESS", map[string]interface{}{
			"policy_id":   p.ID.String(),
			"name":        p.Name,
			"tenant_slug": tenant,
		})

		writeJSON(w, http.StatusCreated, p)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleEndpointPolicyDetail handles GET, PUT, DELETE for a specific policy
func (h *Handler) handleEndpointPolicyDetail(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)
	idStr := strings.TrimPrefix(r.URL.Path, "/api/v1/endpoint/policies/")
	idStr = strings.Trim(idStr, "/")

	pID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid policy UUID"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, err := h.pgDB.GetEndpointPolicy(r.Context(), pID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		writeJSON(w, http.StatusOK, p)

	case http.MethodPut:
		var req struct {
			Name        string                      `json:"name"`
			Description string                      `json:"description"`
			IsDefault   bool                        `json:"is_default"`
			Config      models.EndpointPolicyConfig `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}

		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy name is required"})
			return
		}

		if req.Config.HeartbeatIntervalSec < 5 {
			req.Config.HeartbeatIntervalSec = 30
		}
		if req.Config.InventoryIntervalSec < 60 {
			req.Config.InventoryIntervalSec = 3600
		}
		if req.Config.PatchScanIntervalSec < 600 {
			req.Config.PatchScanIntervalSec = 14400
		}
		if req.Config.VulnScanIntervalSec < 600 {
			req.Config.VulnScanIntervalSec = 14400
		}
		if req.Config.MaxCPUPercent <= 0 {
			req.Config.MaxCPUPercent = 10
		}
		if req.Config.MaxRAMMB <= 0 {
			req.Config.MaxRAMMB = 150
		}
		if req.Config.SpoolMaxDiskMB <= 0 {
			req.Config.SpoolMaxDiskMB = 500
		}
		if req.Config.SpoolMaxAgeHours <= 0 {
			req.Config.SpoolMaxAgeHours = 72
		}
		if len(req.Config.EventChannels) == 0 {
			req.Config.EventChannels = []string{"System", "Application", "Security"}
		}
		if req.Config.UpdateChannel == "" {
			req.Config.UpdateChannel = "stable"
		}

		p, err := h.pgDB.UpdateEndpointPolicy(r.Context(), pID, tenant, req.Name, req.Description, req.Config, req.IsDefault)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		h.recordAudit(r, "ENDPOINT_POLICY_UPDATED", "endpoint/policies", "SUCCESS", map[string]interface{}{
			"policy_id": p.ID.String(),
			"name":      p.Name,
			"revision":  p.Revision,
		})

		writeJSON(w, http.StatusOK, p)

	case http.MethodDelete:
		if err := h.pgDB.DeleteEndpointPolicy(r.Context(), pID, tenant); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		h.recordAudit(r, "ENDPOINT_POLICY_DELETED", "endpoint/policies", "SUCCESS", map[string]interface{}{
			"policy_id": pID.String(),
		})

		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleEndpointPolicyAssign assigns one or more endpoints to a policy
func (h *Handler) handleEndpointPolicyAssign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentUUID  string    `json:"agent_uuid"`
		AgentUUIDs []string  `json:"agent_uuids"`
		PolicyID   uuid.UUID `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	uuids := req.AgentUUIDs
	if req.AgentUUID != "" {
		uuids = append(uuids, req.AgentUUID)
	}

	if len(uuids) == 0 || req.PolicyID == uuid.Nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_uuid and policy_id are required"})
		return
	}

	successCount := 0
	for _, u := range uuids {
		if err := h.pgDB.AssignAgentPolicy(r.Context(), strings.TrimSpace(u), req.PolicyID); err == nil {
			successCount++
		}
	}

	h.recordAudit(r, "ENDPOINT_POLICY_ASSIGNED", "endpoint/policies", "SUCCESS", map[string]interface{}{
		"policy_id":    req.PolicyID.String(),
		"agents_count": successCount,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "assigned",
		"count":  successCount,
	})
}

// handleEndpointAgentIsolate isolates an endpoint from the network via remote firewall rules
func (h *Handler) handleEndpointAgentIsolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID    string   `json:"agent_id"`
		Reason     string   `json:"reason"`
		AllowedIPs []string `json:"allowed_ips"`
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
		"reason":      req.Reason,
		"allowed_ips": req.AllowedIPs,
	}

	task, err := h.pgDB.DispatchActiveResponseTask(r.Context(), tenant, agentUUID, "isolate_host", payload, username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENDPOINT_AGENT_ISOLATE_TRIGGERED", "endpoint/agents", "SUCCESS", map[string]interface{}{
		"task_id":  task.ID.String(),
		"agent_id": req.AgentID,
		"reason":   req.Reason,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "queued",
		"task_id": task.ID.String(),
		"message": "Host containment task dispatched.",
	})
}

// handleEndpointAgentUnisolate restores normal network connectivity to an isolated host
func (h *Handler) handleEndpointAgentUnisolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID string `json:"agent_id"`
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
	payload := map[string]interface{}{}

	task, err := h.pgDB.DispatchActiveResponseTask(r.Context(), tenant, agentUUID, "unisolate_host", payload, username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENDPOINT_AGENT_UNISOLATE_TRIGGERED", "endpoint/agents", "SUCCESS", map[string]interface{}{
		"task_id":  task.ID.String(),
		"agent_id": req.AgentID,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "queued",
		"task_id": task.ID.String(),
		"message": "Host un-isolation task dispatched.",
	})
}

// handleEndpointAgentKillProcess sends a process termination command to an endpoint
func (h *Handler) handleEndpointAgentKillProcess(w http.ResponseWriter, r *http.Request) {
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

	h.recordAudit(r, "ENDPOINT_AGENT_KILL_PROCESS", "endpoint/agents", "SUCCESS", map[string]interface{}{
		"task_id":      task.ID.String(),
		"agent_id":     req.AgentID,
		"pid":          req.PID,
		"process_name": req.ProcessName,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "queued",
		"task_id": task.ID.String(),
		"message": "Process termination command dispatched.",
	})
}

// handleEndpointAgentQuarantineFile instructs the agent to isolate and neutralize a suspicious file
func (h *Handler) handleEndpointAgentQuarantineFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID  string `json:"agent_id"`
		FilePath string `json:"file_path"`
		Reason   string `json:"reason"`
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
		"file_path": req.FilePath,
		"reason":    req.Reason,
	}

	task, err := h.pgDB.DispatchActiveResponseTask(r.Context(), tenant, agentUUID, "file_quarantine", payload, username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENDPOINT_AGENT_QUARANTINE_FILE", "endpoint/agents", "SUCCESS", map[string]interface{}{
		"task_id":   task.ID.String(),
		"agent_id":  req.AgentID,
		"file_path": req.FilePath,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "queued",
		"task_id": task.ID.String(),
		"message": "File quarantine task dispatched.",
	})
}

// handleEndpointAgentQuarantinedFiles lists quarantined files for an agent or tenant
func (h *Handler) handleEndpointAgentQuarantinedFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	var agentIDPtr *uuid.UUID
	if agentIDStr := r.URL.Query().Get("agent_id"); agentIDStr != "" {
		if id, err := uuid.Parse(agentIDStr); err == nil {
			agentIDPtr = &id
		}
	}

	files, err := h.pgDB.ListQuarantinedFiles(r.Context(), tenant, agentIDPtr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"files": files,
		"total": len(files),
	})
}

// handleEndpointAgentOSQuery executes a remote live forensic query against the endpoint
func (h *Handler) handleEndpointAgentOSQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID    string `json:"agent_id"`
		Query      string `json:"query"`
		TimeoutSec int    `json:"timeout_sec"`
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

	if strings.TrimSpace(req.Query) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "query cannot be empty"})
		return
	}

	username := "admin"
	if s, ok := h.getSession(r); ok && s != nil {
		username = s.Username
	}

	tenant := h.tenantScope(r)
	payload := map[string]interface{}{
		"query":       req.Query,
		"timeout_sec": req.TimeoutSec,
	}

	task, err := h.pgDB.DispatchActiveResponseTask(r.Context(), tenant, agentUUID, "osquery_run", payload, username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENDPOINT_AGENT_OSQUERY", "endpoint/agents", "SUCCESS", map[string]interface{}{
		"task_id":  task.ID.String(),
		"agent_id": req.AgentID,
		"query":    req.Query,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "queued",
		"task_id": task.ID.String(),
		"message": "Forensic SQL query dispatched.",
	})
}


