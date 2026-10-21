package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

	// Standard default policy config
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

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// handleEndpointEnrollmentTokenRevoke revokes an existing token
func (h *Handler) handleEndpointEnrollmentTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/endpoint/enrollment/tokens/")
	idStr := strings.TrimSpace(path)
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token id"})
		return
	}

	tenant := h.tenantScope(r)
	if err := h.pgDB.RevokeEnrollmentToken(r.Context(), id, tenant); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "ENROLLMENT_TOKEN_REVOKED", "endpoint/enrollment_token", "SUCCESS", map[string]interface{}{
		"token_id": id.String(),
	})

	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}
