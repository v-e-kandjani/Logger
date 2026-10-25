package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// handleEndpointAgentRansomware processes ransomware detections and honeypot canary tripwires submitted by native agents (Phase P)
func (h *Handler) handleEndpointAgentRansomware(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentRansomwareSubmission
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

	// Resolve agent context
	agentID, tenantSlug, hostname, ipAddress, _, err := h.pgDB.ResolveAgentByUUID(r.Context(), agentUUID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent not found or unenrolled"})
		return
	}

	now := time.Now().UTC()

	// Enrich and persist canary tokens
	for i := range req.Canaries {
		req.Canaries[i].AgentID = agentID
		req.Canaries[i].TenantSlug = tenantSlug
		req.Canaries[i].AgentHostname = hostname
		req.Canaries[i].LastCheckedAt = now
	}
	if len(req.Canaries) > 0 {
		_ = h.pgDB.UpsertCanaryTokens(r.Context(), req.Canaries)
	}

	// Enrich and persist ransomware incidents
	for i := range req.Incidents {
		req.Incidents[i].AgentID = agentID
		req.Incidents[i].TenantSlug = tenantSlug
		req.Incidents[i].AgentHostname = hostname
		req.Incidents[i].AgentIP = ipAddress
		if req.Incidents[i].CreatedAt.IsZero() {
			req.Incidents[i].CreatedAt = now
		}

		// Dispatch high-severity alert to SIEM correlation engine
		if h.siemEngine != nil {
			alert := &models.SIEMAlert{
				ID:             uuid.New(),
				RuleID:         "EDR-RANSOMWARE-DETECTED",
				RuleName:       fmt.Sprintf("Ransomware Activity Detected: %s on %s", req.Incidents[i].TriggerType, hostname),
				Severity:       "CRITICAL",
				Tenant:         tenantSlug,
				DeviceName:     hostname,
				SourceIP:       ipAddress,
				Category:       "endpoint_ransomware",
				EventCount:     1,
				FirstSeen:      now,
				LastSeen:       now,
				Status:         "NEW",
				MitreTactic:    req.Incidents[i].MitreTactic,
				MitreTechnique: req.Incidents[i].MitreTechnique,
				RiskScore:      98,
				Summary:        fmt.Sprintf("Host '%s': %s (Process: %s, PID: %d, Target: %s, Action: %s)", hostname, req.Incidents[i].TriggerType, req.Incidents[i].ProcessName, req.Incidents[i].ProcessPID, req.Incidents[i].TargetFile, req.Incidents[i].ActionTaken),
				CreatedAt:      now,
			}
			h.siemEngine.DispatchDirectAlert(alert)
		}
	}

	if len(req.Incidents) > 0 {
		if err := h.pgDB.RecordRansomwareIncidents(r.Context(), req.Incidents); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed recording incidents: " + err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":              "success",
		"incidents_processed": len(req.Incidents),
		"canaries_registered": len(req.Canaries),
	})
}

// handleEndpointRansomwareIncidents returns historical ransomware incidents
func (h *Handler) handleEndpointRansomwareIncidents(w http.ResponseWriter, r *http.Request) {
	tenantSlug := h.tenantScope(r)
	agentID := r.URL.Query().Get("agent_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	incidents, total, err := h.pgDB.ListRansomwareIncidents(r.Context(), tenantSlug, agentID, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"incidents": incidents,
		"total":     total,
	})
}

// handleEndpointCanaries returns active honeypot decoy files across the fleet
func (h *Handler) handleEndpointCanaries(w http.ResponseWriter, r *http.Request) {
	tenantSlug := h.tenantScope(r)
	agentID := r.URL.Query().Get("agent_id")

	canaries, err := h.pgDB.ListCanaryTokens(r.Context(), tenantSlug, agentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"canaries": canaries,
		"total":    len(canaries),
	})
}

// handleEndpointRansomwareStats returns aggregate KPI metrics for Phase P Anti-Ransomware Shield
func (h *Handler) handleEndpointRansomwareStats(w http.ResponseWriter, r *http.Request) {
	tenantSlug := h.tenantScope(r)

	stats, err := h.pgDB.GetRansomwareStats(r.Context(), tenantSlug)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// handleEndpointRansomwareSimulate triggers a synthetic ransomware tripwire for SOC operators
func (h *Handler) handleEndpointRansomwareSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantSlug := h.tenantScope(r)
	if tenantSlug == "" || tenantSlug == "all" {
		tenantSlug = "default"
	}

	// Fetch first active agent or synthesize demo agent
	agents, _, _ := h.pgDB.ListAgents(r.Context(), tenantSlug, "", "", "", 1, 0)
	var targetAgentID uuid.UUID
	targetHostname := "FINANCE-PC01.corp"
	targetIP := "192.168.10.45"

	if len(agents) > 0 {
		targetAgentID = agents[0].ID
		targetHostname = agents[0].Hostname
		targetIP = agents[0].IPAddress
	} else {
		targetAgentID = uuid.New()
	}

	now := time.Now().UTC()

	// 1. Create simulated canary token
	canary := models.EndpointCanaryToken{
		ID:            uuid.New(),
		TenantSlug:    tenantSlug,
		AgentID:       targetAgentID,
		AgentHostname: targetHostname,
		FilePath:      `C:\Users\CEO\Documents\.canary_q4_budget.docx`,
		FileType:      "docx",
		InitialHash:   "a3f5b891e2049d56c80214ef9081bc6214d02187a02b4ef891ca029384756192",
		Status:        "TRIGGERED",
		LastCheckedAt: now,
		TriggeredAt:   &now,
		CreatedAt:     now,
	}
	_ = h.pgDB.UpsertCanaryTokens(r.Context(), []models.EndpointCanaryToken{canary})

	// 2. Create simulated ransomware incident
	incident := models.EndpointRansomwareIncident{
		ID:                uuid.New(),
		TenantSlug:        tenantSlug,
		AgentID:           targetAgentID,
		AgentHostname:     targetHostname,
		AgentIP:           targetIP,
		ProcessName:       "vss_encryptor.exe",
		ProcessPID:        4820,
		ProcessPath:       `C:\Users\Public\vss_encryptor.exe`,
		CommandLine:       `vss_encryptor.exe --encrypt --dir="C:\Users" --ext=".locked"`,
		TriggerType:       "canary_tripwire",
		TargetFile:        canary.FilePath,
		ExtensionDetected: ".locked",
		EntropyScore:      7.92,
		FilesAffected:     14,
		ActionTaken:       "TERMINATED & QUARANTINED",
		Severity:          "CRITICAL",
		MitreTactic:       "Impact",
		MitreTechnique:    "T1486",
		CreatedAt:         now,
	}

	if err := h.pgDB.RecordRansomwareIncidents(r.Context(), []models.EndpointRansomwareIncident{incident}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "simulation failed: " + err.Error()})
		return
	}

	// 3. Dispatch to SIEM correlation engine
	if h.siemEngine != nil {
		alert := &models.SIEMAlert{
			ID:             uuid.New(),
			RuleID:         "EDR-RANSOMWARE-DETECTED",
			RuleName:       fmt.Sprintf("SIMULATION: Ransomware Detected on %s", targetHostname),
			Severity:       "CRITICAL",
			Tenant:         tenantSlug,
			DeviceName:     targetHostname,
			SourceIP:       targetIP,
			Category:       "endpoint_ransomware",
			EventCount:     1,
			FirstSeen:      now,
			LastSeen:       now,
			Status:         "NEW",
			MitreTactic:    "Impact",
			MitreTechnique: "T1486",
			RiskScore:      98,
			Summary:        fmt.Sprintf("SIMULATION: Canary Tripwire triggered on %s. Rogue process %s (PID: %d) terminated, host isolated.", targetHostname, incident.ProcessName, incident.ProcessPID),
			CreatedAt:      now,
		}
		h.siemEngine.DispatchDirectAlert(alert)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "simulated",
		"incident": incident,
		"canary":   canary,
	})
}

// handleEndpointHoneypotConfig handles GET (retrieve) and POST (save) for honeypot settings
func (h *Handler) handleEndpointHoneypotConfig(w http.ResponseWriter, r *http.Request) {
	tenantSlug := h.tenantScope(r)
	if tenantSlug == "" || tenantSlug == "all" {
		tenantSlug = "default"
	}

	if r.Method == http.MethodGet {
		cfg, err := h.pgDB.GetHoneypotConfig(r.Context(), tenantSlug)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
		return
	}

	if r.Method == http.MethodPost {
		var cfg models.EndpointHoneypotConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}
		cfg.TenantSlug = tenantSlug
		if err := h.pgDB.SaveHoneypotConfig(r.Context(), &cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "saved",
			"config":  cfg,
			"message": "Honeypot ve Fidye Kalkanı yapılandırması başarıyla kaydedildi.",
		})
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// handleEndpointArmFleetCanaries triggers fleet-wide re-arming and seeding of honeypot canaries
func (h *Handler) handleEndpointArmFleetCanaries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantSlug := h.tenantScope(r)
	if tenantSlug == "" || tenantSlug == "all" {
		tenantSlug = "default"
	}

	agents, _, err := h.pgDB.ListAgents(r.Context(), tenantSlug, "", "", "", 100, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	var seededCanaries []models.EndpointCanaryToken

	standardDecoys := []struct {
		name string
		ext  string
	}{
		{"Confidential_Q4_Financial_Ledger", "xlsx"},
		{"Executive_Payroll_Master_Records", "docx"},
		{"Domain_Admin_Emergency_Recovery_Keys", "pdf"},
	}

	for _, ag := range agents {
		baseDir := `C:\Users\Public\Documents\.canaries`
		if ag.OSType != "windows" {
			baseDir = "/var/logseal/canaries"
		}
		for _, dec := range standardDecoys {
			seededCanaries = append(seededCanaries, models.EndpointCanaryToken{
				TenantSlug:    tenantSlug,
				AgentID:       ag.ID,
				AgentHostname: ag.Hostname,
				FilePath:      fmt.Sprintf("%s/%s.%s", baseDir, dec.name, dec.ext),
				FileType:      dec.ext,
				InitialHash:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Status:        "ARMED",
				LastCheckedAt: now,
				CreatedAt:     now,
			})
		}
	}

	if len(seededCanaries) > 0 {
		_ = h.pgDB.UpsertCanaryTokens(r.Context(), seededCanaries)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "armed",
		"agents_reached": len(agents),
		"canaries_armed": len(seededCanaries),
		"message":        fmt.Sprintf("%d uç nokta için toplam %d tuzak yem başarıyla dağıtıldı ve silahlandırıldı.", len(agents), len(seededCanaries)),
	})
}

