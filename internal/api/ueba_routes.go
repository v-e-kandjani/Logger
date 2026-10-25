package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// handleUEBAStats returns aggregate KPI metrics for UEBA dashboard
func (h *Handler) handleUEBAStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	stats, err := h.pgDB.GetUEBAStats(r.Context(), tenant)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// handleUEBARiskLeaderboard returns top high-risk identities
func (h *Handler) handleUEBARiskLeaderboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 10
	}

	items, err := h.pgDB.GetUEBARiskLeaderboard(r.Context(), tenant, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"total": len(items),
	})
}

// handleUEBAProfiles returns paginated behavioral baseline profiles
func (h *Handler) handleUEBAProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	search := r.URL.Query().Get("search")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if limit <= 0 {
		limit = 20
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	profiles, total, err := h.pgDB.ListUEBAProfiles(r.Context(), tenant, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profiles": profiles,
		"total":    total,
		"page":     page,
		"limit":    limit,
	})
}

// handleUEBAAnomalies returns paginated detected behavioral anomalies
func (h *Handler) handleUEBAAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	username := r.URL.Query().Get("username")
	anomalyType := r.URL.Query().Get("type")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if limit <= 0 {
		limit = 50
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	anomalies, total, err := h.pgDB.ListUEBAAnomalies(r.Context(), tenant, username, anomalyType, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"anomalies": anomalies,
		"total":     total,
		"page":      page,
		"limit":     limit,
	})
}

// handleUEBASimulate enables security operators to simulate a synthetic UEBA anomaly for testing
func (h *Handler) handleUEBASimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.uebaEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "UEBA engine not initialized"})
		return
	}

	var req struct {
		Username    string `json:"username"`
		AnomalyType string `json:"anomaly_type"`
		SourceIP    string `json:"source_ip"`
		DeviceName  string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	tenant := h.tenantScope(r)
	anomaly, err := h.uebaEngine.SimulateAnomaly(r.Context(), tenant, req.Username, req.AnomalyType, req.SourceIP, req.DeviceName)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "simulated",
		"anomaly": anomaly,
	})
}

// handleUEBAResetRisk allows operators to acknowledge/clear risk score for a user
func (h *Handler) handleUEBAResetRisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}

	tenant := h.tenantScope(r)
	if err := h.pgDB.ResetUEBARiskScore(r.Context(), tenant, req.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"username": req.Username,
		"message":  "Risk score successfully reset to 0",
	})
}
