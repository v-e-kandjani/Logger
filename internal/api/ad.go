package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/auth/ad"
)

// handleADTestAPI tests connectivity and service account credentials to Active Directory
func (h *Handler) handleADTestAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	ctx, cancel := contextWithTimeout(r, 8*time.Second)
	defer cancel()

	// Load settings from DB
	settings, err := h.pgDB.GetSettings(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed reading settings: " + err.Error()})
		return
	}

	cfg := ad.LoadConfigFromSettings(settings)

	// Allow overriding settings from request body if user is testing unsaved form values
	if r.ContentLength > 0 {
		var req struct {
			Server             string `json:"server"`
			Port               int    `json:"port"`
			UseSSL             bool   `json:"use_ssl"`
			StartTLS           bool   `json:"start_tls"`
			InsecureSkipVerify bool   `json:"insecure_skip_verify"`
			BaseDN             string `json:"base_dn"`
			BindDN             string `json:"bind_dn"`
			BindPassword       string `json:"bind_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if req.Server != "" {
				cfg.Server = strings.TrimSpace(req.Server)
			}
			if req.Port > 0 {
				cfg.Port = req.Port
			}
			cfg.UseSSL = req.UseSSL
			cfg.StartTLS = req.StartTLS
			cfg.InsecureSkipVerify = req.InsecureSkipVerify
			if req.BaseDN != "" {
				cfg.BaseDN = strings.TrimSpace(req.BaseDN)
			}
			if req.BindDN != "" {
				cfg.BindDN = strings.TrimSpace(req.BindDN)
			}
			if req.BindPassword != "" && req.BindPassword != "********" {
				cfg.BindPassword = req.BindPassword
			}
		}
	}

	client := ad.NewClient(cfg)
	if err := client.TestConnection(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"status": "error",
			"error":  "Active Directory connection failed: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "Successfully connected and authenticated with Active Directory domain controller",
	})
}

// handleADPreviewAPI fetches users from Active Directory for inspection before syncing
func (h *Handler) handleADPreviewAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	settings, err := h.pgDB.GetSettings(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed loading settings: " + err.Error()})
		return
	}

	cfg := ad.LoadConfigFromSettings(settings)
	client := ad.NewClient(cfg)

	users, err := client.SearchUsers(200)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Active Directory search failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"count":  len(users),
		"users":  users,
	})
}

// handleADSyncAPI executes a synchronization batch from Active Directory into local user table
func (h *Handler) handleADSyncAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()

	settings, err := h.pgDB.GetSettings(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed loading settings: " + err.Error()})
		return
	}

	cfg := ad.LoadConfigFromSettings(settings)
	client := ad.NewClient(cfg)

	adUsers, err := client.SearchUsers(500)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Failed discovering AD users: " + err.Error()})
		return
	}

	syncedCount := 0
	for _, u := range adUsers {
		role := cfg.DefaultRole
		if role == "" {
			role = "Security Analyst"
		}
		_, err := h.pgDB.UpsertADUser(ctx, u.Username, u.FullName, u.Email, role)
		if err == nil {
			syncedCount++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"message":      "Active Directory user synchronization completed",
		"total_found":  len(adUsers),
		"synced_count": syncedCount,
	})
}
