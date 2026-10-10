package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/cache"
	"github.com/syslog-platform/logger/internal/https"
)

// handleHTTPSStatus returns the active HTTPS, Certificate, and FQDN configuration status
func (h *Handler) handleHTTPSStatus(w http.ResponseWriter, r *http.Request) {
	if h.httpsMgr == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "has_certificate": false})
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	status := h.httpsMgr.GetStatus(ctx)
	writeJSON(w, http.StatusOK, status)
}

// handleHTTPSToggle enables or disables HTTPS, updates port, and redirect policy
func (h *Handler) handleHTTPSToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled  bool `json:"enabled"`
		Port     int  `json:"port"`
		Redirect bool `json:"redirect"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.Port <= 0 {
		req.Port = https.DefaultHTTPSPort
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	if h.httpsMgr != nil {
		if err := h.httpsMgr.ToggleHTTPS(ctx, req.Enabled, req.Port, req.Redirect); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Failed to apply HTTPS state: %v", err)})
			return
		}
	}

	status := h.httpsMgr.GetStatus(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"message": fmt.Sprintf("HTTPS settings updated successfully (Active: %v, Port: %d)", req.Enabled, req.Port),
		"config":  status,
	})
}

// handleHTTPSGenerateCert creates an X.509 v3 self-signed certificate and hot-swaps it into memory
func (h *Handler) handleHTTPSGenerateCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CommonName   string   `json:"common_name"`
		SANs         []string `json:"sans"`
		ValidityDays int      `json:"validity_days"`
		Organization string   `json:"organization"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()

	if h.httpsMgr == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "HTTPS manager not initialized"})
		return
	}

	// Auto-populate FQDN if CN is empty
	if req.CommonName == "" {
		status := h.httpsMgr.GetStatus(ctx)
		if status.FQDNEnabled && status.FQDNHost != "" {
			req.CommonName = status.FQDNHost
		} else {
			req.CommonName = "localhost"
		}
	}

	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}
	if req.Organization == "" {
		req.Organization = "Valtrivo LogSeal Security Authority"
	}

	_, _, meta, err := h.httpsMgr.GenerateSelfSigned(ctx, req.CommonName, req.SANs, req.ValidityDays, req.Organization)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Generation failed: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"message":     fmt.Sprintf("Self-signed certificate generated for %s (Valid for %d days)", meta.CommonName, req.ValidityDays),
		"certificate": meta,
	})
}

// handleHTTPSUploadCert accepts and activates custom TLS certificate and private key
func (h *Handler) handleHTTPSUploadCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var certData []byte
	var keyData []byte

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") {
		// Multipart file upload
		if err := r.ParseMultipartForm(10 * 1024 * 1024); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Failed parsing multipart upload: " + err.Error()})
			return
		}

		certFile, _, err := r.FormFile("certificate")
		if err == nil {
			defer certFile.Close()
			certData, _ = io.ReadAll(certFile)
		}

		keyFile, _, err := r.FormFile("private_key")
		if err == nil {
			defer keyFile.Close()
			keyData, _ = io.ReadAll(keyFile)
		}
	} else {
		// JSON payload containing PEM text
		var req struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
			return
		}
		certData = []byte(req.CertPEM)
		keyData = []byte(req.KeyPEM)
	}

	if len(certData) == 0 || len(keyData) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Both certificate (.crt/.pem) and private key (.key/.pem) are required"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	if h.httpsMgr == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "HTTPS manager not initialized"})
		return
	}

	meta, err := h.httpsMgr.UploadCertificate(ctx, certData, keyData)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Certificate validation failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"message":     fmt.Sprintf("Certificate successfully installed and hot-swapped (CN=%s, Issuer=%s)", meta.CommonName, meta.Issuer),
		"certificate": meta,
	})
}

// handleHTTPSDownloadCert downloads active server certificate (.crt) for client trust installation
func (h *Handler) handleHTTPSDownloadCert(w http.ResponseWriter, r *http.Request) {
	if h.httpsMgr == nil {
		http.Error(w, "HTTPS manager not initialized", http.StatusInternalServerError)
		return
	}

	data, filename, err := h.httpsMgr.GetCertificateDownload()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleFQDNSettings updates FQDN configuration, host enforcement, and redirect policies
func (h *Handler) handleFQDNSettings(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if r.Method == http.MethodGet {
		settings, _ := h.pgDB.GetSettings(ctx)
		writeJSON(w, http.StatusOK, map[string]any{
			"fqdn_enabled":         settings[https.SettingFQDNEnabled] == "true",
			"fqdn_host":            settings[https.SettingFQDNHost],
			"fqdn_enforce_host":    settings[https.SettingFQDNEnforce] == "true",
			"fqdn_redirect_to_fqdn": settings[https.SettingFQDNRedirect] == "true",
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled  bool   `json:"fqdn_enabled"`
		Host     string `json:"fqdn_host"`
		Enforce  bool   `json:"fqdn_enforce_host"`
		Redirect bool   `json:"fqdn_redirect_to_fqdn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	req.Host = strings.TrimSpace(req.Host)
	_ = h.pgDB.SaveSetting(ctx, https.SettingFQDNEnabled, strconv.FormatBool(req.Enabled))
	_ = h.pgDB.SaveSetting(ctx, https.SettingFQDNHost, req.Host)
	_ = h.pgDB.SaveSetting(ctx, https.SettingFQDNEnforce, strconv.FormatBool(req.Enforce))
	_ = h.pgDB.SaveSetting(ctx, https.SettingFQDNRedirect, strconv.FormatBool(req.Redirect))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"message": "FQDN configuration saved successfully",
		"config":  req,
	})
}

// handleCacheStats returns real-time in-memory query result cache telemetry
func (h *Handler) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	cacheInst := h.resultCache
	if cacheInst == nil {
		cacheInst = cache.GetResultCache()
	}
	writeJSON(w, http.StatusOK, cacheInst.Stats())
}

// handleCacheClear flushes the in-memory query result cache
func (h *Handler) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cacheInst := h.resultCache
	if cacheInst == nil {
		cacheInst = cache.GetResultCache()
	}
	cacheInst.Clear()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "cleared",
		"message": "In-memory query result cache flushed successfully",
		"stats":   cacheInst.Stats(),
	})
}

// handleCacheToggle enables or disables in-memory query result acceleration
func (h *Handler) handleCacheToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	cacheInst := h.resultCache
	if cacheInst == nil {
		cacheInst = cache.GetResultCache()
	}
	cacheInst.SetEnabled(req.Enabled)

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	_ = h.pgDB.SaveSetting(ctx, "query_cache_enabled", strconv.FormatBool(req.Enabled))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"enabled": req.Enabled,
		"message": fmt.Sprintf("In-memory query acceleration set to %v", req.Enabled),
		"stats":   cacheInst.Stats(),
	})
}
