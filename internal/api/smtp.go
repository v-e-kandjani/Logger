package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/notification/smtp"
)

// handleSMTPTestAPI sends a test message to verify mail server settings
func (h *Handler) handleSMTPTestAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	ctx, cancel := contextWithTimeout(r, 12*time.Second)
	defer cancel()

	settings, err := h.pgDB.GetSettings(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed loading settings: " + err.Error()})
		return
	}

	cfg := smtp.LoadConfigFromSettings(settings)

	var req struct {
		Recipient          string `json:"recipient"`
		Host               string `json:"host"`
		Port               int    `json:"port"`
		Encryption         string `json:"encryption"`
		InsecureSkipVerify bool   `json:"insecure_skip_verify"`
		Username           string `json:"username"`
		Password           string `json:"password"`
		FromAddress        string `json:"from_address"`
		FromName           string `json:"from_name"`
	}

	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	// Apply any test overrides from frontend form
	if req.Host != "" {
		cfg.Host = strings.TrimSpace(req.Host)
	}
	if req.Port > 0 {
		cfg.Port = req.Port
	}
	if req.Encryption != "" {
		cfg.Encryption = req.Encryption
	}
	cfg.InsecureSkipVerify = req.InsecureSkipVerify
	if req.Username != "" {
		cfg.Username = strings.TrimSpace(req.Username)
	}
	if req.Password != "" && req.Password != "********" {
		cfg.Password = req.Password
	}
	if req.FromAddress != "" {
		cfg.FromAddress = strings.TrimSpace(req.FromAddress)
	}
	if req.FromName != "" {
		cfg.FromName = strings.TrimSpace(req.FromName)
	}

	targetRecipient := strings.TrimSpace(req.Recipient)
	if targetRecipient == "" {
		targetRecipient = cfg.FromAddress
	}
	if targetRecipient == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a recipient email address is required for the test message"})
		return
	}

	mailer := smtp.NewMailer(cfg)
	if err := mailer.SendTestEmail(targetRecipient); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"status": "error",
			"error":  "SMTP delivery test failed: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "SMTP test email sent successfully to " + targetRecipient,
	})
}
