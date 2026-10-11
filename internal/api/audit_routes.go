package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// recordAudit logs an administrative event into PostgreSQL audit_logs table
func (h *Handler) recordAudit(r *http.Request, action, resource, result string, details map[string]interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var username string = "anonymous"
	var tenantSlug string = "default"
	var userID *uuid.UUID = nil

	if session, ok := h.getSession(r); ok && session != nil {
		username = session.Username
		tenantSlug = session.TenantSlug
		uid := session.UserID
		userID = &uid
	}

	clientIP := getClientIP(r)

	audit := &models.AuditLog{
		UserID:     userID,
		Username:   username,
		SourceIP:   clientIP,
		Action:     action,
		Resource:   resource,
		Result:     result,
		Details:    details,
		TenantSlug: tenantSlug,
	}

	_ = h.pgDB.InsertAuditLog(ctx, audit)
}

// handleAuditLogsAPI returns paginated audit events
func (h *Handler) handleAuditLogsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Allowed for Super Administrator, Auditor, and Tenant Admins
	isAllowed := session.Role == "Super Administrator" || session.Role == "Auditor" || session.IsTenantAdmin
	if !isAllowed {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied: audit permission required"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	scope := h.tenantScope(r)
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit <= 0 {
		limit = 50
	}

	logs, total, err := h.pgDB.ListAuditLogs(ctx, scope, action, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "querying audit logs: " + err.Error()})
		return
	}

	if logs == nil {
		logs = []models.AuditLog{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   logs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
