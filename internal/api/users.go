package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

type RoleProfile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

var AvailableRoles = []RoleProfile{
	{
		ID:          "Super Administrator",
		Name:        "Super Administrator",
		Description: "Unrestricted control over system settings, user accounts, and TÜBİTAK KamuSM credentials",
		Permissions: []string{"all:manage", "users:manage", "settings:manage", "archives:create", "logs:view"},
	},
	{
		ID:          "Security Analyst",
		Name:        "Security Analyst",
		Description: "Threat hunting, live syslog stream inspection, and forensic ClickHouse queries",
		Permissions: []string{"logs:view", "logs:search", "stream:live", "devices:view"},
	},
	{
		ID:          "Auditor",
		Name:        "Auditor (Compliance)",
		Description: "Verification of Law No. 5651 legal evidence, SHA-256 digests, and KamuSM .zd timestamp tokens",
		Permissions: []string{"archives:view", "archives:verify", "audit:view", "logs:view"},
	},
	{
		ID:          "Operator",
		Name:        "Network Operator",
		Description: "Perimeter device onboarding, syslog socket monitoring, and queue telemetry",
		Permissions: []string{"devices:manage", "unregistered:manage", "health:view"},
	},
	{
		ID:          "Read Only",
		Name:        "Read Only",
		Description: "View-only access to dashboard statistics and health metrics",
		Permissions: []string{"dashboard:view"},
	},
}

func (h *Handler) handleRolesAPI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, AvailableRoles)
}

func (h *Handler) canManageUsers(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	session, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return nil, false
	}
	if session.Role != "Super Administrator" && !session.IsTenantAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied: administrator privileges required"})
		return nil, false
	}
	return session, true
}

func (h *Handler) handleUsersAPI(w http.ResponseWriter, r *http.Request) {
	session, ok := h.canManageUsers(w, r)
	if !ok {
		return
	}

	scope := h.tenantScope(r)
	isRoot := session.IsRootOperator()

	switch r.Method {
	case http.MethodGet:
		ctx, cancel := contextWithTimeout(r, 5*time.Second)
		defer cancel()

		users, err := h.pgDB.ListUsers(ctx, scope)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed listing users: " + err.Error()})
			return
		}
		if users == nil {
			users = []models.User{}
		}
		writeJSON(w, http.StatusOK, users)

	case http.MethodPost:
		var req struct {
			Username      string `json:"username"`
			Password      string `json:"password"`
			FullName      string `json:"full_name"`
			Email         string `json:"email"`
			Role          string `json:"role"`
			IsEnabled     bool   `json:"is_enabled"`
			TenantSlug    string `json:"tenant_slug"`
			IsTenantAdmin bool   `json:"is_tenant_admin"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
			return
		}

		req.Username = strings.TrimSpace(req.Username)
		req.FullName = strings.TrimSpace(req.FullName)
		req.Email = strings.TrimSpace(req.Email)
		req.Role = strings.TrimSpace(req.Role)
		req.TenantSlug = strings.TrimSpace(req.TenantSlug)

		if req.Username == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password are required"})
			return
		}

		// Enforce enterprise password complexity
		if err := ValidatePasswordPolicy(req.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if req.Role == "" {
			req.Role = "Security Analyst"
		}

		// Tenant admin restrictions
		if !isRoot {
			req.TenantSlug = session.TenantSlug
			if req.Role == "Super Administrator" {
				req.Role = "Security Analyst"
			}
		} else if req.TenantSlug == "" {
			req.TenantSlug = "default"
		}

		if req.FullName == "" {
			req.FullName = req.Username
		}
		if req.Email == "" {
			req.Email = req.Username + "@local.syslog"
		}

		ctx, cancel := contextWithTimeout(r, 5*time.Second)
		defer cancel()

		user := &models.User{
			Username:      req.Username,
			FullName:      req.FullName,
			Email:         req.Email,
			Role:          req.Role,
			IsEnabled:     req.IsEnabled,
			TenantSlug:    req.TenantSlug,
			IsTenantAdmin: req.IsTenantAdmin,
		}

		if err := h.pgDB.CreateUser(ctx, user, req.Password); err != nil {
			h.recordAudit(r, "USER_CREATE", "user/"+req.Username, "FAILED", map[string]interface{}{"error": err.Error()})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed creating user: " + err.Error()})
			return
		}

		h.recordAudit(r, "USER_CREATE", "user/"+user.Username, "SUCCESS", map[string]interface{}{"role": user.Role, "tenant": user.TenantSlug})
		writeJSON(w, http.StatusCreated, user)

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		id, err := uuid.Parse(idStr)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
			return
		}

		// A user cannot delete itself!
		if session.UserID == id {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete your own account"})
			return
		}

		ctx, cancel := contextWithTimeout(r, 5*time.Second)
		defer cancel()

		targetUser, err := h.pgDB.GetUserByID(ctx, id)
		if err != nil || targetUser == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		// Tenant Admin check
		if !isRoot && targetUser.TenantSlug != session.TenantSlug {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied: cross-tenant deletion prohibited"})
			return
		}

		if err := h.pgDB.DeleteUser(ctx, id); err != nil {
			h.recordAudit(r, "USER_DELETE", "user/"+targetUser.Username, "FAILED", map[string]interface{}{"error": err.Error()})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed deleting user: " + err.Error()})
			return
		}

		h.recordAudit(r, "USER_DELETE", "user/"+targetUser.Username, "SUCCESS", map[string]interface{}{"id": idStr})
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleToggleUserAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, ok := h.canManageUsers(w, r)
	if !ok {
		return
	}

	idStr := r.URL.Query().Get("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}

	// Prevent disabling own active account
	if session.UserID == id {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot disable your own active account"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	targetUser, err := h.pgDB.GetUserByID(ctx, id)
	if err != nil || targetUser == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	if !session.IsRootOperator() && targetUser.TenantSlug != session.TenantSlug {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied: cross-tenant modification prohibited"})
		return
	}

	newState, err := h.pgDB.ToggleUserStatus(ctx, id)
	if err != nil {
		h.recordAudit(r, "USER_STATUS_TOGGLE", "user/"+targetUser.Username, "FAILED", map[string]interface{}{"error": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed toggling status: " + err.Error()})
		return
	}

	h.recordAudit(r, "USER_STATUS_TOGGLE", "user/"+targetUser.Username, "SUCCESS", map[string]interface{}{"is_enabled": newState})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "is_enabled": newState})
}

func (h *Handler) handleResetUserPasswordAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, ok := h.canManageUsers(w, r)
	if !ok {
		return
	}

	var req struct {
		UserID      string `json:"user_id"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	id, err := uuid.Parse(req.UserID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}

	if err := ValidatePasswordPolicy(req.NewPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	targetUser, err := h.pgDB.GetUserByID(ctx, id)
	if err != nil || targetUser == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	if !session.IsRootOperator() && targetUser.TenantSlug != session.TenantSlug {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied: cross-tenant password reset prohibited"})
		return
	}

	if err := h.pgDB.ResetUserPassword(ctx, id, req.NewPassword); err != nil {
		h.recordAudit(r, "USER_PASSWORD_RESET", "user/"+targetUser.Username, "FAILED", map[string]interface{}{"error": err.Error()})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed resetting password: " + err.Error()})
		return
	}

	h.recordAudit(r, "USER_PASSWORD_RESET", "user/"+targetUser.Username, "SUCCESS", map[string]interface{}{"user_id": req.UserID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset_success"})
}
