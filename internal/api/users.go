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

func (h *Handler) handleUsersAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := contextWithTimeout(r, 5*time.Second)
		defer cancel()

		users, err := h.pgDB.ListUsers(ctx)
		if err != nil {
			http.Error(w, "failed listing users: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, users)

	case http.MethodPost:
		var req struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			FullName  string `json:"full_name"`
			Email     string `json:"email"`
			Role      string `json:"role"`
			IsEnabled bool   `json:"is_enabled"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
			return
		}

		req.Username = strings.TrimSpace(req.Username)
		req.FullName = strings.TrimSpace(req.FullName)
		req.Email = strings.TrimSpace(req.Email)
		req.Role = strings.TrimSpace(req.Role)

		if req.Username == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password are required"})
			return
		}
		if len(req.Password) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
			return
		}
		if req.Role == "" {
			req.Role = "Security Analyst"
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
			Username:  req.Username,
			FullName:  req.FullName,
			Email:     req.Email,
			Role:      req.Role,
			IsEnabled: req.IsEnabled,
		}

		if err := h.pgDB.CreateUser(ctx, user, req.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed creating user: " + err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, user)

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		id, err := uuid.Parse(idStr)
		if err != nil {
			http.Error(w, "invalid user id", http.StatusBadRequest)
			return
		}

		// Prevent deleting currently logged-in user
		cookie, _ := r.Cookie(SessionCookieName)
		if cookie != nil && cookie.Value != "" {
			if s, ok := h.sessions.Get(cookie.Value); ok && s.UserID == id {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete your own active account"})
				return
			}
		}

		ctx, cancel := contextWithTimeout(r, 5*time.Second)
		defer cancel()

		if err := h.pgDB.DeleteUser(ctx, id); err != nil {
			http.Error(w, "failed deleting user: "+err.Error(), http.StatusInternalServerError)
			return
		}
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

	idStr := r.URL.Query().Get("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	// Prevent disabling currently logged in user
	cookie, _ := r.Cookie(SessionCookieName)
	if cookie != nil && cookie.Value != "" {
		if s, ok := h.sessions.Get(cookie.Value); ok && s.UserID == id {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot disable your own active account"})
			return
		}
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	newState, err := h.pgDB.ToggleUserStatus(ctx, id)
	if err != nil {
		http.Error(w, "failed toggling status: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"id": id, "is_enabled": newState})
}
