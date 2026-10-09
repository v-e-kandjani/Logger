package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/auth/mfa"
)

// MFATicket tracks an in-flight two-factor authentication challenge
type MFATicket struct {
	Ticket    string
	UserID    uuid.UUID
	Username  string
	ExpiresAt time.Time
}

type MFATicketManager struct {
	mu      sync.RWMutex
	tickets map[string]*MFATicket
}

func NewMFATicketManager() *MFATicketManager {
	tm := &MFATicketManager{
		tickets: make(map[string]*MFATicket),
	}
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		for range ticker.C {
			tm.cleanup()
		}
	}()
	return tm
}

func (tm *MFATicketManager) Create(userID uuid.UUID, username string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	ticket := hex.EncodeToString(b)

	t := &MFATicket{
		Ticket:    ticket,
		UserID:    userID,
		Username:  username,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	tm.mu.Lock()
	tm.tickets[ticket] = t
	tm.mu.Unlock()
	return ticket
}

func (tm *MFATicketManager) Consume(ticket string) (*MFATicket, bool) {
	if ticket == "" {
		return nil, false
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()

	t, ok := tm.tickets[ticket]
	if !ok || time.Now().After(t.ExpiresAt) {
		delete(tm.tickets, ticket)
		return nil, false
	}
	delete(tm.tickets, ticket)
	return t, true
}

func (tm *MFATicketManager) cleanup() {
	now := time.Now()
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for k, v := range tm.tickets {
		if now.After(v.ExpiresAt) {
			delete(tm.tickets, k)
		}
	}
}

// HTTP API Handlers for MFA

// handleLoginMFAAPI verifies Step 2 TOTP or recovery code after password check
func (h *Handler) handleLoginMFAAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MFATicket string `json:"mfa_ticket"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	req.MFATicket = strings.TrimSpace(req.MFATicket)
	req.Code = strings.TrimSpace(req.Code)

	if req.MFATicket == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mfa_ticket and 6-digit verification code required"})
		return
	}

	ticket, ok := h.mfaTickets.Consume(req.MFATicket)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "mfa session has expired or is invalid. please log in again"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	user, err := h.pgDB.GetUserByID(ctx, ticket.UserID)
	if err != nil || !user.IsEnabled {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user account not accessible"})
		return
	}

	// 1. Try TOTP validation
	valid := mfa.ValidateTOTP(user.MFASecret, req.Code, time.Now())

	// 2. If TOTP failed, try recovery code
	if !valid {
		consumed, recErr := h.pgDB.ValidateAndConsumeRecoveryCode(ctx, user.ID, req.Code)
		if recErr == nil && consumed {
			valid = true
		}
	}

	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid 6-digit authenticator code or recovery code"})
		return
	}

	// Code is valid! Create authenticated session
	token := h.sessions.Create(user)
	_ = h.pgDB.UpdateUserLastLogin(ctx, user.ID)

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(SessionDuration),
		MaxAge:   int(SessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"user": map[string]any{
			"username":  user.Username,
			"full_name": user.FullName,
			"role":      user.Role,
		},
	})
}

// handleMFASetupAPI generates an enrollment package for the active user
func (h *Handler) handleMFASetupAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	pkg, err := mfa.GenerateSetupPackage(session.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed generating mfa package: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, pkg)
}

// handleMFAVerifyAndEnableAPI activates MFA after validating the first 6-digit TOTP code
func (h *Handler) handleMFAVerifyAndEnableAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		Secret        string   `json:"secret"`
		Code          string   `json:"code"`
		RecoveryCodes []string `json:"recovery_codes"`
		Provider      string   `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}

	req.Secret = strings.TrimSpace(req.Secret)
	req.Code = strings.TrimSpace(req.Code)
	if req.Secret == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret and verification code required"})
		return
	}

	if !mfa.ValidateTOTP(req.Secret, req.Code, time.Now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "verification code is incorrect. please check the clock on your authenticator app"})
		return
	}

	if req.Provider == "" {
		req.Provider = "totp"
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if err := h.pgDB.UpdateUserMFA(ctx, session.UserID, true, req.Secret, req.RecoveryCodes, req.Provider); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed activating mfa: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "multi-factor authentication successfully enabled",
	})
}

// handleMFADisableAPI disables MFA for the active session user
func (h *Handler) handleMFADisableAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if err := h.pgDB.DisableUserMFA(ctx, session.UserID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed disabling mfa: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "multi-factor authentication disabled",
	})
}

// handleMFAAdminResetAPI allows Super Administrators to reset MFA for any user who lost their device
func (h *Handler) handleMFAAdminResetAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	userIDStr := r.URL.Query().Get("id")
	if userIDStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user id required"})
		return
	}

	targetID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user uuid"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if err := h.pgDB.DisableUserMFA(ctx, targetID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed resetting mfa: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "user mfa credentials reset successfully",
	})
}
