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
	"github.com/syslog-platform/logger/internal/models"
	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookieName = "syslog_session"
	SessionDuration   = 24 * time.Hour
)

type Session struct {
	ID        string    `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Username  string    `json:"username"`
	FullName  string    `json:"full_name"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
	}
	// Background cleanup of expired sessions
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		for range ticker.C {
			sm.cleanup()
		}
	}()
	return sm
}

func (sm *SessionManager) Create(user *models.User) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	s := &Session{
		ID:        token,
		UserID:    user.ID,
		Username:  user.Username,
		FullName:  user.FullName,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(SessionDuration),
	}

	sm.mu.Lock()
	sm.sessions[token] = s
	sm.mu.Unlock()

	return token
}

func (sm *SessionManager) Get(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	sm.mu.RLock()
	s, ok := sm.sessions[token]
	sm.mu.RUnlock()

	if !ok || time.Now().After(s.ExpiresAt) {
		if ok {
			sm.Delete(token)
		}
		return nil, false
	}
	return s, true
}

func (sm *SessionManager) Delete(token string) {
	sm.mu.Lock()
	delete(sm.sessions, token)
	sm.mu.Unlock()
}

func (sm *SessionManager) cleanup() {
	now := time.Now()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for k, s := range sm.sessions {
		if now.After(s.ExpiresAt) {
			delete(sm.sessions, k)
		}
	}
}

// Authentication HTTP Handlers

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	user, err := h.pgDB.GetUserByUsername(ctx, req.Username)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}

	if !user.IsEnabled {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "user account is disabled"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}

	// Create session
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

func (h *Handler) handleLogoutAPI(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		h.sessions.Delete(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) getSession(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	return h.sessions.Get(cookie.Value)
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	session, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return nil, false
	}
	if session.Role != "Super Administrator" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied: administrator privileges required"})
		return nil, false
	}
	return session, true
}

func (h *Handler) handleMeAPI(w http.ResponseWriter, r *http.Request) {
	session, ok := h.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"user_id":       session.UserID,
		"username":      session.Username,
		"full_name":     session.FullName,
		"role":          session.Role,
	})
}

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		if _, ok := h.sessions.Get(cookie.Value); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	http.ServeFile(w, r, "./web/templates/login.html")
}
