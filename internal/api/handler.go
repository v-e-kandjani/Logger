package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/syslog-platform/logger/internal/archive"
	"github.com/syslog-platform/logger/internal/database/clickhouse"
	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/syslog/pipeline"
	"github.com/syslog-platform/logger/internal/timestamp"
	"github.com/syslog-platform/logger/internal/version"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Handler struct {
	pipeline    *pipeline.Pipeline
	chClient    *clickhouse.Client
	pgDB        *postgres.DB
	deviceCache *postgres.DeviceCache
	archEngine  *archive.Engine
	tsProvider  timestamp.TimestampProvider
	nodeName    string
	sessions    *SessionManager
}

func NewHandler(
	pipe *pipeline.Pipeline,
	ch *clickhouse.Client,
	pg *postgres.DB,
	dc *postgres.DeviceCache,
	ae *archive.Engine,
	ts timestamp.TimestampProvider,
	node string,
) *Handler {
	return &Handler{
		pipeline:    pipe,
		chClient:    ch,
		pgDB:        pg,
		deviceCache: dc,
		archEngine:  ae,
		tsProvider:  ts,
		nodeName:    node,
		sessions:    NewSessionManager(),
	}
}

func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookieName)
		if err != nil || cookie.Value == "" {
			h.unauthorized(w, r)
			return
		}

		session, ok := h.sessions.Get(cookie.Value)
		if !ok {
			h.unauthorized(w, r)
			return
		}

		_ = session
		next(w, r)
	}
}

func (h *Handler) unauthorized(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{
		"error":     "unauthorized",
		"login_url": "/login",
	})
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Public Authentication & Health Routes
	mux.HandleFunc("/login", h.handleLoginPage)
	mux.HandleFunc("/api/v1/auth/login", h.handleLoginAPI)
	mux.HandleFunc("/api/v1/auth/logout", h.handleLogoutAPI)
	mux.HandleFunc("/api/v1/auth/me", h.handleMeAPI)
	mux.HandleFunc("/api/v1/system/health", h.handleHealth)

	// Protected API v1 Endpoints (Require valid session)
	mux.HandleFunc("/api/v1/dashboard", h.requireAuth(h.handleDashboard))
	mux.HandleFunc("/api/v1/logs", h.requireAuth(h.handleSearchLogs))
	mux.HandleFunc("/api/v1/logs/live", h.requireAuth(h.handleLiveWebSocket))
	mux.HandleFunc("/api/v1/devices", h.requireAuth(h.handleDevices))
	mux.HandleFunc("/api/v1/unregistered", h.requireAuth(h.handleUnregisteredSources))
	mux.HandleFunc("/api/v1/archives", h.requireAuth(h.handleArchives))
	mux.HandleFunc("/api/v1/archives/create", h.requireAuth(h.handleCreateArchiveNow))
	mux.HandleFunc("/api/v1/settings", h.requireAuth(h.handleSettings))
	mux.HandleFunc("/api/v1/timestamp/credit", h.requireAuth(h.handleTimestampCredit))
	mux.HandleFunc("/api/v1/users", h.requireAuth(h.handleUsersAPI))
	mux.HandleFunc("/api/v1/users/toggle", h.requireAuth(h.handleToggleUserAPI))
	mux.HandleFunc("/api/v1/roles", h.requireAuth(h.handleRolesAPI))

	// Static Assets (Public so login page can load CSS/JS)
	fs := http.FileServer(http.Dir("./web/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Protected Dashboard UI (Redirects to /login if unauthenticated)
	mux.HandleFunc("/", h.requireAuth(h.handleDashboardUI))
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 2*time.Second)
	defer cancel()

	chStatus := "UP"
	if err := h.chClient.Ping(ctx); err != nil {
		chStatus = "DOWN: " + err.Error()
	}

	pgStatus := "UP"
	if err := h.pgDB.Ping(ctx); err != nil {
		pgStatus = "DOWN: " + err.Error()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":         version.Version,
		"platform":        version.Platform,
		"build_date":      version.BuildDate,
		"status":          "HEALTHY",
		"node":            h.nodeName,
		"clickhouse":      chStatus,
		"postgres":        pgStatus,
		"queue_depth":     h.pipeline.QueueDepth(),
		"packets_rx":      h.pipeline.PacketsReceived.Load(),
		"events_parsed":   h.pipeline.EventsParsed.Load(),
		"events_inserted": h.chClient.TotalInserted.Load(),
		"insert_errors":   h.chClient.TotalFailed.Load(),
		"timestamp":       time.Now().UTC(),
	})
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	devices, _ := h.pgDB.ListDevices(ctx)
	activeCount := 0
	warningCount := 0
	offlineCount := 0
	for _, d := range devices {
		switch d.SyslogStatus {
		case "HEALTHY":
			activeCount++
		case "WARNING":
			warningCount++
		case "OFFLINE", "NEVER_SEEN":
			offlineCount++
		}
	}

	unreg, _ := h.pgDB.ListUnregisteredSources(ctx)
	archives, _ := h.pgDB.ListArchives(ctx, 5)

	// Query today's logs from ClickHouse
	todayStart := time.Now().UTC().Truncate(24 * time.Hour)
	var countToday uint64
	row, err := h.chClient.QueryEvents(ctx, "SELECT count() FROM syslog.syslog_events WHERE event_timestamp >= ?", todayStart)
	if err == nil && row != nil {
		defer row.Close()
		if row.Next() {
			_ = row.Scan(&countToday)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"logs_today":          countToday,
		"queue_depth":         h.pipeline.QueueDepth(),
		"packets_rx":          h.pipeline.PacketsReceived.Load(),
		"total_inserted":      h.chClient.TotalInserted.Load(),
		"total_devices":       len(devices),
		"active_devices":      activeCount,
		"warning_devices":     warningCount,
		"offline_devices":     offlineCount,
		"unknown_sources":     len(unreg),
		"recent_archives":     archives,
		"clickhouse_healthy":  h.chClient.IsHealthy(),
	})
}

func (h *Handler) handleSearchLogs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
		limit = l
	}

	// Filter parameters
	queryText := strings.TrimSpace(r.URL.Query().Get("q"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	vendorFilter := strings.TrimSpace(r.URL.Query().Get("vendor"))

	var conditions []string
	var args []any

	// Default to last 24 hours if no time range provided
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour)
	conditions = append(conditions, "event_timestamp >= ?")
	args = append(args, start)

	if vendorFilter != "" {
		conditions = append(conditions, "vendor = ?")
		args = append(args, vendorFilter)
	}
	if queryText != "" {
		conditions = append(conditions, "(hasToken(message, ?) OR hasToken(raw_message, ?) OR ilike(hostname, ?) OR ilike(vendor, ?) OR ilike(device_name, ?))")
		queryLike := "%" + queryText + "%"
		args = append(args, queryText, queryText, queryLike, queryLike, queryLike)
	}
	if severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, severity)
	}
	if source != "" {
		conditions = append(conditions, "source_ip = ?")
		args = append(args, net.ParseIP(source))
	}

	whereClause := strings.Join(conditions, " AND ")
	sql := fmt.Sprintf(`
		SELECT internal_id, event_timestamp, source_ip, source_port, transport_protocol,
		       device_name, vendor, severity, facility, hostname, application_name, message, raw_message
		FROM syslog.syslog_events
		WHERE %s
		ORDER BY event_timestamp DESC
		LIMIT %d`, whereClause, limit)

	rows, err := h.chClient.QueryEvents(ctx, sql, args...)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		var (
			id       string
			evTime   time.Time
			srcIP    net.IP
			srcPort  uint16
			proto    string
			devName  string
			vendor   string
			sev      string
			fac      string
			host     string
			app      string
			msg      string
			rawMsg   string
		)
		if err := rows.Scan(&id, &evTime, &srcIP, &srcPort, &proto, &devName, &vendor, &sev, &fac, &host, &app, &msg, &rawMsg); err != nil {
			continue
		}
		results = append(results, map[string]any{
			"id":          id,
			"timestamp":   evTime.Format(time.RFC3339),
			"source_ip":   srcIP.String(),
			"port":        srcPort,
			"protocol":    proto,
			"device_name": devName,
			"vendor":      vendor,
			"severity":    sev,
			"facility":    fac,
			"hostname":    host,
			"application": app,
			"message":     msg,
			"raw_message": rawMsg,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(results),
		"logs":  results,
	})
}

func (h *Handler) handleLiveWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ch := h.pipeline.Subscribe()
	defer h.pipeline.Unsubscribe(ch)

	for event := range ch {
		data, err := json.Marshal(event)
		if err != nil {
			continue
		}
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			break
		}
	}
}

func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if r.Method == http.MethodPost {
		var d models.Device
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if d.ExpectedProtocol == "" {
			d.ExpectedProtocol = "ANY"
		}
		if d.ExpectedPort == 0 {
			d.ExpectedPort = 514
		}
		if d.RetentionDays == 0 {
			d.RetentionDays = 365
		}
		if d.TimestampPolicy == "" {
			d.TimestampPolicy = "HOURLY"
		}
		d.IsEnabled = true

		if err := h.pgDB.CreateDevice(ctx, &d); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = h.deviceCache.Refresh(ctx)
		writeJSON(w, http.StatusCreated, d)
		return
	}

	if r.Method == http.MethodDelete {
		idStr := r.URL.Query().Get("id")
		devID, err := uuid.Parse(idStr)
		if err != nil {
			http.Error(w, "invalid device id", http.StatusBadRequest)
			return
		}
		if err := h.pgDB.DeleteDevice(ctx, devID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = h.deviceCache.Refresh(ctx)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}

	devices, err := h.pgDB.ListDevices(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (h *Handler) handleSettings(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if r.Method == http.MethodPost {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		for k, v := range req {
			if k == "kamusm_customer_password" && (v == "********" || v == "") {
				continue // Do not overwrite existing password with mask
			}
			_ = h.pgDB.SaveSetting(ctx, k, v)
		}

		// Update runtime Adaptive provider if configured
		if ap, ok := h.tsProvider.(*timestamp.AdaptiveTimestampProvider); ok {
			if mode, ok := req["stamping_mode"]; ok && mode != "" {
				ap.SetMode(timestamp.StampingMode(mode))
			}
			if af, ok := req["auto_fallback"]; ok {
				ap.SetAutoFallback(af == "true" || af == "1")
			}
			currentCfg := ap.GetKamuSMConfig()
			if url, ok := req["kamusm_server_url"]; ok && url != "" {
				currentCfg.ServerURL = url
			}
			if port, ok := req["kamusm_server_port"]; ok && port != "" {
				if p, err := strconv.Atoi(port); err == nil {
					currentCfg.ServerPort = p
				}
			}
			if custNo, ok := req["kamusm_customer_no"]; ok {
				currentCfg.CustomerNo = custNo
			}
			if custPass, ok := req["kamusm_customer_password"]; ok && custPass != "********" && custPass != "" {
				currentCfg.CustomerPass = custPass
			}
			if dt, ok := req["kamusm_digest_type"]; ok && dt != "" {
				currentCfg.DigestType = dt
			}
			ap.UpdateKamuSMConfig(currentCfg)
		} else if kp, ok := h.tsProvider.(*timestamp.KamuSMTimestampProvider); ok {
			kp.UpdateConfig(timestamp.KamuSMConfig{
				ServerURL:    req["kamusm_server_url"],
				CustomerNo:   req["kamusm_customer_no"],
				CustomerPass: req["kamusm_customer_password"],
				DigestType:   req["kamusm_digest_type"],
			})
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
		return
	}

	// GET settings
	settings, err := h.pgDB.GetSettings(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Include defaults if not yet set in DB
	if _, ok := settings["stamping_mode"]; !ok {
		settings["stamping_mode"] = "internal"
	}
	if _, ok := settings["auto_fallback"]; !ok {
		settings["auto_fallback"] = "true"
	}
	if _, ok := settings["kamusm_server_url"]; !ok {
		settings["kamusm_server_url"] = "http://zd.kamusm.gov.tr"
	}
	if _, ok := settings["kamusm_server_port"]; !ok {
		settings["kamusm_server_port"] = "80"
	}
	if _, ok := settings["kamusm_digest_type"]; !ok {
		settings["kamusm_digest_type"] = "sha-256"
	}
	if _, ok := settings["kamusm_provider"]; !ok {
		settings["kamusm_provider"] = "adaptive"
	}
	if _, ok := settings["archive_interval"]; !ok {
		settings["archive_interval"] = "hourly"
	}

	// Mask password before returning
	if pass, ok := settings["kamusm_customer_password"]; ok && len(pass) > 0 {
		settings["kamusm_customer_password"] = "********"
	}

	writeJSON(w, http.StatusOK, settings)
}

func (h *Handler) handleUnregisteredSources(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	sources, err := h.pgDB.ListUnregisteredSources(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sources)
}

func (h *Handler) handleArchives(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	archives, err := h.pgDB.ListArchives(ctx, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, archives)
}

func (h *Handler) handleCreateArchiveNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := contextWithTimeout(r, 30*time.Second)
	defer cancel()

	end := time.Now().UTC()
	start := end.Add(-1 * time.Hour)

	arch, err := h.archEngine.CreateArchiveSlice(ctx, start, end)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, arch)
}

func (h *Handler) handleTimestampCredit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	credit, err := h.tsProvider.QueryCredit(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "error", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "message": credit})
}

func (h *Handler) handleDashboardUI(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./web/templates/index.html")
}

func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
