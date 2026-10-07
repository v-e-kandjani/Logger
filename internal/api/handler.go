package api

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	manualArchiving   atomic.Bool
	archiveMu         sync.Mutex
	lastManualArchive time.Time
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
	mux.HandleFunc("/api/v1/archives/download", h.requireAuth(h.handleDownloadArchive))
	mux.HandleFunc("/api/v1/archives/export-custom", h.requireAuth(h.handleExportCustomRange))
	mux.HandleFunc("/api/v1/system/storage", h.requireAuth(h.handleStorageStats))
	mux.HandleFunc("/api/v1/system/storage/prune", h.requireAuth(h.handleStoragePrune))
	mux.HandleFunc("/api/v1/settings", h.requireAuth(h.handleSettings))
	mux.HandleFunc("/api/v1/timestamp/credit", h.requireAuth(h.handleTimestampCredit))
	mux.HandleFunc("/api/v1/users", h.requireAuth(h.handleUsersAPI))
	mux.HandleFunc("/api/v1/users/toggle", h.requireAuth(h.handleToggleUserAPI))
	mux.HandleFunc("/api/v1/users/reset-password", h.requireAuth(h.handleResetUserPasswordAPI))
	mux.HandleFunc("/api/v1/roles", h.requireAuth(h.handleRolesAPI))
	mux.HandleFunc("/api/v1/system/update/status", h.requireAuth(h.handleSystemUpdateStatus))
	mux.HandleFunc("/api/v1/system/update/check", h.requireAuth(h.handleSystemUpdateCheck))
	mux.HandleFunc("/api/v1/system/update/apply", h.requireAuth(h.handleSystemUpdateApply))

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
		"events_inserted":        h.chClient.TotalInserted.Load(),
		"insert_errors":          h.chClient.TotalFailed.Load(),
		"strict_device_filtering": h.pipeline.IsStrictFiltering(),
		"dropped_unauthorized":   h.pipeline.DroppedUnauthorized.Load(),
		"timestamp":              time.Now().UTC(),
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

	// Query today's logs from ClickHouse (match either event_timestamp or received_at to protect against device clock drift)
	todayStart := time.Now().UTC().Truncate(24 * time.Hour)
	var countToday uint64
	countQuery := fmt.Sprintf("SELECT count() FROM %s.syslog_events WHERE event_timestamp >= ? OR received_at >= ?", h.chClient.Database())
	row, err := h.chClient.QueryEvents(ctx, countQuery, todayStart, todayStart)
	if err == nil && row != nil {
		defer row.Close()
		if row.Next() {
			_ = row.Scan(&countToday)
		}
	}

	// Storage metrics from ClickHouse
	storageStats, _ := h.chClient.GetStorageStats(ctx)

	writeJSON(w, http.StatusOK, map[string]any{
		"logs_today":              countToday,
		"queue_depth":             h.pipeline.QueueDepth(),
		"packets_rx":              h.pipeline.PacketsReceived.Load(),
		"total_inserted":          h.chClient.TotalInserted.Load(),
		"total_devices":           len(devices),
		"active_devices":          activeCount,
		"warning_devices":         warningCount,
		"offline_devices":         offlineCount,
		"unknown_sources":         len(unreg),
		"recent_archives":         archives,
		"clickhouse_healthy":      h.chClient.IsHealthy(),
		"strict_device_filtering": h.pipeline.IsStrictFiltering(),
		"dropped_unauthorized":   h.pipeline.DroppedUnauthorized.Load(),
		"storage":                 storageStats,
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
	timeRange := strings.TrimSpace(r.URL.Query().Get("range"))

	var conditions []string
	var args []any

	now := time.Now().UTC()
	switch timeRange {
	case "15m":
		conditions = append(conditions, "(event_timestamp >= ? OR received_at >= ?)")
		args = append(args, now.Add(-15*time.Minute), now.Add(-15*time.Minute))
	case "1h":
		conditions = append(conditions, "(event_timestamp >= ? OR received_at >= ?)")
		args = append(args, now.Add(-1*time.Hour), now.Add(-1*time.Hour))
	case "7d":
		conditions = append(conditions, "(event_timestamp >= ? OR received_at >= ?)")
		args = append(args, now.Add(-7*24*time.Hour), now.Add(-7*24*time.Hour))
	case "30d":
		conditions = append(conditions, "(event_timestamp >= ? OR received_at >= ?)")
		args = append(args, now.Add(-30*24*time.Hour), now.Add(-30*24*time.Hour))
	case "all":
		// No time restriction
	default: // "24h" or empty
		conditions = append(conditions, "(event_timestamp >= ? OR received_at >= ?)")
		args = append(args, now.Add(-24*time.Hour), now.Add(-24*time.Hour))
	}

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
		if parsedIP := net.ParseIP(source); parsedIP != nil {
			conditions = append(conditions, "source_ip = ?")
			args = append(args, parsedIP)
		} else {
			conditions = append(conditions, "hasToken(toString(source_ip), ?)")
			args = append(args, source)
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}
	sql := fmt.Sprintf(`
		SELECT internal_id, event_timestamp, source_ip, source_port, transport_protocol,
		       device_name, vendor, severity, facility, hostname, application_name, message, raw_message
		FROM %s.syslog_events
		%s
		ORDER BY event_timestamp DESC
		LIMIT %d`, h.chClient.Database(), whereClause, limit)

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

		if sdf, ok := req["strict_device_filtering"]; ok {
			h.pipeline.SetStrictFiltering(sdf == "true" || sdf == "1")
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
	if _, ok := settings["strict_device_filtering"]; !ok {
		settings["strict_device_filtering"] = strconv.FormatBool(h.pipeline.IsStrictFiltering())
	}
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

	// Prevent overlapping manual archiving runs
	if !h.manualArchiving.CompareAndSwap(false, true) {
		http.Error(w, "Archive generation is already in progress. Please wait for it to complete.", http.StatusConflict)
		return
	}
	defer h.manualArchiving.Store(false)

	// Rate-limit manual triggers to once every 30 seconds
	h.archiveMu.Lock()
	if !h.lastManualArchive.IsZero() && time.Since(h.lastManualArchive) < 30*time.Second {
		remaining := int(30 - time.Since(h.lastManualArchive).Seconds())
		h.archiveMu.Unlock()
		http.Error(w, fmt.Sprintf("Please wait %d seconds before creating another manual archive.", remaining), http.StatusTooManyRequests)
		return
	}
	h.lastManualArchive = time.Now()
	h.archiveMu.Unlock()

	ctx, cancel := contextWithTimeout(r, 120*time.Second)
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

func (h *Handler) handleDownloadArchive(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	fileType := r.URL.Query().Get("type") // "archive" (default), "evidence", "hash", "bundle"

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid archive id", http.StatusBadRequest)
		return
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	arch, err := h.pgDB.GetArchive(ctx, id)
	if err != nil {
		http.Error(w, "archive not found: "+err.Error(), http.StatusNotFound)
		return
	}

	switch fileType {
	case "evidence":
		targetPath := arch.ArchivePath + ".zd"
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			http.Error(w, "evidence file does not exist (archive may be unstamped)", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zd\"", arch.ArchiveName))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeFile(w, r, targetPath)
		return

	case "hash":
		targetPath := arch.ArchivePath + ".sha256"
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			http.Error(w, "hash file does not exist", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.sha256\"", arch.ArchiveName))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeFile(w, r, targetPath)
		return

	case "bundle":
		h.serveArchiveBundleZip(w, r, arch)
		return

	default: // "archive" or empty
		targetPath := arch.ArchivePath
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			http.Error(w, "archive file not found on disk", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.jsonl.gz\"", arch.ArchiveName))
		w.Header().Set("Content-Type", "application/gzip")
		http.ServeFile(w, r, targetPath)
		return
	}
}

func (h *Handler) serveArchiveBundleZip(w http.ResponseWriter, r *http.Request, arch *models.LogArchive) {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-compliance-bundle.zip\"", arch.ArchiveName))
	w.Header().Set("Content-Type", "application/zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	filesToBundle := []struct {
		diskPath string
		zipName  string
	}{
		{arch.ArchivePath, arch.ArchiveName + ".jsonl.gz"},
		{arch.ArchivePath + ".zd", arch.ArchiveName + ".jsonl.gz.zd"},
		{arch.ArchivePath + ".sha256", arch.ArchiveName + ".sha256"},
	}

	for _, f := range filesToBundle {
		data, err := os.ReadFile(f.diskPath)
		if err != nil {
			continue // Skip if file is not on disk (e.g. .zd when disabled)
		}
		zf, err := zw.Create(f.zipName)
		if err != nil {
			continue
		}
		_, _ = zf.Write(data)
	}
}

func (h *Handler) handleDashboardUI(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./web/templates/index.html")
}

func (h *Handler) handleStorageStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	stats, err := h.chClient.GetStorageStats(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (h *Handler) handleStoragePrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := contextWithTimeout(r, 30*time.Second)
	defer cancel()

	var req struct {
		Action string `json:"action"` // "oldest_partition" or "retention"
		Days   int    `json:"days"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.Action == "retention" && req.Days > 0 {
		if err := h.chClient.PruneOlderThanDays(ctx, req.Days); err != nil {
			http.Error(w, "Prune failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		stats, _ := h.chClient.GetStorageStats(ctx)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "pruned",
			"message": fmt.Sprintf("Events older than %d days successfully pruned", req.Days),
			"storage": stats,
		})
		return
	}

	droppedPart, err := h.chClient.PruneOldestPartition(ctx)
	if err != nil {
		http.Error(w, "Pruning oldest partition: "+err.Error(), http.StatusInternalServerError)
		return
	}

	stats, _ := h.chClient.GetStorageStats(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "pruned",
		"dropped_partition": droppedPart,
		"message":           fmt.Sprintf("Oldest partition %s successfully removed to reclaim storage", droppedPart),
		"storage":           stats,
	})
}

func parseFlexibleTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse datetime: %s", s)
}

func (h *Handler) handleExportCustomRange(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 60*time.Second)
	defer cancel()

	var startStr, endStr, timeField, format string
	seal := true
	register := true

	if r.Method == http.MethodPost {
		var req struct {
			Start     string `json:"start"`
			End       string `json:"end"`
			TimeField string `json:"time_field"`
			Format    string `json:"format"`
			Seal      *bool  `json:"seal"`
			Register  *bool  `json:"register"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			startStr = req.Start
			endStr = req.End
			timeField = req.TimeField
			format = req.Format
			if req.Seal != nil {
				seal = *req.Seal
			}
			if req.Register != nil {
				register = *req.Register
			}
		}
	} else {
		// GET query params
		startStr = r.URL.Query().Get("start")
		endStr = r.URL.Query().Get("end")
		timeField = r.URL.Query().Get("time_field")
		format = r.URL.Query().Get("format")
		if s := r.URL.Query().Get("seal"); s == "false" || s == "0" {
			seal = false
		}
		if reg := r.URL.Query().Get("register"); reg == "false" || reg == "0" {
			register = false
		}
	}

	if startStr == "" || endStr == "" {
		http.Error(w, "start and end dates are required", http.StatusBadRequest)
		return
	}

	startTime, err := parseFlexibleTime(startStr)
	if err != nil {
		http.Error(w, "invalid start datetime: "+err.Error(), http.StatusBadRequest)
		return
	}

	endTime, err := parseFlexibleTime(endStr)
	if err != nil {
		http.Error(w, "invalid end datetime: "+err.Error(), http.StatusBadRequest)
		return
	}

	if timeField != "received_at" {
		timeField = "event_timestamp"
	}
	if format == "" {
		format = "bundle"
	}

	opts := archive.CustomRangeOptions{
		Start:     startTime,
		End:       endTime,
		TimeField: timeField,
		Format:    format,
		Seal:      seal,
		Register:  register,
	}

	res, err := h.archEngine.CreateCustomRangeArchive(ctx, opts)
	if err != nil {
		http.Error(w, "generating custom archive: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// If direct download was requested via GET or download=true parameter
	if r.Method == http.MethodGet || r.URL.Query().Get("download") == "true" {
		targetFile := res.FilePath
		if _, err := os.Stat(targetFile); os.IsNotExist(err) {
			http.Error(w, "generated file not found on disk", http.StatusInternalServerError)
			return
		}

		filename := filepath.Base(targetFile)
		switch format {
		case "bundle":
			w.Header().Set("Content-Type", "application/zip")
		case "csv":
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		default:
			w.Header().Set("Content-Type", "application/gzip")
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		http.ServeFile(w, r, targetFile)
		return
	}

	// Otherwise return JSON with download link & metrics
	downloadURL := fmt.Sprintf("/api/v1/archives/export-custom?start=%s&end=%s&time_field=%s&format=%s&seal=%t&register=%t&download=true",
		startTime.Format(time.RFC3339),
		endTime.Format(time.RFC3339),
		timeField,
		format,
		seal,
		register,
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"result":       res,
		"download_url": downloadURL,
	})
}

func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
