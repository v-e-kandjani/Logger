package api

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/cache"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/syslog/pipeline"
)

// Allowed sync interval choices
var validSyncIntervals = map[string]int{
	"online":          0,
	"every 60 second": 60,
	"every 5 min":     300,
	"every 15 min":    900,
	"every 30 min":    1800,
	"every hour":      3600,
}

func getIntervalSeconds(interval string) int {
	if sec, ok := validSyncIntervals[interval]; ok {
		return sec
	}
	return 0 // default: online
}

// generateEdgeToken creates a cryptographically secure token: lp_edge_<hex>
func generateEdgeToken() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return "lp_edge_" + hex.EncodeToString(b)
}

func getClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// EdgeHeartbeatRequest represents an edge forwarder check-in
type EdgeHeartbeatRequest struct {
	Token         string `json:"token"`
	NodeName      string `json:"node_name"`
	Version       string `json:"version"`
	BufferedCount int    `json:"buffered_count"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// handleEdgeHeartbeat processes regular proxy node check-ins and returns active sync interval
func (h *Handler) handleEdgeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EdgeHeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token = strings.TrimSpace(token)
	}
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Edge-Token"))
	}

	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "edge node token required"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 4*time.Second)
	defer cancel()

	node, err := h.pgDB.GetEdgeNodeByToken(ctx, token)
	if err != nil || node == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: edge node token not found or revoked"})
		return
	}

	clientIP := getClientIP(r)
	updatedNode, err := h.pgDB.UpdateEdgeNodeHeartbeat(ctx, token, clientIP, req.Version, 0)
	if err != nil {
		updatedNode = node
	}

	syncInterval := updatedNode.SyncInterval
	if syncInterval == "" {
		syncInterval = "online"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":                updatedNode.ActivationStatus, // "active", "pending_activation"
		"node_id":               updatedNode.ID.String(),
		"node_name":             updatedNode.Name,
		"tenant_name":           updatedNode.TenantName,
		"sync_interval":         syncInterval,
		"sync_interval_seconds": getIntervalSeconds(syncInterval),
		"ldap_config":           updatedNode.LDAPConfig,
		"server_time":           time.Now().UTC().Format(time.RFC3339),
	})
}

// EdgeIngestRequest carries a batch of forwarder syslog packets
type EdgeIngestRequest struct {
	Token    string             `json:"token"`
	NodeName string             `json:"node_name"`
	Events   []EdgeIngestPacket `json:"events"`
}

type EdgeIngestPacket struct {
	Data       string `json:"data"`
	SourceIP   string `json:"source_ip"`
	SourcePort uint16 `json:"source_port"`
	Protocol   string `json:"protocol"`
	Timestamp  string `json:"timestamp"`
}

// handleEdgeIngest receives raw syslog logs buffered on remote proxy nodes
func (h *Handler) handleEdgeIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var reader io.Reader = r.Body
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "gzip decompression failed: " + err.Error()})
			return
		}
		defer gz.Close()
		reader = gz
	}

	var req EdgeIngestRequest
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token = strings.TrimSpace(token)
	}
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Edge-Token"))
	}

	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "edge node token required"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 6*time.Second)
	defer cancel()

	node, err := h.pgDB.GetEdgeNodeByToken(ctx, token)
	if err != nil || node == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized edge node"})
		return
	}

	// Active Tenant & Node Status Enforcement (Phase 4)
	if node.ActivationStatus != "active" {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("edge node '%s' is not active (status: %s)", node.Name, node.ActivationStatus),
		})
		return
	}

	clientIP := getClientIP(r)
	count := int64(len(req.Events))

	if h.quotaEnforcer != nil {
		allowed, curEPS, maxEPS, qErr := h.quotaEnforcer.CheckIngestQuota(ctx, node.TenantName, int(count))
		if !allowed {
			if qErr != nil && strings.Contains(qErr.Error(), "suspended") {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": qErr.Error(),
				})
				return
			}
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":       fmt.Sprintf("tenant '%s' EPS quota exceeded: current %.1f EPS > max %d EPS limit", node.TenantName, curEPS, maxEPS),
				"current_eps": curEPS,
				"max_eps":     maxEPS,
			})
			return
		}
	}

	// Ingest each packet into high-performance pipeline
	for _, evt := range req.Events {
		if evt.Data == "" {
			continue
		}

		srcIP := net.ParseIP(evt.SourceIP)
		if srcIP == nil {
			srcIP = net.ParseIP(clientIP)
		}
		if srcIP == nil {
			srcIP = net.IPv4(127, 0, 0, 1)
		}

		srcPort := evt.SourcePort
		if srcPort == 0 {
			srcPort = 514
		}

		proto := strings.ToLower(evt.Protocol)
		if proto == "" {
			proto = "udp"
		}

		recTime := time.Now()
		if evt.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, evt.Timestamp); err == nil {
				recTime = t
			}
		}

		h.pipeline.Ingest(pipeline.RawPacket{
			Data:       []byte(evt.Data),
			SourceIP:   srcIP,
			SourcePort: srcPort,
			Protocol:   proto,
			ReceivedAt: recTime,
			Tenant:     node.TenantName,
		})
	}

	// Update node stats in background
	go func() {
		bgCtx, bgCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer bgCancel()
		_, _ = h.pgDB.UpdateEdgeNodeHeartbeat(bgCtx, token, clientIP, "", count)
	}()

	syncInterval := node.SyncInterval
	if syncInterval == "" {
		syncInterval = "online"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":                "ok",
		"ingested":              count,
		"sync_interval":         syncInterval,
		"sync_interval_seconds": getIntervalSeconds(syncInterval),
	})
}

// handleEdgeNodes handles GET and POST for edge proxy nodes in Settings
func (h *Handler) handleEdgeNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := contextWithTimeout(r, 3*time.Second)
		defer cancel()

		tenantFilter := h.tenantScope(r)
		nodes, err := h.pgDB.ListEdgeNodes(ctx, tenantFilter)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if nodes == nil {
			nodes = []*models.EdgeNode{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"nodes": nodes,
			"valid_intervals": []string{
				"online",
				"every 60 second",
				"every 5 min",
				"every 15 min",
				"every 30 min",
				"every hour",
			},
		})

	case http.MethodPost:
		var req struct {
			Name             string                 `json:"name"`
			TenantName       string                 `json:"tenant_name"`
			SyncInterval     string                 `json:"sync_interval"`
			AdminName        string                 `json:"admin_name"`
			AdminEmail       string                 `json:"admin_email"`
			AdminUsername    string                 `json:"admin_username"`
			AdminInitialPass string                 `json:"admin_initial_pass"`
			ActivationStatus string                 `json:"activation_status"`
			LDAPConfig       map[string]interface{} `json:"ldap_config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}

		name := strings.TrimSpace(req.Name)
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node name is required"})
			return
		}

		tenant := strings.TrimSpace(req.TenantName)
		if sess, ok := h.getSession(r); ok && !sess.IsRootOperator() {
			tenant = sess.TenantSlug // tenant admins can only provision nodes for themselves
		}
		if tenant == "" {
			tenant = "default"
		}

		// Quota: root (default) tenant is unlimited; other tenants honour max_nodes (0 = unlimited)
		if tenant != "default" {
			qctx, qcancel := contextWithTimeout(r, 3*time.Second)
			t, terr := h.pgDB.GetTenantBySlug(qctx, tenant)
			if terr == nil && t == nil {
				qcancel()
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown tenant: " + tenant})
				return
			}
			if t != nil && t.MaxNodes > 0 {
				if n, cerr := h.pgDB.CountEdgeNodesByTenant(qctx, tenant); cerr == nil && n >= t.MaxNodes {
					qcancel()
					writeJSON(w, http.StatusForbidden, map[string]string{
						"error": fmt.Sprintf("tenant '%s' node quota reached (%d/%d)", tenant, n, t.MaxNodes),
					})
					return
				}
			}
			qcancel()
		}

		interval := strings.TrimSpace(req.SyncInterval)
		if _, ok := validSyncIntervals[interval]; !ok {
			interval = "online"
		}

		actStatus := strings.TrimSpace(req.ActivationStatus)
		if actStatus == "" {
			actStatus = "active"
		}

		node := &models.EdgeNode{
			ID:               uuid.New(),
			Name:             name,
			Token:            generateEdgeToken(),
			TenantName:       tenant,
			SyncInterval:     interval,
			AdminName:        strings.TrimSpace(req.AdminName),
			AdminEmail:       strings.TrimSpace(req.AdminEmail),
			AdminUsername:    strings.TrimSpace(req.AdminUsername),
			AdminInitialPass: strings.TrimSpace(req.AdminInitialPass),
			ActivationStatus: actStatus,
			LDAPConfig:       req.LDAPConfig,
		}

		ctx, cancel := contextWithTimeout(r, 4*time.Second)
		defer cancel()

		if err := h.pgDB.CreateEdgeNode(ctx, node); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "creating edge node: " + err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, node)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleEdgeNodeInterval updates sync schedule from Cloud UI
func (h *Handler) handleEdgeNodeInterval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID           string `json:"id"`
		SyncInterval string `json:"sync_interval"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	nodeID, err := uuid.Parse(strings.TrimSpace(req.ID))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
		return
	}

	interval := strings.TrimSpace(req.SyncInterval)
	if _, ok := validSyncIntervals[interval]; !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid sync interval"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 3*time.Second)
	defer cancel()

	if err := h.pgDB.UpdateEdgeNodeInterval(ctx, nodeID, interval); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	updated, _ := h.pgDB.GetEdgeNodeByID(ctx, nodeID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"node":          updated,
		"sync_interval": interval,
	})
}

// handleEdgeNodeDelete deletes or revokes an edge node
func (h *Handler) handleEdgeNodeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		var req struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		idStr = req.ID
	}

	nodeID, err := uuid.Parse(strings.TrimSpace(idStr))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 3*time.Second)
	defer cancel()

	if err := h.pgDB.DeleteEdgeNode(ctx, nodeID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleEdgeInstallScript serves proxy_install.sh for easy 1-line installation
func (h *Handler) handleEdgeInstallScript(w http.ResponseWriter, r *http.Request) {
	// Look for script in scripts/proxy_install.sh or local directory
	candidates := []string{
		"scripts/proxy_install.sh",
		"./proxy_install.sh",
		"/opt/syslog-platform/scripts/proxy_install.sh",
	}

	var content []byte
	var err error
	for _, path := range candidates {
		if content, err = os.ReadFile(path); err == nil {
			break
		}
	}

	if len(content) == 0 {
		http.Error(w, "proxy_install.sh script not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// handleEdgeDownloadBinary serves the compiled logseal-proxy binary for remote Linux nodes
func (h *Handler) handleEdgeDownloadBinary(w http.ResponseWriter, r *http.Request) {
	candidates := []string{
		"/opt/syslog-platform/bin/logseal-proxy",
		"bin/logseal-proxy",
		"./logseal-proxy",
		"/usr/local/bin/logseal-proxy",
	}

	var foundPath string
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			foundPath = p
			break
		}
	}

	if foundPath == "" {
		http.Error(w, "logseal-proxy binary not yet available on server", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"logseal-proxy\"")
	http.ServeFile(w, r, foundPath)
}

// handleEdgeNodeActivate enables a pending edge node and provisions its user & cloud LDAP settings
func (h *Handler) handleEdgeNodeActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID            string                 `json:"id"`
		AdminName     string                 `json:"admin_name"`
		AdminEmail    string                 `json:"admin_email"`
		AdminUsername string                 `json:"admin_username"`
		AdminPass     string                 `json:"admin_pass"`
		SyncInterval  string                 `json:"sync_interval"`
		LDAPConfig    map[string]interface{} `json:"ldap_config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	nodeID, err := uuid.Parse(strings.TrimSpace(req.ID))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
		return
	}

	interval := strings.TrimSpace(req.SyncInterval)
	if _, ok := validSyncIntervals[interval]; !ok {
		interval = "online"
	}

	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()

	if err := h.pgDB.ActivateEdgeNode(
		ctx,
		nodeID,
		strings.TrimSpace(req.AdminName),
		strings.TrimSpace(req.AdminEmail),
		strings.TrimSpace(req.AdminUsername),
		strings.TrimSpace(req.AdminPass),
		interval,
		req.LDAPConfig,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "activating node: " + err.Error()})
		return
	}

	updated, _ := h.pgDB.GetEdgeNodeByID(ctx, nodeID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": "Edge proxy node successfully activated and preconfigured",
		"node":    updated,
	})
}

// handleTenants handles GET, POST, and DELETE for multi-tenant organizations
func (h *Handler) handleTenants(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 4*time.Second)
	defer cancel()

	session, _ := h.getSession(r)
	isRoot := session == nil || session.IsRootOperator()
	if r.Method != http.MethodGet && !isRoot {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only the root organization can manage tenants"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		tenants, err := h.pgDB.ListTenants(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tenants == nil {
			tenants = []*models.Tenant{}
		}

		usage, _ := h.pgDB.GetTenantUsage(ctx)
		epsByTenant := h.currentEPSByTenant(ctx)
		logCounts, _ := h.chClient.GetTenantStorageBreakdown(ctx)

		type tenantView struct {
			*models.Tenant
			Unlimited        bool    `json:"unlimited"`
			NodeCount        int     `json:"node_count"`
			DeviceCount      int     `json:"device_count"`
			LogCount         uint64  `json:"log_count"`
			CurrentEPS       float64 `json:"current_eps"`
			NodeQuotaPercent float64 `json:"node_quota_percent"`
			EPSQuotaPercent  float64 `json:"eps_quota_percent"`
			QuotaExceeded    bool    `json:"quota_exceeded"`
		}
		views := make([]tenantView, 0, len(tenants))
		var totalNodes, totalDevices int
		var totalLogs uint64
		var totalEPS float64
		for _, t := range tenants {
			// Tenant users only see their own organization
			if !isRoot && t.Slug != session.TenantSlug {
				continue
			}
			v := tenantView{Tenant: t, Unlimited: t.Slug == "default" || (t.MaxNodes <= 0 && t.MaxEPS <= 0)}
			if u, ok := usage[t.Slug]; ok {
				v.NodeCount = u.NodeCount
				v.DeviceCount = u.DeviceCount
			}
			if logCounts != nil {
				v.LogCount = logCounts[t.Slug]
			}
			v.CurrentEPS = epsByTenant[t.Slug]
			if t.MaxNodes > 0 {
				v.NodeQuotaPercent = float64(v.NodeCount) / float64(t.MaxNodes) * 100.0
			}
			if t.MaxEPS > 0 {
				v.EPSQuotaPercent = v.CurrentEPS / float64(t.MaxEPS) * 100.0
			}
			v.QuotaExceeded = (t.MaxNodes > 0 && v.NodeCount >= t.MaxNodes) || (t.MaxEPS > 0 && v.CurrentEPS >= float64(t.MaxEPS))

			totalNodes += v.NodeCount
			totalDevices += v.DeviceCount
			totalLogs += v.LogCount
			totalEPS += v.CurrentEPS
			views = append(views, v)
		}

		currentTenant := "default"
		if session != nil {
			currentTenant = session.TenantSlug
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"tenants":        views,
			"is_root":        isRoot,
			"current_tenant": currentTenant,
			// Root operates every tenant's nodes/EPS without quota: aggregate totals
			"totals": map[string]interface{}{
				"nodes":   totalNodes,
				"devices": totalDevices,
				"logs":    totalLogs,
				"eps":     totalEPS,
			},
		})

	case http.MethodPost:
		var req struct {
			Slug             string `json:"slug"`
			Name             string `json:"name"`
			Description      string `json:"description"`
			AdminName        string `json:"admin_name"`
			AdminEmail       string `json:"admin_email"`
			AdminUsername    string `json:"admin_username"`
			AdminInitialPass string `json:"admin_initial_pass"`
			MaxNodes         int    `json:"max_nodes"`
			MaxEPS           int    `json:"max_eps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}

		name := strings.TrimSpace(req.Name)
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant name is required"})
			return
		}

		slug := strings.TrimSpace(req.Slug)
		if slug == "" {
			slug = strings.ToLower(strings.ReplaceAll(name, " ", "-"))
		}

		t := &models.Tenant{
			Slug:          slug,
			Name:          name,
			Description:   strings.TrimSpace(req.Description),
			AdminName:     strings.TrimSpace(req.AdminName),
			AdminEmail:    strings.TrimSpace(req.AdminEmail),
			AdminUsername: strings.TrimSpace(req.AdminUsername),
			Status:        "active",
			MaxNodes:      req.MaxNodes,
			MaxEPS:        req.MaxEPS,
		}

		if err := h.pgDB.CreateTenant(ctx, t, strings.TrimSpace(req.AdminInitialPass)); err != nil {
			h.recordAudit(r, "TENANT_CREATE", "tenant/"+slug, "FAILED", map[string]interface{}{"error": err.Error()})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "creating tenant: " + err.Error()})
			return
		}

		h.recordAudit(r, "TENANT_CREATE", "tenant/"+slug, "SUCCESS", map[string]interface{}{"name": name, "max_nodes": req.MaxNodes, "max_eps": req.MaxEPS})
		writeJSON(w, http.StatusCreated, t)

	case http.MethodDelete:
		slug := strings.TrimSpace(r.URL.Query().Get("slug"))
		if slug == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug is required"})
			return
		}
		if slug == "default" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete default root tenant"})
			return
		}

		if err := h.pgDB.DeleteTenant(ctx, slug); err != nil {
			h.recordAudit(r, "TENANT_DELETE", "tenant/"+slug, "FAILED", map[string]interface{}{"error": err.Error()})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		h.recordAudit(r, "TENANT_DELETE", "tenant/"+slug, "SUCCESS", map[string]interface{}{"slug": slug})
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// currentEPSByTenant returns events-per-second over the last 60s grouped by tenant (cached 10s)
func (h *Handler) currentEPSByTenant(ctx context.Context) map[string]float64 {
	out := map[string]float64{}
	key := cache.MakeKey("tenant_eps")
	if h.resultCache != nil {
		if b, ok := h.resultCache.Get(key); ok && json.Unmarshal(b, &out) == nil {
			return out
		}
	}
	q := fmt.Sprintf("SELECT tenant, count() FROM %s.syslog_events WHERE received_at >= now() - INTERVAL 60 SECOND GROUP BY tenant", h.chClient.Database())
	rows, err := h.chClient.QueryEvents(ctx, q)
	if err != nil || rows == nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var n uint64
		if rows.Scan(&t, &n) == nil {
			out[t] = float64(n) / 60.0
		}
	}
	if h.resultCache != nil {
		if b, err := json.Marshal(out); err == nil {
			h.resultCache.Set(key, b, 10*time.Second)
		}
	}
	return out
}
