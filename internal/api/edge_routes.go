package api

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/cache"
	"github.com/syslog-platform/logger/internal/database/postgres"
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

// isIPAllowed checks whether clientIP satisfies the allowedCIDRs Zero-Trust whitelist
func isIPAllowed(clientIP, allowedCIDRs string) bool {
	allowedCIDRs = strings.TrimSpace(allowedCIDRs)
	if allowedCIDRs == "" || allowedCIDRs == "*" {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return false
	}
	parts := strings.Split(allowedCIDRs, ",")
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			if targetIP := net.ParseIP(item); targetIP != nil && targetIP.Equal(ip) {
				return true
			}
			continue
		}
		if _, ipNet, err := net.ParseCIDR(item); err == nil && ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// extractEdgeToken retrieves authentication token from headers or request payload
func extractEdgeToken(r *http.Request, bodyToken string) string {
	t := strings.TrimSpace(bodyToken)
	if t != "" {
		return t
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return strings.TrimSpace(auth[7:])
		}
	}
	if t = strings.TrimSpace(r.Header.Get("X-Edge-Token")); t != "" {
		return t
	}
	if t = strings.TrimSpace(r.Header.Get("X-API-Key")); t != "" {
		return t
	}
	return ""
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

	token := extractEdgeToken(r, req.Token)
	clientIP := getClientIP(r)

	if token == "" {
		h.recordAudit(r, "EDGE_AUTH_FAILURE", "edge/heartbeat", "FAILED", map[string]interface{}{
			"reason":    "missing token",
			"client_ip": clientIP,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "edge node token required"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 4*time.Second)
	defer cancel()

	node, err := h.pgDB.GetEdgeNodeByToken(ctx, token)
	if err != nil || node == nil {
		h.recordAudit(r, "EDGE_AUTH_FAILURE", "edge/heartbeat", "FAILED", map[string]interface{}{
			"reason":       "token not found or revoked",
			"token_prefix": postgres.MaskEdgeToken(token),
			"client_ip":    clientIP,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: edge node token not found or revoked"})
		return
	}

	// Zero-Trust Expiration check
	if node.KeyExpiresAt != nil && time.Now().After(*node.KeyExpiresAt) {
		h.recordAudit(r, "EDGE_AUTH_EXPIRED", "edge/node/"+node.ID.String(), "FAILED", map[string]interface{}{
			"node_name":   node.Name,
			"tenant_name": node.TenantName,
			"expired_at":  node.KeyExpiresAt.Format(time.RFC3339),
			"client_ip":   clientIP,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: edge node api key has expired"})
		return
	}

	// Zero-Trust Source IP / CIDR check
	if !isIPAllowed(clientIP, node.AllowedCIDRs) {
		h.recordAudit(r, "EDGE_IP_BLOCKED", "edge/node/"+node.ID.String(), "BLOCKED", map[string]interface{}{
			"node_name":     node.Name,
			"tenant_name":   node.TenantName,
			"client_ip":     clientIP,
			"allowed_cidrs": node.AllowedCIDRs,
		})
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("forbidden: client ip '%s' not in allowed cidrs whitelist", clientIP),
		})
		return
	}

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

	token := extractEdgeToken(r, req.Token)
	clientIP := getClientIP(r)

	if token == "" {
		h.recordAudit(r, "EDGE_AUTH_FAILURE", "edge/ingest", "FAILED", map[string]interface{}{
			"reason":    "missing token",
			"client_ip": clientIP,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "edge node token required"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 6*time.Second)
	defer cancel()

	node, err := h.pgDB.GetEdgeNodeByToken(ctx, token)
	if err != nil || node == nil {
		h.recordAudit(r, "EDGE_AUTH_FAILURE", "edge/ingest", "FAILED", map[string]interface{}{
			"reason":       "unauthorized edge node",
			"token_prefix": postgres.MaskEdgeToken(token),
			"client_ip":    clientIP,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized edge node"})
		return
	}

	// Zero-Trust Expiration check
	if node.KeyExpiresAt != nil && time.Now().After(*node.KeyExpiresAt) {
		h.recordAudit(r, "EDGE_AUTH_EXPIRED", "edge/node/"+node.ID.String(), "FAILED", map[string]interface{}{
			"node_name":   node.Name,
			"tenant_name": node.TenantName,
			"expired_at":  node.KeyExpiresAt.Format(time.RFC3339),
			"client_ip":   clientIP,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: edge node api key has expired"})
		return
	}

	// Zero-Trust Source IP / CIDR check
	if !isIPAllowed(clientIP, node.AllowedCIDRs) {
		h.recordAudit(r, "EDGE_IP_BLOCKED", "edge/node/"+node.ID.String(), "BLOCKED", map[string]interface{}{
			"node_name":     node.Name,
			"tenant_name":   node.TenantName,
			"client_ip":     clientIP,
			"allowed_cidrs": node.AllowedCIDRs,
		})
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("forbidden: client ip '%s' not in allowed cidrs whitelist", clientIP),
		})
		return
	}

	// Active Tenant & Node Status Enforcement (Phase 4)
	if node.ActivationStatus != "active" {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("edge node '%s' is not active (status: %s)", node.Name, node.ActivationStatus),
		})
		return
	}

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
			AllowedCIDRs     string                 `json:"allowed_cidrs"`
			ExpiresDays      int                    `json:"expires_days"`
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

		var keyExpiresAt *time.Time
		if req.ExpiresDays > 0 {
			exp := time.Now().AddDate(0, 0, req.ExpiresDays)
			keyExpiresAt = &exp
		}

		rawToken := generateEdgeToken()
		now := time.Now()
		node := &models.EdgeNode{
			ID:               uuid.New(),
			Name:             name,
			Token:            rawToken,
			TokenHash:        postgres.HashEdgeToken(rawToken),
			TokenPrefix:      postgres.MaskEdgeToken(rawToken),
			KeyExpiresAt:     keyExpiresAt,
			AllowedCIDRs:     strings.TrimSpace(req.AllowedCIDRs),
			LastKeyRotatedAt: &now,
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
			h.recordAudit(r, "EDGE_NODE_CREATED", "edge/node", "FAILED", map[string]interface{}{
				"error":       err.Error(),
				"node_name":   node.Name,
				"tenant_name": node.TenantName,
			})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "creating edge node: " + err.Error()})
			return
		}

		h.recordAudit(r, "EDGE_NODE_CREATED", "edge/node/"+node.ID.String(), "SUCCESS", map[string]interface{}{
			"node_name":     node.Name,
			"tenant_name":   node.TenantName,
			"token_prefix":  node.TokenPrefix,
			"allowed_cidrs": node.AllowedCIDRs,
			"expires_days":  req.ExpiresDays,
		})

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
		h.recordAudit(r, "EDGE_INTERVAL_UPDATED", "edge/node/"+nodeID.String(), "FAILED", map[string]interface{}{
			"error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "EDGE_INTERVAL_UPDATED", "edge/node/"+nodeID.String(), "SUCCESS", map[string]interface{}{
		"sync_interval": interval,
	})

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
		h.recordAudit(r, "EDGE_NODE_DELETED", "edge/node/"+nodeID.String(), "FAILED", map[string]interface{}{
			"error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "EDGE_NODE_DELETED", "edge/node/"+nodeID.String(), "SUCCESS", map[string]interface{}{
		"node_id": nodeID.String(),
	})

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
		AllowedCIDRs  string                 `json:"allowed_cidrs"`
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
		strings.TrimSpace(req.AllowedCIDRs),
	); err != nil {
		h.recordAudit(r, "EDGE_NODE_ACTIVATED", "edge/node/"+nodeID.String(), "FAILED", map[string]interface{}{
			"error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "activating node: " + err.Error()})
		return
	}

	h.recordAudit(r, "EDGE_NODE_ACTIVATED", "edge/node/"+nodeID.String(), "SUCCESS", map[string]interface{}{
		"node_id":       nodeID.String(),
		"allowed_cidrs": req.AllowedCIDRs,
	})

	updated, _ := h.pgDB.GetEdgeNodeByID(ctx, nodeID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": "Edge proxy node successfully activated and preconfigured",
		"node":    updated,
	})
}

// handleEdgeRotateKey generates a new secure token and invalidates the previous one
func (h *Handler) handleEdgeRotateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID          string `json:"id"`
		ExpiresDays int    `json:"expires_days"`
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

	var expiresAt *time.Time
	if req.ExpiresDays > 0 {
		exp := time.Now().AddDate(0, 0, req.ExpiresDays)
		expiresAt = &exp
	}

	newToken := generateEdgeToken()

	ctx, cancel := contextWithTimeout(r, 4*time.Second)
	defer cancel()

	updated, err := h.pgDB.RotateEdgeNodeToken(ctx, nodeID, newToken, expiresAt)
	if err != nil {
		h.recordAudit(r, "EDGE_KEY_ROTATED", "edge/node/"+nodeID.String(), "FAILED", map[string]interface{}{
			"error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rotating token: " + err.Error()})
		return
	}

	h.recordAudit(r, "EDGE_KEY_ROTATED", "edge/node/"+nodeID.String(), "SUCCESS", map[string]interface{}{
		"node_name":    updated.Name,
		"token_prefix": updated.TokenPrefix,
		"expires_days": req.ExpiresDays,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "ok",
		"node_id":      updated.ID.String(),
		"token":        newToken,
		"token_prefix": updated.TokenPrefix,
		"expires_at":   updated.KeyExpiresAt,
	})
}

// handleEdgeNodeCIDRs updates allowed IP / CIDR whitelist for an edge forwarder
func (h *Handler) handleEdgeNodeCIDRs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID           string `json:"id"`
		AllowedCIDRs string `json:"allowed_cidrs"`
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

	ctx, cancel := contextWithTimeout(r, 3*time.Second)
	defer cancel()

	if err := h.pgDB.UpdateEdgeNodeCIDRs(ctx, nodeID, req.AllowedCIDRs); err != nil {
		h.recordAudit(r, "EDGE_CIDR_UPDATED", "edge/node/"+nodeID.String(), "FAILED", map[string]interface{}{
			"error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "updating allowed cidrs: " + err.Error()})
		return
	}

	h.recordAudit(r, "EDGE_CIDR_UPDATED", "edge/node/"+nodeID.String(), "SUCCESS", map[string]interface{}{
		"allowed_cidrs": req.AllowedCIDRs,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"allowed_cidrs": req.AllowedCIDRs,
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
		storageMetrics, _ := h.chClient.GetTenantStorageMetrics(ctx)

		type tenantView struct {
			*models.Tenant
			Unlimited           bool    `json:"unlimited"`
			NodeCount           int     `json:"node_count"`
			DeviceCount         int     `json:"device_count"`
			LogCount            uint64  `json:"log_count"`
			CurrentEPS          float64 `json:"current_eps"`
			NodeQuotaPercent    float64 `json:"node_quota_percent"`
			EPSQuotaPercent     float64 `json:"eps_quota_percent"`
			QuotaExceeded       bool    `json:"quota_exceeded"`
			StorageBytes        uint64  `json:"storage_bytes"`
			StorageGB           float64 `json:"storage_gb"`
			StorageQuotaPercent float64 `json:"storage_quota_percent"`
			StorageExceeded     bool    `json:"storage_exceeded"`
			OldestLogTime       string  `json:"oldest_log_time"`
			NewestLogTime       string  `json:"newest_log_time"`
		}
		views := make([]tenantView, 0, len(tenants))
		var totalNodes, totalDevices int
		var totalLogs, totalStorageBytes uint64
		var totalEPS float64
		for _, t := range tenants {
			// Tenant users only see their own organization
			if !isRoot && t.Slug != session.TenantSlug {
				continue
			}
			v := tenantView{Tenant: t, Unlimited: t.Slug == "default" || (t.MaxNodes <= 0 && t.MaxEPS <= 0 && t.MaxStorageGB <= 0 && t.RetentionDays <= 0)}
			if u, ok := usage[t.Slug]; ok {
				v.NodeCount = u.NodeCount
				v.DeviceCount = u.DeviceCount
			}
			if logCounts != nil {
				v.LogCount = logCounts[t.Slug]
			}
			if storageMetrics != nil {
				if sm, ok := storageMetrics[t.Slug]; ok && sm != nil {
					v.StorageBytes = sm.TotalBytes
					v.StorageGB = float64(sm.TotalBytes) / (1024.0 * 1024.0 * 1024.0)
					if sm.LogCount > 0 && v.LogCount == 0 {
						v.LogCount = sm.LogCount
					}
					if !sm.OldestTimestamp.IsZero() {
						v.OldestLogTime = sm.OldestTimestamp.Format("2006-01-02 15:04:05")
					}
					if !sm.NewestTimestamp.IsZero() {
						v.NewestLogTime = sm.NewestTimestamp.Format("2006-01-02 15:04:05")
					}
				}
			}
			v.CurrentEPS = epsByTenant[t.Slug]
			if t.MaxNodes > 0 {
				v.NodeQuotaPercent = float64(v.NodeCount) / float64(t.MaxNodes) * 100.0
			}
			if t.MaxEPS > 0 {
				v.EPSQuotaPercent = v.CurrentEPS / float64(t.MaxEPS) * 100.0
			}
			if t.MaxStorageGB > 0 {
				maxBytes := float64(t.MaxStorageGB) * 1024.0 * 1024.0 * 1024.0
				v.StorageQuotaPercent = (float64(v.StorageBytes) / maxBytes) * 100.0
				v.StorageExceeded = v.StorageBytes >= uint64(maxBytes)
			}
			v.QuotaExceeded = (t.MaxNodes > 0 && v.NodeCount >= t.MaxNodes) ||
				(t.MaxEPS > 0 && v.CurrentEPS >= float64(t.MaxEPS)) ||
				v.StorageExceeded

			totalNodes += v.NodeCount
			totalDevices += v.DeviceCount
			totalLogs += v.LogCount
			totalEPS += v.CurrentEPS
			totalStorageBytes += v.StorageBytes
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
				"nodes":         totalNodes,
				"devices":       totalDevices,
				"logs":          totalLogs,
				"eps":           totalEPS,
				"storage_bytes": totalStorageBytes,
				"storage_gb":    float64(totalStorageBytes) / (1024.0 * 1024.0 * 1024.0),
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
			IngestPolicy     string `json:"ingest_policy"`
			MaxNodes         int    `json:"max_nodes"`
			MaxEPS           int    `json:"max_eps"`
			RetentionDays    int    `json:"retention_days"`
			MaxStorageGB     int    `json:"max_storage_gb"`
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

		policy := strings.ToLower(strings.TrimSpace(req.IngestPolicy))
		if policy != "strict" {
			policy = "permissive"
		}

		t := &models.Tenant{
			Slug:          slug,
			Name:          name,
			Description:   strings.TrimSpace(req.Description),
			AdminName:     strings.TrimSpace(req.AdminName),
			AdminEmail:    strings.TrimSpace(req.AdminEmail),
			AdminUsername: strings.TrimSpace(req.AdminUsername),
			Status:        "active",
			IngestPolicy:  policy,
			MaxNodes:      req.MaxNodes,
			MaxEPS:        req.MaxEPS,
			RetentionDays: req.RetentionDays,
			MaxStorageGB:  req.MaxStorageGB,
		}

		if err := h.pgDB.CreateTenant(ctx, t, strings.TrimSpace(req.AdminInitialPass)); err != nil {
			h.recordAudit(r, "TENANT_CREATE", "tenant/"+slug, "FAILED", map[string]interface{}{"error": err.Error()})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "creating tenant: " + err.Error()})
			return
		}

		_ = h.deviceCache.Refresh(ctx)
		h.recordAudit(r, "TENANT_CREATE", "tenant/"+slug, "SUCCESS", map[string]interface{}{
			"name":           name,
			"ingest_policy":  policy,
			"max_nodes":      req.MaxNodes,
			"max_eps":        req.MaxEPS,
			"retention_days": req.RetentionDays,
			"max_storage_gb": req.MaxStorageGB,
		})
		writeJSON(w, http.StatusCreated, t)

	case http.MethodPut:
		var req struct {
			Slug          string  `json:"slug"`
			IngestPolicy  *string `json:"ingest_policy"`
			MaxNodes      *int    `json:"max_nodes"`
			MaxEPS        *int    `json:"max_eps"`
			RetentionDays *int    `json:"retention_days"`
			MaxStorageGB  *int    `json:"max_storage_gb"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}
		slug := strings.TrimSpace(req.Slug)
		if slug == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug is required"})
			return
		}

		existing, err := h.pgDB.GetTenantBySlug(ctx, slug)
		if err != nil || existing == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
			return
		}

		maxNodes := existing.MaxNodes
		if req.MaxNodes != nil {
			maxNodes = *req.MaxNodes
		}
		maxEPS := existing.MaxEPS
		if req.MaxEPS != nil {
			maxEPS = *req.MaxEPS
		}
		retentionDays := existing.RetentionDays
		if req.RetentionDays != nil {
			retentionDays = *req.RetentionDays
		}
		maxStorageGB := existing.MaxStorageGB
		if req.MaxStorageGB != nil {
			maxStorageGB = *req.MaxStorageGB
		}
		policy := existing.IngestPolicy
		if req.IngestPolicy != nil && *req.IngestPolicy != "" {
			p := strings.ToLower(strings.TrimSpace(*req.IngestPolicy))
			if p == "strict" || p == "permissive" {
				policy = p
			}
		}

		if err := h.pgDB.UpdateTenantQuotas(ctx, slug, maxNodes, maxEPS, retentionDays, maxStorageGB, policy); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "updating quotas: " + err.Error()})
			return
		}
		_ = h.deviceCache.Refresh(ctx)
		h.recordAudit(r, "TENANT_QUOTA_UPDATE", "tenant/"+slug, "SUCCESS", map[string]interface{}{
			"max_nodes":      maxNodes,
			"max_eps":        maxEPS,
			"retention_days": retentionDays,
			"max_storage_gb": maxStorageGB,
			"ingest_policy":  policy,
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":         "updated",
			"slug":           slug,
			"max_nodes":      maxNodes,
			"max_eps":        maxEPS,
			"retention_days": retentionDays,
			"max_storage_gb": maxStorageGB,
			"ingest_policy":  policy,
		})

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

// handleTenantPrune triggers on-demand retention pruning and automated partition drops
func (h *Handler) handleTenantPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _ := h.getSession(r)
	isRoot := session == nil || session.IsRootOperator()
	if !isRoot {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only root administrators can trigger retention prune"})
		return
	}

	ctx, cancel := contextWithTimeout(r, 60*time.Second)
	defer cancel()

	var req struct {
		TenantSlug     string `json:"tenant"`
		Days           int    `json:"days"`
		DropPartitions bool   `json:"drop_partitions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	tenants, err := h.pgDB.ListTenants(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing tenants: " + err.Error()})
		return
	}

	type pruneResult struct {
		Tenant        string `json:"tenant"`
		RetentionDays int    `json:"retention_days"`
		PrunedRows    int64  `json:"pruned_rows"`
		StorageFreed  bool   `json:"storage_freed"`
	}

	results := []pruneResult{}
	storageMetrics, _ := h.chClient.GetTenantStorageMetrics(ctx)

	for _, t := range tenants {
		if req.TenantSlug != "" && t.Slug != req.TenantSlug {
			continue
		}
		retention := t.RetentionDays
		if req.TenantSlug == t.Slug && req.Days > 0 {
			retention = req.Days
		}
		res := pruneResult{Tenant: t.Slug, RetentionDays: retention}
		if retention > 0 {
			err := h.chClient.PruneTenantOlderThanDays(ctx, t.Slug, retention)
			if err == nil {
				res.PrunedRows = 1
			}
		}
		if t.MaxStorageGB > 0 && storageMetrics != nil {
			if sm, ok := storageMetrics[t.Slug]; ok && sm != nil {
				maxBytes := uint64(t.MaxStorageGB) * 1024 * 1024 * 1024
				if sm.TotalBytes > maxBytes {
					_ = h.chClient.PruneTenantOldestBatch(ctx, t.Slug, 24)
					res.StorageFreed = true
				}
			}
		}
		results = append(results, res)
	}

	var droppedPartitions []string
	if req.DropPartitions {
		hasUnlimited := false
		maxRetention := 0
		for _, t := range tenants {
			if t.RetentionDays == 0 {
				hasUnlimited = true
				break
			}
			if t.RetentionDays > maxRetention {
				maxRetention = t.RetentionDays
			}
		}
		if !hasUnlimited && maxRetention > 0 {
			cutoff := time.Now().AddDate(0, 0, -maxRetention)
			cutoffMonth := cutoff.Format("200601")
			if dropped, err := h.chClient.PrunePartitionsOlderThan(ctx, cutoffMonth); err == nil && len(dropped) > 0 {
				droppedPartitions = append(droppedPartitions, dropped...)
			}
		}
	}

	h.recordAudit(r, "TENANT_RETENTION_PRUNE", "tenants/prune", "SUCCESS", map[string]interface{}{
		"target_tenant":      req.TenantSlug,
		"results_count":      len(results),
		"dropped_partitions": droppedPartitions,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":             "completed",
		"tenants_evaluated":  len(results),
		"results":            results,
		"dropped_partitions": droppedPartitions,
	})
}

// StartTenantRetentionWorker launches the background worker that enforces per-tenant data retention and storage quotas
func (h *Handler) StartTenantRetentionWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		defer ticker.Stop()
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Minute):
			h.runRetentionCycle(ctx)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.runRetentionCycle(ctx)
			}
		}
	}()
}

func (h *Handler) runRetentionCycle(ctx context.Context) {
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	tenants, err := h.pgDB.ListTenants(runCtx)
	if err != nil || len(tenants) == 0 {
		return
	}

	storageMetrics, _ := h.chClient.GetTenantStorageMetrics(runCtx)
	for _, t := range tenants {
		if t.RetentionDays > 0 {
			if err := h.chClient.PruneTenantOlderThanDays(runCtx, t.Slug, t.RetentionDays); err != nil {
				log.Printf("[RetentionWorker] Pruning tenant '%s' (>%d days) failed: %v", t.Slug, t.RetentionDays, err)
			} else {
				log.Printf("[RetentionWorker] Pruned events older than %d days for tenant '%s'", t.RetentionDays, t.Slug)
			}
		}

		if t.MaxStorageGB > 0 && storageMetrics != nil {
			if sm, ok := storageMetrics[t.Slug]; ok && sm != nil {
				maxBytes := uint64(t.MaxStorageGB) * 1024 * 1024 * 1024
				if sm.TotalBytes > maxBytes {
					log.Printf("[RetentionWorker] Tenant '%s' exceeded storage quota (%d bytes > %d bytes max). Purging oldest 24h batch...",
						t.Slug, sm.TotalBytes, maxBytes)
					_ = h.chClient.PruneTenantOldestBatch(runCtx, t.Slug, 24)
				}
			}
		}
	}

	hasUnlimited := false
	maxRetention := 0
	for _, t := range tenants {
		if t.RetentionDays == 0 {
			hasUnlimited = true
			break
		}
		if t.RetentionDays > maxRetention {
			maxRetention = t.RetentionDays
		}
	}
	if !hasUnlimited && maxRetention > 0 {
		cutoff := time.Now().AddDate(0, 0, -maxRetention)
		cutoffMonth := cutoff.Format("200601")
		if dropped, err := h.chClient.PrunePartitionsOlderThan(runCtx, cutoffMonth); err == nil && len(dropped) > 0 {
			log.Printf("[RetentionWorker] Partition drop evaluated for months <= %s (dropped partitions: %v)", cutoffMonth, dropped)
		}
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
