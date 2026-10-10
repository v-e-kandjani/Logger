package api

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
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
		"status":                "ok",
		"node_id":               updatedNode.ID.String(),
		"node_name":             updatedNode.Name,
		"tenant_name":           updatedNode.TenantName,
		"sync_interval":         syncInterval,
		"sync_interval_seconds": getIntervalSeconds(syncInterval),
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

	clientIP := getClientIP(r)
	count := int64(len(req.Events))

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

// handleEdgeNodesList handles GET and POST for edge proxy nodes in Settings
func (h *Handler) handleEdgeNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := contextWithTimeout(r, 3*time.Second)
		defer cancel()

		nodes, err := h.pgDB.ListEdgeNodes(ctx)
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
			Name         string `json:"name"`
			TenantName   string `json:"tenant_name"`
			SyncInterval string `json:"sync_interval"`
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
		if tenant == "" {
			tenant = "default"
		}

		interval := strings.TrimSpace(req.SyncInterval)
		if _, ok := validSyncIntervals[interval]; !ok {
			interval = "online"
		}

		node := &models.EdgeNode{
			ID:           uuid.New(),
			Name:         name,
			Token:        generateEdgeToken(),
			TenantName:   tenant,
			SyncInterval: interval,
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
