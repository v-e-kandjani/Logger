package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
)

// handleTIFeeds handles listing and creating threat intelligence feeds (Phase Q)
func (h *Handler) handleTIFeeds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		feeds, err := h.pgDB.ListTIFeeds(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed listing feeds: " + err.Error()})
			return
		}
		if feeds == nil {
			feeds = []models.TIFeed{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"feeds": feeds})

	case http.MethodPost:
		var feed models.TIFeed
		if err := json.NewDecoder(r.Body).Decode(&feed); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}
		if strings.TrimSpace(feed.Name) == "" || strings.TrimSpace(feed.URL) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and url are required"})
			return
		}
		if feed.PollIntervalMinutes <= 0 {
			feed.PollIntervalMinutes = 60
		}
		if feed.DefaultConfidence <= 0 {
			feed.DefaultConfidence = 80
		}
		if feed.FeedType == "" {
			feed.FeedType = "plain_list"
		}
		if feed.IndicatorType == "" {
			feed.IndicatorType = "ip"
		}
		if feed.ThreatCategory == "" {
			feed.ThreatCategory = "botnet_c2"
		}

		if err := h.pgDB.CreateTIFeed(r.Context(), &feed); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed creating feed: " + err.Error()})
			return
		}

		// Asynchronously trigger initial sync if enabled
		if feed.IsEnabled && h.tiEngine != nil {
			go func(feedID int) {
				_, _ = h.tiEngine.SyncFeed(r.Context(), feedID)
			}(feed.ID)
		}

		writeJSON(w, http.StatusCreated, map[string]any{"status": "created", "feed": feed})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleTIFeedDetail handles getting, updating, and deleting a single threat feed
func (h *Handler) handleTIFeedDetail(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /api/v1/ti/feeds/{id} or /api/v1/ti/feeds/{id}/sync
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(parts[4])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid feed id"})
		return
	}

	// Check if this is a sub-action like /sync
	if len(parts) >= 6 && parts[5] == "sync" {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if h.tiEngine == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "threat intel engine not ready"})
			return
		}
		count, err := h.tiEngine.SyncFeed(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "feed sync failed: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":              "success",
			"indicators_imported": count,
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		feed, err := h.pgDB.GetTIFeed(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "feed not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"feed": feed})

	case http.MethodPut:
		var feed models.TIFeed
		if err := json.NewDecoder(r.Body).Decode(&feed); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}
		feed.ID = id
		if err := h.pgDB.UpdateTIFeed(r.Context(), &feed); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed updating feed: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "feed": feed})

	case http.MethodDelete:
		if err := h.pgDB.DeleteTIFeed(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed deleting feed: " + err.Error()})
			return
		}
		if h.tiEngine != nil {
			_ = h.tiEngine.RebuildCache(r.Context())
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleTIFeedsSyncAll synchronizes all enabled threat feeds
func (h *Handler) handleTIFeedsSyncAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.tiEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "threat intel engine not ready"})
		return
	}

	results, err := h.tiEngine.SyncAllFeeds(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed syncing feeds: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"results": results,
	})
}

// handleTIIndicators handles querying and adding threat indicators
func (h *Handler) handleTIIndicators(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		feedID, _ := strconv.Atoi(q.Get("feed_id"))

		filter := postgres.IndicatorFilter{
			IndicatorType: q.Get("type"),
			Severity:      q.Get("severity"),
			Search:        q.Get("q"),
			FeedID:        feedID,
			Limit:         limit,
			Offset:        offset,
		}

		indicators, total, err := h.pgDB.ListTIIndicators(r.Context(), filter)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed listing indicators: " + err.Error()})
			return
		}
		if indicators == nil {
			indicators = []models.TIIndicator{}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"indicators": indicators,
			"total":      total,
			"limit":      filter.Limit,
			"offset":     filter.Offset,
		})

	case http.MethodPost:
		var ind models.TIIndicator
		if err := json.NewDecoder(r.Body).Decode(&ind); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}
		if strings.TrimSpace(ind.IndicatorValue) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "indicator_value is required"})
			return
		}
		if ind.IndicatorType == "" {
			ind.IndicatorType = "ip"
		}
		if ind.Severity == "" {
			ind.Severity = "high"
		}
		if ind.Confidence <= 0 {
			ind.Confidence = 85
		}
		if ind.Source == "" {
			ind.Source = "Manual Entry"
		}

		if err := h.pgDB.CreateTIIndicator(r.Context(), &ind); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed creating indicator: " + err.Error()})
			return
		}

		// Update in-memory matcher snapshot
		if h.tiEngine != nil {
			_ = h.tiEngine.RebuildCache(r.Context())
		}

		writeJSON(w, http.StatusCreated, map[string]any{"status": "created", "indicator": ind})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleTIIndicatorDetail handles deleting an individual threat indicator
func (h *Handler) handleTIIndicatorDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid indicator id"})
		return
	}

	if err := h.pgDB.DeleteTIIndicator(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed deleting indicator: " + err.Error()})
		return
	}

	if h.tiEngine != nil {
		_ = h.tiEngine.RebuildCache(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleTIMatches returns recent match audit records (tenant-scoped)
func (h *Handler) handleTIMatches(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantScope := h.tenantScope(r)
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	matches, total, err := h.pgDB.ListTIMatches(r.Context(), tenantScope, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed listing matches: " + err.Error()})
		return
	}
	if matches == nil {
		matches = []models.TIMatch{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"matches": matches,
		"total":   total,
	})
}

// handleTIStats returns executive KPIs and distribution metrics for Threat Intelligence
func (h *Handler) handleTIStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantScope := h.tenantScope(r)
	stats, err := h.pgDB.GetTIStats(r.Context(), tenantScope)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed getting stats: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// handleTISimulate triggers on-demand threat match simulation
func (h *Handler) handleTISimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IndicatorType  string `json:"indicator_type"`
		IndicatorValue string `json:"indicator_value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	if strings.TrimSpace(req.IndicatorValue) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "indicator_value is required"})
		return
	}
	if req.IndicatorType == "" {
		req.IndicatorType = "ip"
	}

	tenantScope := h.tenantScope(r)
	if tenantScope == "" || tenantScope == "all" || tenantScope == "*" {
		tenantScope = "default"
	}

	if h.tiEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "threat intel engine not ready"})
		return
	}

	match, err := h.tiEngine.SimulateMatch(r.Context(), tenantScope, req.IndicatorType, req.IndicatorValue)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "simulation failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "simulated",
		"match":   match,
		"message": "Threat indicator match successfully simulated and broadcast to SIEM & SOC Alert Bell",
	})
}
