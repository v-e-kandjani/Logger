package api

import (
	"encoding/json"
	"net/http"

	"github.com/syslog-platform/logger/internal/cache"
	"github.com/syslog-platform/logger/internal/governor"
)

// handleGovernorStatusAPI returns real-time cgroup v2 resource governor telemetry and operator views.
func (h *Handler) handleGovernorStatusAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	gov := governor.GetGovernor()
	status := gov.GetStatus()

	// Live Pipeline Ingestion Telemetry
	if h.pipeline != nil {
		qDepth := h.pipeline.QueueDepth()
		status.OperatorView.QueueLossCount = h.pipeline.DroppedPackets.Load()
		if qDepth > 0 {
			rem := 250000 - qDepth
			if rem < 0 {
				rem = 0
			}
			runway := rem / 2000
			if runway < 5 {
				runway = 5
			}
			status.OperatorView.QueueRunwaySec = runway
		} else {
			status.OperatorView.QueueRunwaySec = 125
		}
	}

	// Live Cache Stats
	cStats := cache.GetResultCache().Stats()
	status.OperatorView.CacheHitRatio = cStats.HitRatioPercent
	status.OperatorView.CacheMemoryMB = cStats.CurrentMemoryMB
	status.OperatorView.CacheItems = cStats.ItemCount

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, `{"error":"failed to serialize governor status"}`, http.StatusInternalServerError)
	}
}
