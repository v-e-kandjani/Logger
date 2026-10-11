package api

import (
	"encoding/json"
	"net/http"

	"github.com/syslog-platform/logger/internal/governor"
)

// handleGovernorStatusAPI returns real-time cgroup v2 resource governor telemetry.
func (h *Handler) handleGovernorStatusAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	gov := governor.GetGovernor()
	status := gov.GetStatus()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, `{"error":"failed to serialize governor status"}`, http.StatusInternalServerError)
	}
}
