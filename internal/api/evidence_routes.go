package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/syslog-platform/logger/internal/models"
)

// handleManualArchiveAPI enqueues and triggers a manual evidence archive for a selected period.
// POST /api/v1/archives/manual
func (h *Handler) handleManualArchiveAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		From      string `json:"from"`       // RFC3339 or "2006-01-02T15:04"
		To        string `json:"to"`         // RFC3339 or "2006-01-02T15:04"
		TimeBasis string `json:"time_basis"` // "receipt_time" or "event_time"
		Reason    string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json request payload"}`, http.StatusBadRequest)
		return
	}

	if req.From == "" || req.To == "" {
		http.Error(w, `{"error":"from and to timestamps are required"}`, http.StatusBadRequest)
		return
	}

	fromTime, err := parseFlexibleTime(req.From)
	if err != nil {
		http.Error(w, `{"error":"invalid from timestamp format"}`, http.StatusBadRequest)
		return
	}

	toTime, err := parseFlexibleTime(req.To)
	if err != nil {
		http.Error(w, `{"error":"invalid to timestamp format"}`, http.StatusBadRequest)
		return
	}

	if !toTime.After(fromTime) {
		http.Error(w, `{"error":"to timestamp must be strictly after from timestamp"}`, http.StatusBadRequest)
		return
	}

	timeBasis := req.TimeBasis
	if timeBasis == "" {
		timeBasis = "receipt_time"
	}

	tenant := h.tenantScope(r)
	if tenant == "" {
		tenant = "default"
	}

	operator := "system"
	if s, ok := h.getSession(r); ok && s.Username != "" {
		operator = s.Username
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		idempotencyKey = fmt.Sprintf("manual_%s_%d_%d", tenant, fromTime.Unix(), toTime.Unix())
	}

	job := &models.ArchiveJob{
		TenantSlug:     tenant,
		RequestType:    "MANUAL_PERIOD",
		PeriodStart:    fromTime,
		PeriodEnd:      toTime,
		TimeBasis:      timeBasis,
		IdempotencyKey: idempotencyKey,
		Requester:      operator,
		Reason:         req.Reason,
		State:          "QUEUED",
	}

	ctx := r.Context()
	if err := h.pgDB.CreateArchiveJob(ctx, job); err != nil {
		http.Error(w, `{"error":"failed to create archive job: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Asynchronously execute deterministic evidence sealing
	if h.evidenceSealer != nil {
		go func(j *models.ArchiveJob) {
			_, _ = h.evidenceSealer.ProcessJob(context.Background(), j)
		}(job)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":          job.ID,
		"status":          job.State,
		"idempotency_key": job.IdempotencyKey,
		"message":         "Manual evidence archive job enqueued and sealing initiated",
	})
}

// handleListArchiveJobsAPI lists asynchronous evidence sealing jobs and their states.
// GET /api/v1/archives/jobs
func (h *Handler) handleListArchiveJobsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	jobs, err := h.pgDB.ListArchiveJobs(r.Context(), tenant, 50)
	if err != nil {
		http.Error(w, `{"error":"failed to list archive jobs: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jobs":  jobs,
		"total": len(jobs),
	})
}
