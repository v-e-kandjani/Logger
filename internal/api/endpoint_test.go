package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/syslog-platform/logger/internal/models"
)

func TestAgentEnrollValidation(t *testing.T) {
	h := &Handler{}

	t.Run("MissingToken", func(t *testing.T) {
		reqBody, _ := json.Marshal(models.AgentEnrollRequest{
			AgentUUID: "test-uuid-123",
			Hostname:  "test-host",
		})
		r := httptest.NewRequest(http.MethodPost, "/api/agent/v1/enroll", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()

		h.handleAgentEnroll(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 for missing token, got %d", w.Code)
		}
	})

	t.Run("MissingAgentUUID", func(t *testing.T) {
		reqBody, _ := json.Marshal(models.AgentEnrollRequest{
			EnrollmentToken: "lp_ea_testtoken123",
			Hostname:        "test-host",
		})
		r := httptest.NewRequest(http.MethodPost, "/api/agent/v1/enroll", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()

		h.handleAgentEnroll(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 for missing agent_uuid, got %d", w.Code)
		}
	})

	t.Run("HeartbeatMissingUUID", func(t *testing.T) {
		reqBody, _ := json.Marshal(models.AgentHeartbeatRequest{
			Hostname: "test-host",
		})
		r := httptest.NewRequest(http.MethodPost, "/api/agent/v1/heartbeat", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()

		h.handleAgentHeartbeat(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 for missing agent_uuid in heartbeat, got %d", w.Code)
		}
	})

	t.Run("AgentConfigEndpoint", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/api/agent/v1/config", nil)
		w := httptest.NewRecorder()

		h.handleAgentConfig(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200 for config endpoint, got %d", w.Code)
		}

		var cfg models.EndpointPolicyConfig
		if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
			t.Fatalf("failed to decode policy config: %v", err)
		}
		if cfg.HeartbeatIntervalSec <= 0 {
			t.Errorf("expected valid heartbeat interval, got %d", cfg.HeartbeatIntervalSec)
		}
	})
}
