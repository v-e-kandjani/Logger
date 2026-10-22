package soar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
)

// Engine evaluates security alerts against SOAR playbooks and orchestrates automated response actions
type Engine struct {
	pgDB           *postgres.DB
	httpClient     *http.Client
	cooldowns      sync.Map // key: playbook_id:target_host -> time.Time
	activeExecs    sync.Map // key: exec_id -> *models.SOARPlaybookExecution
}

// NewEngine initializes the SOAR playbook execution engine
func NewEngine(pgDB *postgres.DB) *Engine {
	return &Engine{
		pgDB: pgDB,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// StartAlertListener attaches to a SIEM alert channel and evaluates arriving incidents
func (e *Engine) StartAlertListener(alertCh <-chan *models.SIEMAlert) {
	go func() {
		for alert := range alertCh {
			if alert != nil {
				e.EvaluateAlert(alert)
			}
		}
	}()
}

// EvaluateAlert checks a triggered SIEM alert against all active playbooks
func (e *Engine) EvaluateAlert(alert *models.SIEMAlert) {
	if alert == nil || e.pgDB == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	playbooks, err := e.pgDB.ListPlaybooks(ctx, alert.Tenant)
	if err != nil {
		log.Printf("[SOAR] Error loading playbooks for alert %s (tenant %s): %v", alert.ID, alert.Tenant, err)
		return
	}

	for _, pb := range playbooks {
		if !pb.IsEnabled {
			continue
		}

		if !e.matchesTrigger(pb, alert) {
			continue
		}

		// Find target endpoint agent matching this alert
		agent, _ := e.pgDB.FindAgentForAlert(ctx, alert.Tenant, alert.DeviceName, alert.SourceIP, alert.DestinationIP)
		targetHost := alert.DeviceName
		if targetHost == "" && agent != nil {
			targetHost = agent.Hostname
		}
		if targetHost == "" {
			targetHost = alert.SourceIP
		}

		// Check cooldown to avoid repetitive flapping or action storms
		cooldownKey := fmt.Sprintf("%s:%s", pb.ID.String(), targetHost)
		if pb.CooldownMinutes > 0 {
			if val, ok := e.cooldowns.Load(cooldownKey); ok {
				if lastFired, ok := val.(time.Time); ok {
					if time.Since(lastFired) < time.Duration(pb.CooldownMinutes)*time.Minute {
						log.Printf("[SOAR] Playbook '%s' skipped for host '%s' due to active %dm cooldown", pb.Name, targetHost, pb.CooldownMinutes)
						continue
					}
				}
			}
		}

		// Update cooldown timestamp
		e.cooldowns.Store(cooldownKey, time.Now().UTC())

		if pb.ExecutionMode == "autonomous" {
			log.Printf("[SOAR] Autonomous execution triggered: '%s' for alert '%s' on host '%s'", pb.Name, alert.RuleName, targetHost)
			go func(playbook *models.SOARPlaybook, al *models.SIEMAlert, ag *models.EndpointAgent, host string) {
				execCtx, execCancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer execCancel()
				_, _ = e.ExecutePlaybook(execCtx, playbook, al, ag, fmt.Sprintf("Autonomous Trigger: SIEM Alert (%s)", al.RuleName), "System (Autonomous)")
			}(pb, alert, agent, targetHost)
		} else {
			// Manual approval required
			log.Printf("[SOAR] Playbook '%s' requires manual analyst approval for alert '%s' on host '%s'", pb.Name, alert.RuleName, targetHost)
			go e.createPendingExecution(context.Background(), pb, alert, agent, targetHost)
		}
	}
}

func (e *Engine) matchesTrigger(pb *models.SOARPlaybook, alert *models.SIEMAlert) bool {
	tc := pb.TriggerConditions

	// 1. Min Risk Score
	if tc.MinRiskScore > 0 && alert.RiskScore < tc.MinRiskScore {
		return false
	}

	// 2. Severities
	if len(tc.Severities) > 0 {
		matched := false
		for _, s := range tc.Severities {
			if strings.EqualFold(s, alert.Severity) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 3. Rule IDs
	if len(tc.RuleIDs) > 0 {
		matched := false
		for _, r := range tc.RuleIDs {
			if strings.EqualFold(r, alert.RuleID) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 4. Categories
	if len(tc.Categories) > 0 {
		matched := false
		for _, c := range tc.Categories {
			if strings.EqualFold(c, alert.Category) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 5. MITRE Tactics
	if len(tc.MitreTactics) > 0 {
		matched := false
		for _, t := range tc.MitreTactics {
			if strings.Contains(strings.ToLower(alert.MitreTactic), strings.ToLower(t)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func (e *Engine) createPendingExecution(ctx context.Context, pb *models.SOARPlaybook, alert *models.SIEMAlert, agent *models.EndpointAgent, targetHost string) {
	exec := &models.SOARPlaybookExecution{
		ID:           uuid.New(),
		PlaybookID:   pb.ID,
		PlaybookName: pb.Name,
		AlertID:      &alert.ID,
		TenantSlug:   alert.Tenant,
		TriggeredBy:  fmt.Sprintf("SIEM Alert: %s (Severity: %s)", alert.RuleName, alert.Severity),
		TargetHost:   targetHost,
		Status:       "PENDING_APPROVAL",
		ExecutionLog: []models.SOARActionLog{
			{
				ActionType: "trigger_evaluated",
				Status:     "success",
				Message:    fmt.Sprintf("Playbook criteria matched. Awaiting analyst approval for %d mitigation action(s).", len(pb.Actions)),
				Timestamp:  time.Now().UTC(),
			},
		},
		CreatedAt: time.Now().UTC(),
	}
	if agent != nil {
		exec.TargetAgentID = &agent.ID
	}

	if err := e.pgDB.CreateExecution(ctx, exec); err != nil {
		log.Printf("[SOAR] Failed creating pending execution: %v", err)
		return
	}

	// Append note to alert
	_ = e.pgDB.AddSIEMIncidentNote(ctx, alert.ID, "SOAR-Engine",
		fmt.Sprintf("⚡ Playbook '%s' pending analyst approval for host '%s'.", pb.Name, targetHost))
}

// ExecutePlaybook executes the actions defined in a playbook
func (e *Engine) ExecutePlaybook(ctx context.Context, pb *models.SOARPlaybook, alert *models.SIEMAlert, agent *models.EndpointAgent, triggeredBy string, approvedBy string) (*models.SOARPlaybookExecution, error) {
	now := time.Now().UTC()
	exec := &models.SOARPlaybookExecution{
		ID:           uuid.New(),
		PlaybookID:   pb.ID,
		PlaybookName: pb.Name,
		TenantSlug:   pb.TenantSlug,
		TriggeredBy:  triggeredBy,
		ApprovedBy:   approvedBy,
		Status:       "RUNNING",
		CreatedAt:    now,
		ExecutionLog: []models.SOARActionLog{},
	}
	if alert != nil {
		exec.AlertID = &alert.ID
		if exec.TenantSlug == "" || exec.TenantSlug == "default" {
			exec.TenantSlug = alert.Tenant
		}
	}
	if agent != nil {
		exec.TargetAgentID = &agent.ID
		exec.TargetHost = agent.Hostname
	} else if alert != nil {
		exec.TargetHost = alert.DeviceName
		if exec.TargetHost == "" {
			exec.TargetHost = alert.SourceIP
		}
	}

	if approvedBy != "" && approvedBy != "System (Autonomous)" {
		exec.ApprovedAt = &now
	}

	if err := e.pgDB.CreateExecution(ctx, exec); err != nil {
		log.Printf("[SOAR] Failed initializing execution log: %v", err)
	}

	var hasFailure bool
	var lastErr string

	for i, action := range pb.Actions {
		actionStart := time.Now()
		logEntry := models.SOARActionLog{
			ActionType: action.Type,
			Timestamp:  actionStart,
			Details:    action.Parameters,
		}

		err := e.executeSingleAction(ctx, action, exec, agent, alert)
		logEntry.DurationMs = time.Since(actionStart).Milliseconds()

		if err != nil {
			logEntry.Status = "failed"
			logEntry.Message = fmt.Sprintf("Step %d failed: %v", i+1, err)
			hasFailure = true
			lastErr = err.Error()
			exec.ExecutionLog = append(exec.ExecutionLog, logEntry)
			log.Printf("[SOAR] Step %d (%s) failed in playbook '%s': %v", i+1, action.Type, pb.Name, err)
			break
		} else {
			logEntry.Status = "success"
			logEntry.Message = fmt.Sprintf("Step %d (%s) executed successfully.", i+1, action.Type)
			exec.ActionsExecuted++
			exec.ExecutionLog = append(exec.ExecutionLog, logEntry)
		}
	}

	compTime := time.Now().UTC()
	exec.CompletedAt = &compTime

	if hasFailure {
		exec.Status = "FAILED"
		exec.ErrorMsg = lastErr
	} else {
		exec.Status = "COMPLETED"
	}

	_ = e.pgDB.UpdateExecution(ctx, exec)
	_ = e.pgDB.RecordPlaybookExecutionStats(ctx, pb.ID)

	if alert != nil {
		noteMsg := fmt.Sprintf("🛡️ SOAR Playbook '%s' completed (%s) with %d action(s) executed.",
			pb.Name, exec.Status, exec.ActionsExecuted)
		_ = e.pgDB.AddSIEMIncidentNote(ctx, alert.ID, "SOAR-Engine", noteMsg)
	}

	return exec, nil
}

func (e *Engine) executeSingleAction(ctx context.Context, action models.SOARAction, exec *models.SOARPlaybookExecution, agent *models.EndpointAgent, alert *models.SIEMAlert) error {
	switch action.Type {
	case "isolate_host":
		if agent == nil {
			return fmt.Errorf("no connected endpoint agent found for host '%s'", exec.TargetHost)
		}
		reason := "Automated SOAR Playbook: " + exec.PlaybookName
		if r, ok := action.Parameters["reason"].(string); ok && r != "" {
			reason = r
		}
		payload := map[string]interface{}{
			"reason": reason,
		}
		_, err := e.pgDB.DispatchActiveResponseTask(ctx, agent.TenantSlug, agent.ID, "isolate_host", payload, "SOAR: "+exec.PlaybookName)
		return err

	case "unisolate_host":
		if agent == nil {
			return fmt.Errorf("no connected endpoint agent found for host '%s'", exec.TargetHost)
		}
		payload := map[string]interface{}{}
		_, err := e.pgDB.DispatchActiveResponseTask(ctx, agent.TenantSlug, agent.ID, "unisolate_host", payload, "SOAR: "+exec.PlaybookName)
		return err

	case "kill_process":
		if agent == nil {
			return fmt.Errorf("no connected endpoint agent found for host '%s'", exec.TargetHost)
		}
		payload := map[string]interface{}{}
		if pid, ok := action.Parameters["pid"]; ok {
			payload["pid"] = pid
		}
		if name, ok := action.Parameters["process_name"]; ok {
			payload["process_name"] = name
		}
		_, err := e.pgDB.DispatchActiveResponseTask(ctx, agent.TenantSlug, agent.ID, "process_kill", payload, "SOAR: "+exec.PlaybookName)
		return err

	case "file_quarantine":
		if agent == nil {
			return fmt.Errorf("no connected endpoint agent found for host '%s'", exec.TargetHost)
		}
		filePath, _ := action.Parameters["file_path"].(string)
		if filePath == "" {
			return fmt.Errorf("file_path parameter is required for file_quarantine")
		}
		payload := map[string]interface{}{
			"file_path": filePath,
		}
		_, err := e.pgDB.DispatchActiveResponseTask(ctx, agent.TenantSlug, agent.ID, "file_quarantine", payload, "SOAR: "+exec.PlaybookName)
		return err

	case "osquery_run":
		if agent == nil {
			return fmt.Errorf("no connected endpoint agent found for host '%s'", exec.TargetHost)
		}
		query, _ := action.Parameters["query"].(string)
		if query == "" {
			query = "SELECT * FROM listening_ports;"
		}
		payload := map[string]interface{}{
			"query":       query,
			"timeout_sec": 30,
		}
		_, err := e.pgDB.DispatchActiveResponseTask(ctx, agent.TenantSlug, agent.ID, "osquery_run", payload, "SOAR: "+exec.PlaybookName)
		return err

	case "webhook_notify":
		webhookURL, _ := action.Parameters["url"].(string)
		if webhookURL == "" {
			// No external webhook URL configured; treat as internal operational notification
			log.Printf("[SOAR] Webhook notification step executed internally for playbook '%s'", exec.PlaybookName)
			return nil
		}

		payloadBody := map[string]interface{}{
			"event":         "soar_playbook_execution",
			"playbook_name": exec.PlaybookName,
			"status":        exec.Status,
			"target_host":   exec.TargetHost,
			"timestamp":     time.Now().UTC().Format(time.RFC3339),
		}
		if alert != nil {
			payloadBody["alert_id"] = alert.ID
			payloadBody["rule_name"] = alert.RuleName
			payloadBody["severity"] = alert.Severity
			payloadBody["risk_score"] = alert.RiskScore
			payloadBody["summary"] = alert.Summary
		}

		bodyBytes, _ := json.Marshal(payloadBody)
		req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "LogSeal-SOAR/1.0")

		resp, err := e.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("webhook dispatch error: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("webhook responded with HTTP %d", resp.StatusCode)
		}
		return nil

	default:
		return fmt.Errorf("unrecognized action type '%s'", action.Type)
	}
}

// ApproveAndExecute approves a pending execution and dispatches its actions
func (e *Engine) ApproveAndExecute(ctx context.Context, tenantSlug string, execID uuid.UUID, approvedBy string) (*models.SOARPlaybookExecution, error) {
	exec, err := e.pgDB.GetExecutionByID(ctx, tenantSlug, execID)
	if err != nil {
		return nil, err
	}
	if exec == nil {
		return nil, fmt.Errorf("execution record not found")
	}
	if exec.Status != "PENDING_APPROVAL" {
		return nil, fmt.Errorf("execution status is '%s', not awaiting approval", exec.Status)
	}

	pb, err := e.pgDB.GetPlaybookByID(ctx, tenantSlug, exec.PlaybookID)
	if err != nil || pb == nil {
		return nil, fmt.Errorf("parent playbook not found: %v", err)
	}

	var alert *models.SIEMAlert
	if exec.AlertID != nil {
		alert, _, _ = e.pgDB.GetSIEMAlert(ctx, *exec.AlertID)
	}

	var agent *models.EndpointAgent
	if exec.TargetAgentID != nil {
		agent, _ = e.pgDB.GetAgentByID(ctx, *exec.TargetAgentID, tenantSlug)
	}

	now := time.Now().UTC()
	exec.ApprovedBy = approvedBy
	exec.ApprovedAt = &now
	exec.Status = "RUNNING"
	_ = e.pgDB.UpdateExecution(ctx, exec)

	go func() {
		execCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		var hasFailure bool
		var lastErr string

		for i, action := range pb.Actions {
			actionStart := time.Now()
			logEntry := models.SOARActionLog{
				ActionType: action.Type,
				Timestamp:  actionStart,
				Details:    action.Parameters,
			}

			err := e.executeSingleAction(execCtx, action, exec, agent, alert)
			logEntry.DurationMs = time.Since(actionStart).Milliseconds()

			if err != nil {
				logEntry.Status = "failed"
				logEntry.Message = fmt.Sprintf("Step %d failed: %v", i+1, err)
				hasFailure = true
				lastErr = err.Error()
				exec.ExecutionLog = append(exec.ExecutionLog, logEntry)
				break
			} else {
				logEntry.Status = "success"
				logEntry.Message = fmt.Sprintf("Step %d (%s) executed successfully.", i+1, action.Type)
				exec.ActionsExecuted++
				exec.ExecutionLog = append(exec.ExecutionLog, logEntry)
			}
		}

		compTime := time.Now().UTC()
		exec.CompletedAt = &compTime

		if hasFailure {
			exec.Status = "FAILED"
			exec.ErrorMsg = lastErr
		} else {
			exec.Status = "COMPLETED"
		}

		_ = e.pgDB.UpdateExecution(execCtx, exec)
		_ = e.pgDB.RecordPlaybookExecutionStats(execCtx, pb.ID)

		if alert != nil {
			noteMsg := fmt.Sprintf("🛡️ Analyst-approved SOAR Playbook '%s' completed (%s) by %s.",
				pb.Name, exec.Status, approvedBy)
			_ = e.pgDB.AddSIEMIncidentNote(execCtx, alert.ID, "SOAR-Engine", noteMsg)
		}
	}()

	return exec, nil
}

// RejectExecution marks a pending execution as REJECTED
func (e *Engine) RejectExecution(ctx context.Context, tenantSlug string, execID uuid.UUID, rejectedBy string) (*models.SOARPlaybookExecution, error) {
	exec, err := e.pgDB.GetExecutionByID(ctx, tenantSlug, execID)
	if err != nil {
		return nil, err
	}
	if exec == nil {
		return nil, fmt.Errorf("execution record not found")
	}
	if exec.Status != "PENDING_APPROVAL" {
		return nil, fmt.Errorf("execution status is '%s', not awaiting approval", exec.Status)
	}

	now := time.Now().UTC()
	exec.Status = "REJECTED"
	exec.ApprovedBy = rejectedBy
	exec.CompletedAt = &now
	exec.ExecutionLog = append(exec.ExecutionLog, models.SOARActionLog{
		ActionType: "approval_rejected",
		Status:     "skipped",
		Message:    fmt.Sprintf("Execution rejected by analyst %s", rejectedBy),
		Timestamp:  now,
	})

	if err := e.pgDB.UpdateExecution(ctx, exec); err != nil {
		return nil, err
	}

	if exec.AlertID != nil {
		_ = e.pgDB.AddSIEMIncidentNote(ctx, *exec.AlertID, "SOAR-Engine",
			fmt.Sprintf("❌ SOAR Playbook '%s' execution rejected by %s.", exec.PlaybookName, rejectedBy))
	}

	return exec, nil
}
