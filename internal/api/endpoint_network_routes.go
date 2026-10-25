package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// handleEndpointAgentNetwork handles network connection and DNS query telemetry from native agents (Phase O)
func (h *Handler) handleEndpointAgentNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentNetworkSubmission
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	agentUUID := req.AgentUUID
	if agentUUID == "" {
		agentUUID = r.Header.Get("X-Agent-UUID")
	}
	if agentUUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_uuid is required"})
		return
	}

	// Resolve agent
	agentID, tenantSlug, hostname, ipAddress, _, err := h.pgDB.ResolveAgentByUUID(r.Context(), agentUUID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent not found or unenrolled"})
		return
	}

	now := time.Now().UTC()

	// 1. Process Connections
	for i := range req.Connections {
		req.Connections[i].AgentID = agentID
		req.Connections[i].TenantSlug = tenantSlug
		req.Connections[i].AgentHostname = hostname
		req.Connections[i].AgentIP = ipAddress
		if req.Connections[i].Timestamp.IsZero() {
			req.Connections[i].Timestamp = now
		}
		if req.Connections[i].CreatedAt.IsZero() {
			req.Connections[i].CreatedAt = now
		}
	}

	if len(req.Connections) > 0 {
		if err := h.pgDB.RecordNetworkConnections(r.Context(), req.Connections); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "recording connections: " + err.Error()})
			return
		}

		// SIEM correlation for suspicious network flows / C2 beaconing
		if h.siemEngine != nil {
			for _, c := range req.Connections {
				sevUpper := strings.ToUpper(c.ThreatSeverity)
				if sevUpper == "HIGH" || sevUpper == "CRITICAL" {
					riskScore := 80
					if sevUpper == "CRITICAL" {
						riskScore = 95
					}

					alert := &models.SIEMAlert{
						ID:             uuid.New(),
						RuleID:         "EDR-NET-THREAT",
						RuleName:       fmt.Sprintf("EDR Network Threat: %s on %s", c.ThreatReason, hostname),
						Severity:       sevUpper,
						Tenant:         tenantSlug,
						DeviceName:     hostname,
						SourceIP:       ipAddress,
						Category:       "endpoint_network",
						EventCount:     1,
						FirstSeen:      c.Timestamp,
						LastSeen:       c.Timestamp,
						Status:         "NEW",
						MitreTactic:    "Command and Control",
						MitreTechnique: "T1071.001",
						RiskScore:      riskScore,
						Summary:        fmt.Sprintf("Host '%s': %s (PID: %d, Process: %s, Destination: %s:%d, Protocol: %s, Action: %s)", hostname, c.ThreatReason, c.PID, c.ProcessName, c.RemoteIP, c.RemotePort, c.Protocol, c.ActionTaken),
						CreatedAt:      c.Timestamp,
					}
					h.siemEngine.DispatchDirectAlert(alert)
				}
			}
		}

		// Cross-match connections against Threat Intelligence (Phase Q)
		if h.tiEngine != nil {
			for _, c := range req.Connections {
				h.tiEngine.ProcessNetworkFlowMatch(r.Context(), tenantSlug, agentUUID, hostname, ipAddress, c.RemoteIP, "")
			}
		}
	}

	// 2. Process DNS Queries
	for i := range req.DNSQueries {
		req.DNSQueries[i].AgentID = agentID
		req.DNSQueries[i].TenantSlug = tenantSlug
		req.DNSQueries[i].AgentHostname = hostname
		req.DNSQueries[i].AgentIP = ipAddress
		if req.DNSQueries[i].Timestamp.IsZero() {
			req.DNSQueries[i].Timestamp = now
		}
		if req.DNSQueries[i].CreatedAt.IsZero() {
			req.DNSQueries[i].CreatedAt = now
		}
	}

	if len(req.DNSQueries) > 0 {
		if err := h.pgDB.RecordDNSQueries(r.Context(), req.DNSQueries); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "recording dns queries: " + err.Error()})
			return
		}

		// SIEM correlation for DGA / Malicious DNS requests
		if h.siemEngine != nil {
			for _, q := range req.DNSQueries {
				if q.IsDGA || q.IsMalicious {
					alert := &models.SIEMAlert{
						ID:             uuid.New(),
						RuleID:         "EDR-DGA-DNS",
						RuleName:       fmt.Sprintf("DGA / Exfiltration DNS Query on %s: %s", hostname, q.QueryDomain),
						Severity:       "HIGH",
						Tenant:         tenantSlug,
						DeviceName:     hostname,
						SourceIP:       ipAddress,
						Category:       "endpoint_dns",
						EventCount:     1,
						FirstSeen:      q.Timestamp,
						LastSeen:       q.Timestamp,
						Status:         "NEW",
						MitreTactic:    "Command and Control",
						MitreTechnique: "T1568.002",
						RiskScore:      85,
						Summary:        fmt.Sprintf("Host '%s': Suspicious DNS query for '%s' (Shannon entropy: %.2f, Reason: %s, Action: %s)", hostname, q.QueryDomain, q.EntropyScore, q.ThreatReason, q.ActionTaken),
						CreatedAt:      q.Timestamp,
					}
					h.siemEngine.DispatchDirectAlert(alert)
				}
			}
		}

		// Cross-match DNS queries against Threat Intelligence (Phase Q)
		if h.tiEngine != nil {
			for _, q := range req.DNSQueries {
				h.tiEngine.ProcessNetworkFlowMatch(r.Context(), tenantSlug, agentUUID, hostname, ipAddress, "", q.QueryDomain)
			}
		}
	}

	// 3. Return active firewall rules to enforce
	rules, _ := h.pgDB.ListFirewallRules(r.Context(), tenantSlug, &agentID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":              "success",
		"connections_count":   len(req.Connections),
		"dns_queries_count":   len(req.DNSQueries),
		"enforced_rules_count": len(rules),
		"rules":               rules,
	})
}

// handleEndpointNetworkConnections returns filtered active network sockets
func (h *Handler) handleEndpointNetworkConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	q := r.URL.Query()

	var agentID *uuid.UUID
	if aidStr := strings.TrimSpace(q.Get("agent_id")); aidStr != "" {
		if id, err := uuid.Parse(aidStr); err == nil {
			agentID = &id
		}
	}

	severity := strings.TrimSpace(q.Get("severity"))
	search := strings.TrimSpace(q.Get("search"))

	limit := 100
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	list, total, err := h.pgDB.ListNetworkConnections(r.Context(), tenant, agentID, severity, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetching network connections: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"connections": list,
		"total":       total,
		"limit":       limit,
		"offset":      offset,
	})
}

// handleEndpointNetworkDNS returns filtered DNS query logs
func (h *Handler) handleEndpointNetworkDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	q := r.URL.Query()

	var agentID *uuid.UUID
	if aidStr := strings.TrimSpace(q.Get("agent_id")); aidStr != "" {
		if id, err := uuid.Parse(aidStr); err == nil {
			agentID = &id
		}
	}

	dgaOnly := q.Get("dga_only") == "true"
	search := strings.TrimSpace(q.Get("search"))

	limit := 100
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	list, total, err := h.pgDB.ListDNSQueries(r.Context(), tenant, agentID, dgaOnly, search, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetching dns queries: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"queries": list,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// handleEndpointNetworkStats returns summary metrics for Phase O Network & DNS EDR
func (h *Handler) handleEndpointNetworkStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	stats, err := h.pgDB.GetEDRNetworkStats(r.Context(), tenant)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetching network stats: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// handleEndpointNetworkFirewallRules lists or creates micro-isolation firewall rules
func (h *Handler) handleEndpointNetworkFirewallRules(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)

	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		var agentID *uuid.UUID
		if aidStr := strings.TrimSpace(q.Get("agent_id")); aidStr != "" {
			if id, err := uuid.Parse(aidStr); err == nil {
				agentID = &id
			}
		}

		rules, err := h.pgDB.ListFirewallRules(r.Context(), tenant, agentID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetching firewall rules: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"rules": rules,
			"total": len(rules),
		})

	case http.MethodPost:
		var rule models.EndpointFirewallRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}

		if rule.RemoteIP == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "remote_ip is required"})
			return
		}

		if tenant != "" && tenant != "all" {
			rule.TenantSlug = tenant
		}
		if rule.TenantSlug == "" {
			rule.TenantSlug = "default"
		}
		if rule.RuleName == "" {
			rule.RuleName = fmt.Sprintf("Block-%s", rule.RemoteIP)
		}
		if rule.Direction == "" {
			rule.Direction = "outbound"
		}
		if rule.Action == "" {
			rule.Action = "block"
		}
		username := "admin"
		if session, ok := h.getSession(r); ok && session != nil && session.Username != "" {
			username = session.Username
		}
		rule.IsEnabled = true
		rule.CreatedBy = username

		if err := h.pgDB.CreateFirewallRule(r.Context(), &rule); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "creating firewall rule: " + err.Error()})
			return
		}

		h.recordAudit(r, "CREATE", "endpoint_firewall_rule", "SUCCESS", map[string]interface{}{
			"rule_name": rule.RuleName,
			"remote_ip": rule.RemoteIP,
			"reason":    rule.Reason,
		})

		writeJSON(w, http.StatusCreated, rule)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleEndpointNetworkFirewallRuleDelete deletes a firewall block rule by ID
func (h *Handler) handleEndpointNetworkFirewallRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing rule id"})
		return
	}
	ruleIDStr := parts[len(parts)-1]
	ruleID, err := uuid.Parse(ruleIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rule id uuid"})
		return
	}

	tenant := h.tenantScope(r)
	if err := h.pgDB.DeleteFirewallRule(r.Context(), tenant, ruleID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "deleting firewall rule: " + err.Error()})
		return
	}

	h.recordAudit(r, "DELETE", "endpoint_firewall_rule", "SUCCESS", map[string]interface{}{
		"rule_id": ruleID.String(),
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleEndpointNetworkFirewallBlock handles quick 1-click IP isolation / blocking
func (h *Handler) handleEndpointNetworkFirewallBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	var req struct {
		AgentID  *uuid.UUID `json:"agent_id,omitempty"`
		RemoteIP string     `json:"remote_ip"`
		Reason   string     `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	req.RemoteIP = strings.TrimSpace(req.RemoteIP)
	if req.RemoteIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "remote_ip is required"})
		return
	}

	if req.Reason == "" {
		req.Reason = "Host containment via Network EDR"
	}

	username := "admin"
	if session, ok := h.getSession(r); ok && session != nil && session.Username != "" {
		username = session.Username
	}

	rule := models.EndpointFirewallRule{
		ID:         uuid.New(),
		TenantSlug: tenant,
		AgentID:    req.AgentID,
		RuleName:   fmt.Sprintf("Isolation-Block-%s", req.RemoteIP),
		Direction:  "both",
		Action:     "block",
		Protocol:   "any",
		RemoteIP:   req.RemoteIP,
		RemotePort: "any",
		IsEnabled:  true,
		Reason:     req.Reason,
		CreatedBy:  username,
	}
	if rule.TenantSlug == "" || rule.TenantSlug == "all" {
		rule.TenantSlug = "default"
	}

	if err := h.pgDB.CreateFirewallRule(r.Context(), &rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "creating block rule: " + err.Error()})
		return
	}

	h.recordAudit(r, "BLOCK_IP", "endpoint_host_firewall", "SUCCESS", map[string]interface{}{
		"remote_ip": req.RemoteIP,
		"reason":    req.Reason,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Firewall isolation rule enforced for %s", req.RemoteIP),
		"rule":    rule,
	})
}

// handleEndpointNetworkSimulate simulates a C2 beaconing socket flow or DGA DNS query for validation
func (h *Handler) handleEndpointNetworkSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	if tenant == "" || tenant == "all" {
		tenant = "default"
	}

	var req struct {
		Type        string `json:"type"` // "c2_beacon", "dga_dns", "suspicious_port"
		AgentID     string `json:"agent_id"`
		Hostname    string `json:"hostname"`
		ProcessName string `json:"process_name"`
		RemoteIP    string `json:"remote_ip"`
		RemotePort  int    `json:"remote_port"`
		Domain      string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	var agentUUID uuid.UUID
	if req.AgentID != "" {
		agentUUID, _ = uuid.Parse(req.AgentID)
	}
	if agentUUID == uuid.Nil {
		// Find an active agent in tenant
		agents, _, _ := h.pgDB.ListAgents(r.Context(), tenant, "", "", "", 1, 0)
		if len(agents) > 0 {
			agentUUID = agents[0].ID
			if req.Hostname == "" {
				req.Hostname = agents[0].Hostname
			}
		} else {
			agentUUID = uuid.New()
			if req.Hostname == "" {
				req.Hostname = "simulated-workstation"
			}
		}
	}

	now := time.Now().UTC()

	switch req.Type {
	case "dga_dns":
		domain := req.Domain
		if domain == "" {
			domain = "x9k2m8q4v1z7p3j6.biz"
		}
		q := models.EndpointDNSQuery{
			ID:            uuid.New(),
			TenantSlug:    tenant,
			AgentID:       agentUUID,
			AgentHostname: req.Hostname,
			AgentIP:       "10.0.0.99",
			PID:           4182,
			ProcessName:   "powershell.exe",
			QueryDomain:   domain,
			QueryType:     "A",
			ResponseCode:  "NOERROR",
			ResolvedIPs:   []string{"198.51.100.88"},
			EntropyScore:  3.92,
			IsDGA:         true,
			IsMalicious:   true,
			ThreatReason:  "Algorithmic DGA domain characteristics detected (Shannon entropy: 3.92)",
			ActionTaken:   "blocked",
			Timestamp:     now,
			CreatedAt:     now,
		}
		_ = h.pgDB.RecordDNSQueries(r.Context(), []models.EndpointDNSQuery{q})

		if h.siemEngine != nil {
			h.siemEngine.DispatchDirectAlert(&models.SIEMAlert{
				ID:             uuid.New(),
				RuleID:         "EDR-DGA-DNS-SIM",
				RuleName:       fmt.Sprintf("DGA / Exfiltration DNS Query on %s: %s", req.Hostname, domain),
				Severity:       "HIGH",
				Tenant:         tenant,
				DeviceName:     req.Hostname,
				SourceIP:       "10.0.0.99",
				Category:       "endpoint_dns",
				EventCount:     1,
				FirstSeen:      now,
				LastSeen:       now,
				Status:         "NEW",
				MitreTactic:    "Command and Control",
				MitreTechnique: "T1568.002",
				RiskScore:      85,
				Summary:        fmt.Sprintf("SIMULATION: DGA DNS resolution query for '%s' detected on host '%s'", domain, req.Hostname),
				CreatedAt:      now,
			})
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "success",
			"message": "DGA DNS exfiltration simulation generated and alerted in SIEM",
			"query":   q,
		})

	case "suspicious_port":
		remotePort := req.RemotePort
		if remotePort == 0 {
			remotePort = 4444
		}
		remoteIP := req.RemoteIP
		if remoteIP == "" {
			remoteIP = "198.51.100.44"
		}
		procName := req.ProcessName
		if procName == "" {
			procName = "powershell.exe"
		}

		conn := models.EndpointNetworkConnection{
			ID:             uuid.New(),
			TenantSlug:     tenant,
			AgentID:        agentUUID,
			AgentHostname:  req.Hostname,
			AgentIP:        "10.0.0.99",
			PID:            3891,
			ProcessName:    procName,
			Protocol:       "tcp",
			LocalIP:        "10.0.0.99",
			LocalPort:      52140,
			RemoteIP:       remoteIP,
			RemotePort:     remotePort,
			State:          "ESTABLISHED",
			Direction:      "outbound",
			ThreatSeverity: "critical",
			ThreatReason:   fmt.Sprintf("Outbound connection to prohibited / suspicious C2 port %d", remotePort),
			ActionTaken:    "blocked",
			Timestamp:      now,
			CreatedAt:      now,
		}
		_ = h.pgDB.RecordNetworkConnections(r.Context(), []models.EndpointNetworkConnection{conn})

		if h.siemEngine != nil {
			h.siemEngine.DispatchDirectAlert(&models.SIEMAlert{
				ID:             uuid.New(),
				RuleID:         "EDR-SUSPICIOUS-PORT-SIM",
				RuleName:       fmt.Sprintf("EDR Network Threat: Suspicious Port %d on %s", remotePort, req.Hostname),
				Severity:       "CRITICAL",
				Tenant:         tenant,
				DeviceName:     req.Hostname,
				SourceIP:       "10.0.0.99",
				Category:       "endpoint_network",
				EventCount:     1,
				FirstSeen:      now,
				LastSeen:       now,
				Status:         "NEW",
				MitreTactic:    "Command and Control",
				MitreTechnique: "T1071.001",
				RiskScore:      95,
				Summary:        fmt.Sprintf("SIMULATION: Reverse shell socket connected to %s:%d by %s", remoteIP, remotePort, procName),
				CreatedAt:      now,
			})
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":     "success",
			"message":    fmt.Sprintf("Suspicious port %d connection simulation generated and alerted in SIEM", remotePort),
			"connection": conn,
		})

	default: // c2_beacon
		remoteIP := req.RemoteIP
		if remoteIP == "" {
			remoteIP = "203.0.113.88"
		}
		remotePort := req.RemotePort
		if remotePort == 0 {
			remotePort = 8443
		}
		procName := req.ProcessName
		if procName == "" {
			procName = "rundll32.exe"
		}

		conn := models.EndpointNetworkConnection{
			ID:             uuid.New(),
			TenantSlug:     tenant,
			AgentID:        agentUUID,
			AgentHostname:  req.Hostname,
			AgentIP:        "10.0.0.99",
			PID:            5812,
			ProcessName:    procName,
			Protocol:       "tcp",
			LocalIP:        "10.0.0.99",
			LocalPort:      53980,
			RemoteIP:       remoteIP,
			RemotePort:     remotePort,
			State:          "ESTABLISHED",
			Direction:      "outbound",
			ThreatSeverity: "critical",
			ThreatReason:   fmt.Sprintf("Periodic C2 Beaconing pattern detected to %s:%d (avg interval: 15.0s, jitter variance: 0.85s)", remoteIP, remotePort),
			ActionTaken:    "blocked",
			Timestamp:      now,
			CreatedAt:      now,
		}
		_ = h.pgDB.RecordNetworkConnections(r.Context(), []models.EndpointNetworkConnection{conn})

		if h.siemEngine != nil {
			h.siemEngine.DispatchDirectAlert(&models.SIEMAlert{
				ID:             uuid.New(),
				RuleID:         "EDR-C2-BEACON-SIM",
				RuleName:       fmt.Sprintf("EDR Threat: Periodic C2 Beaconing on %s to %s", req.Hostname, remoteIP),
				Severity:       "CRITICAL",
				Tenant:         tenant,
				DeviceName:     req.Hostname,
				SourceIP:       "10.0.0.99",
				Category:       "endpoint_network",
				EventCount:     1,
				FirstSeen:      now,
				LastSeen:       now,
				Status:         "NEW",
				MitreTactic:    "Command and Control",
				MitreTechnique: "T1071.001",
				RiskScore:      95,
				Summary:        fmt.Sprintf("SIMULATION: Process %s established regular C2 beaconing heartbeats to %s:%d", procName, remoteIP, remotePort),
				CreatedAt:      now,
			})
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":     "success",
			"message":    fmt.Sprintf("C2 beaconing simulation to %s generated and alerted in SIEM", remoteIP),
			"connection": conn,
		})
	}
}
