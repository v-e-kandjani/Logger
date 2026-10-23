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

// handleEndpointAgentUSB processes connected USB telemetry and DLP violation events submitted by native agents
func (h *Handler) handleEndpointAgentUSB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AgentUSBSubmission
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

	// Resolve agent from PostgreSQL
	agentID, tenantSlug, hostname, ipAddress, _, err := h.pgDB.ResolveAgentByUUID(r.Context(), agentUUID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent not found or unenrolled"})
		return
	}

	// Enrich devices
	for i := range req.Devices {
		req.Devices[i].AgentID = agentID
		req.Devices[i].TenantSlug = tenantSlug
		req.Devices[i].AgentHostname = hostname
		req.Devices[i].AgentIP = ipAddress
	}

	// Enrich events
	for i := range req.Events {
		req.Events[i].AgentID = agentID
		req.Events[i].TenantSlug = tenantSlug
		req.Events[i].AgentHostname = hostname
		req.Events[i].AgentIP = ipAddress
		if req.Events[i].CreatedAt.IsZero() {
			req.Events[i].CreatedAt = time.Now().UTC()
		}
	}

	// 1. Upsert devices in PostgreSQL
	if len(req.Devices) > 0 {
		if err := h.pgDB.UpsertAgentUSBDevices(r.Context(), tenantSlug, agentID, req.Devices); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upserting usb devices: " + err.Error()})
			return
		}
	}

	// 2. Record audit events
	if len(req.Events) > 0 {
		if err := h.pgDB.RecordUSBEvents(r.Context(), tenantSlug, agentID, req.Events); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "recording usb events: " + err.Error()})
			return
		}

		// 3. Correlate DLP Violations directly into SIEM & SOAR Engine
		if h.siemEngine != nil {
			for _, ev := range req.Events {
				if ev.EventType == "blocked" || ev.EventType == "unauthorized_whitelist" || ev.EventType == "write_denied" {
					alertID := uuid.New()
					alert := &models.SIEMAlert{
						ID:             alertID,
						RuleID:         "DLP-USB-VIOLATION",
						RuleName:       fmt.Sprintf("USB DLP Violation: %s on %s", strings.ToUpper(ev.EventType), hostname),
						Severity:       "HIGH",
						Tenant:         tenantSlug,
						DeviceName:     hostname,
						SourceIP:       ipAddress,
						Category:       "endpoint_dlp",
						EventCount:     1,
						FirstSeen:      ev.CreatedAt,
						LastSeen:       ev.CreatedAt,
						Status:         "NEW",
						MitreTactic:    "Exfiltration",
						MitreTechnique: ev.MitreTechnique,
						RiskScore:      85,
						Summary:        fmt.Sprintf("Host '%s' reported DLP policy violation: %s (VID: %s, PID: %s, Serial: %s, Action: %s)", hostname, ev.Details, ev.VendorID, ev.ProductID, ev.SerialNumber, ev.ActionTaken),
						CreatedAt:      ev.CreatedAt,
					}
					h.siemEngine.DispatchDirectAlert(alert)
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"devices": len(req.Devices),
		"events":  len(req.Events),
	})
}

// handleEndpointUSBDevices lists connected and historical USB devices for an analyst or operator
func (h *Handler) handleEndpointUSBDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	q := r.URL.Query()

	var agentID *uuid.UUID
	if aID := strings.TrimSpace(q.Get("agent_id")); aID != "" {
		if parsed, err := uuid.Parse(aID); err == nil {
			agentID = &parsed
		}
	}

	connectedOnly := q.Get("connected_only") == "true"
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	devices, total, err := h.pgDB.ListUSBDevices(r.Context(), tenant, agentID, connectedOnly, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"devices": devices,
		"total":   total,
	})
}

// handleEndpointUSBEvents lists historical DLP events
func (h *Handler) handleEndpointUSBEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	q := r.URL.Query()

	var agentID *uuid.UUID
	if aID := strings.TrimSpace(q.Get("agent_id")); aID != "" {
		if parsed, err := uuid.Parse(aID); err == nil {
			agentID = &parsed
		}
	}

	eventType := strings.TrimSpace(q.Get("event_type"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	events, total, err := h.pgDB.ListUSBEvents(r.Context(), tenant, agentID, eventType, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"events": events,
		"total":  total,
	})
}

// handleEndpointUSBWhitelist handles GET and POST for approved USB hardware
func (h *Handler) handleEndpointUSBWhitelist(w http.ResponseWriter, r *http.Request) {
	tenant := h.tenantScope(r)

	switch r.Method {
	case http.MethodGet:
		list, err := h.pgDB.ListUSBWhitelist(r.Context(), tenant)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":    "ok",
			"whitelist": list,
		})

	case http.MethodPost:
		var entry models.EndpointUSBWhitelistEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}

		if entry.TenantSlug == "" {
			entry.TenantSlug = tenant
			if entry.TenantSlug == "" || entry.TenantSlug == "all" {
				entry.TenantSlug = "default"
			}
		}

		user := "admin"
		if session, ok := h.getSession(r); ok && session.Username != "" {
			user = session.Username
		}
		entry.ApprovedBy = user

		created, err := h.pgDB.AddUSBWhitelistEntry(r.Context(), &entry)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		h.recordAudit(r, "USB_WHITELIST_ADD", "endpoint/usb/whitelist", "SUCCESS", map[string]interface{}{
			"entry_id": created.ID,
			"vid":      created.VendorID,
			"pid":      created.ProductID,
			"serial":   created.SerialNumber,
			"name":     created.Name,
		})

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "success",
			"entry":  created,
		})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleEndpointUSBWhitelistDelete handles DELETE /api/v1/endpoint/usb/whitelist/{id}
func (h *Handler) handleEndpointUSBWhitelistDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var idStr string
	if len(parts) >= 5 {
		idStr = parts[4]
	} else {
		idStr = r.URL.Query().Get("id")
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid uuid"})
		return
	}

	if err := h.pgDB.DeleteUSBWhitelistEntry(r.Context(), tenant, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.recordAudit(r, "USB_WHITELIST_DELETE", "endpoint/usb/whitelist", "SUCCESS", map[string]interface{}{
		"entry_id": id,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "USB whitelist entry deleted successfully",
	})
}

// handleEndpointUSBStats returns aggregate statistics for DLP dashboard telemetry
func (h *Handler) handleEndpointUSBStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	totalDevs, connDevs, blockedEvts, totalEvts, err := h.pgDB.GetUSBStats(r.Context(), tenant)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "ok",
		"total_devices":     totalDevs,
		"connected_devices": connDevs,
		"blocked_events":    blockedEvts,
		"total_events":      totalEvts,
	})
}

// handleEndpointUSBSimulate creates a simulated USB event to validate dashboard alerts and UI rendering
func (h *Handler) handleEndpointUSBSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tenant := h.tenantScope(r)
	if tenant == "" || tenant == "all" {
		tenant = "default"
	}

	// Find the most recent active agent for this tenant
	agents, _, err := h.pgDB.ListAgents(r.Context(), tenant, "", "", "", 1, 0)
	if err != nil || len(agents) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no active agent found to simulate USB event"})
		return
	}

	agent := agents[0]
	now := time.Now().UTC()
	dev := models.EndpointUSBDevice{
		AgentID:       agent.ID,
		TenantSlug:    agent.TenantSlug,
		AgentHostname: agent.Hostname,
		AgentIP:       agent.IPAddress,
		DeviceID:      "USB\\VID_0781&PID_5567\\SANDISK_TEST",
		VendorID:      "0781",
		ProductID:     "5567",
		SerialNumber:  "4C530001050805117450",
		VendorName:    "SanDisk Corp.",
		ProductName:   "Cruzer Blade USB Flash Drive",
		DriveLetter:   "E:",
		MountPoint:    "E:",
		CapacityBytes: 32212254720, // 32 GB
		FileSystem:    "FAT32",
		IsConnected:   true,
		IsBlocked:     false,
		IsReadOnly:    false,
		FirstSeen:     now,
		LastSeen:      now,
	}

	evt := models.EndpointUSBEvent{
		AgentID:        agent.ID,
		TenantSlug:     agent.TenantSlug,
		AgentHostname:  agent.Hostname,
		AgentIP:        agent.IPAddress,
		EventType:      "inserted",
		VendorID:       dev.VendorID,
		ProductID:      dev.ProductID,
		SerialNumber:   dev.SerialNumber,
		DeviceName:     dev.ProductName,
		DriveLetter:    dev.DriveLetter,
		MountPoint:     dev.MountPoint,
		ActionTaken:    "allowed",
		MitreTechnique: "T1052.001",
		Details:        fmt.Sprintf("Host '%s': Authorized SanDisk Cruzer Blade 32GB attached to drive E:", agent.Hostname),
		CreatedAt:      now,
	}

	if err := h.pgDB.UpsertAgentUSBDevices(r.Context(), tenant, agent.ID, []models.EndpointUSBDevice{dev}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upserting simulated device: " + err.Error()})
		return
	}

	if err := h.pgDB.RecordUSBEvents(r.Context(), tenant, agent.ID, []models.EndpointUSBEvent{evt}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "recording simulated event: " + err.Error()})
		return
	}

	h.recordAudit(r, "USB_SIMULATE_EVENT", "endpoint/usb/simulate", "SUCCESS", map[string]interface{}{
		"agent_id": agent.ID,
		"hostname": agent.Hostname,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Simulated USB event generated successfully for agent '%s'", agent.Hostname),
		"device":  dev,
		"event":   evt,
	})
}
