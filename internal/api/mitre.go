package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/siem/mitre"
)

const settingMitreAutoSync = "mitre_auto_sync"

// StartMitreAutoSync restores the persisted ATT&CK catalog and launches the release watcher.
//
// Environment overrides:
//   MITRE_AUTO_SYNC=false            disable automatic release checks (default enabled; UI toggle persists in settings)
//   MITRE_SYNC_INTERVAL_HOURS=24     how often to check the feed (conditional GET, 304 when unchanged)
//   MITRE_STIX_URL=<url>             alternate feed (e.g. internal mirror for air-gapped networks)
func (h *Handler) StartMitreAutoSync(ctx context.Context) {
	h.mitreCatalog.SetStore(h.pgDB)

	// Hook into matrix updates to automatically add related SIEM correlation rules
	h.mitreCatalog.SetOnUpdateHook(func(techs []mitre.Technique) {
		bgCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		added, err := h.AutoAddMitreCorrelationRules(bgCtx, techs)
		if err != nil {
			log.Printf("[MITRE] Error auto-adding correlation rules on matrix update: %v", err)
		} else if added > 0 {
			log.Printf("[MITRE] Matrix update: automatically added %d new SIEM correlation rules", added)
		}
	})

	loadCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	if err := h.mitreCatalog.LoadFromStore(loadCtx); err != nil {
		log.Printf("[MITRE] could not restore persisted catalog: %v (using embedded baseline)", err)
	}
	cancel()
	log.Printf("[MITRE] catalog ready with %d techniques", h.mitreCatalog.TechniqueCount())

	// Ensure any loaded techniques have their correlation rules in the rule set
	go func() {
		initCtx, cancelInit := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancelInit()
		added, _ := h.AutoAddMitreCorrelationRules(initCtx, nil)
		if added > 0 {
			log.Printf("[MITRE] Startup check: added %d missing correlation rules for loaded techniques", added)
		}
	}()

	enabled := true
	if v := strings.TrimSpace(os.Getenv("MITRE_AUTO_SYNC")); v != "" {
		enabled = !(strings.EqualFold(v, "false") || v == "0" || strings.EqualFold(v, "off"))
	}
	settingsCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	if s, err := h.pgDB.GetSettings(settingsCtx); err == nil {
		if v, ok := s[settingMitreAutoSync]; ok && v != "" {
			enabled = v == "true"
		}
	}
	cancel2()

	interval := 24 * time.Hour
	if v, err := strconv.Atoi(os.Getenv("MITRE_SYNC_INTERVAL_HOURS")); err == nil && v > 0 {
		interval = time.Duration(v) * time.Hour
	}

	h.mitreCatalog.StartAutoSync(ctx, mitre.AutoSyncConfig{
		Enabled:       enabled,
		FeedURL:       os.Getenv("MITRE_STIX_URL"),
		CheckInterval: interval,
	})
	log.Printf("[MITRE] automatic ATT&CK release watcher: enabled=%v interval=%s", enabled, interval)
}

// handleSIEMMitreAutoSync
//
//	GET  -> watcher status
//	POST {"enabled": bool}       -> enable/disable (persisted)
//	POST {"check_now": true}     -> run a conditional update check immediately
func (h *Handler) handleSIEMMitreAutoSync(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, h.mitreCatalog.AutoSyncStatus())
		return
	case http.MethodPost:
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled  *bool `json:"enabled"`
		CheckNow bool  `json:"check_now"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.Enabled != nil {
		h.mitreCatalog.SetAutoSyncEnabled(*req.Enabled)
		ctx, cancel := contextWithTimeout(r, 5*time.Second)
		_ = h.pgDB.SaveSetting(ctx, settingMitreAutoSync, strconv.FormatBool(*req.Enabled))
		cancel()
	}

	resp := map[string]interface{}{}
	if req.CheckNow {
		ctx, cancel := contextWithTimeout(r, 6*time.Minute)
		result, err := h.mitreCatalog.CheckForUpdate(ctx)
		if err == nil {
			added, _ := h.AutoAddMitreCorrelationRules(ctx, h.mitreCatalog.GetAllTechniques())
			if added > 0 {
				result = fmt.Sprintf("%s (%d correlation rules automatically added)", result, added)
			}
		}
		cancel()
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{
				"error":  "update check failed: " + err.Error(),
				"status": h.mitreCatalog.AutoSyncStatus(),
			})
			return
		}
		resp["message"] = result
	}
	resp["status"] = h.mitreCatalog.AutoSyncStatus()
	writeJSON(w, http.StatusOK, resp)
}
