package agent

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"runtime"
	"strings"
	"time"

	"github.com/syslog-platform/logger/agent/internal/collector"
	"github.com/syslog-platform/logger/agent/internal/config"
	"github.com/syslog-platform/logger/agent/internal/identity"
	"github.com/syslog-platform/logger/agent/internal/transport"
	"github.com/syslog-platform/logger/agent/internal/version"
	"github.com/syslog-platform/logger/internal/models"
)

// Agent represents the running LOGGER Agent daemon instance
type Agent struct {
	cfg       *config.Config
	identity  *identity.Info
	client    *transport.Client
	policyRev int
}

// NewAgent initializes the agent with configuration and identity
func NewAgent(cfg *config.Config) (*Agent, error) {
	idInfo, err := identity.LoadOrGenerate(cfg.IdentityFile)
	if err != nil {
		return nil, fmt.Errorf("loading identity: %w", err)
	}

	client := transport.NewClient(cfg.ServerURL, true)
	if idInfo.AuthToken != "" {
		client.SetAuthToken(idInfo.AuthToken)
	}

	return &Agent{
		cfg:       cfg,
		identity:  idInfo,
		client:    client,
		policyRev: 1,
	}, nil
}

// Run begins the agent lifecycle: enrollment check and heartbeat loop
func (a *Agent) Run(ctx context.Context) error {
	log.Printf("[LOGGER Agent] Starting on %s (%s/%s), UUID: %s",
		a.identity.Hostname, a.identity.OSType, a.identity.Architecture, a.identity.AgentUUID)

	// 1. Enrollment check
	if a.identity.AuthToken == "" {
		for {
			token := strings.TrimSpace(a.cfg.EnrollmentToken)
			if token == "" || token == "<TOKEN>" {
				log.Println("[LOGGER Agent] Waiting for valid enrollment token in config.json... (Retrying in 15s)")
			} else {
				if err := a.enroll(ctx); err == nil {
					log.Printf("[LOGGER Agent] Successfully enrolled! (Tenant: %s)", a.identity.TenantSlug)
					break
				} else {
					log.Printf("[LOGGER Agent] Enrollment attempt failed: %v. Retrying in 15s...", err)
				}
			}

			select {
			case <-ctx.Done():
				return nil
			case <-time.After(15 * time.Second):
				if a.cfg.ConfigPath != "" {
					if refreshedCfg, err := config.LoadConfig(a.cfg.ConfigPath); err == nil {
						if refreshedCfg.EnrollmentToken != "" && refreshedCfg.EnrollmentToken != "<TOKEN>" {
							a.cfg.EnrollmentToken = refreshedCfg.EnrollmentToken
							a.cfg.ServerURL = refreshedCfg.ServerURL
						}
					}
				}
			}
		}
	} else {
		log.Printf("[LOGGER Agent] Authenticated with existing credentials (Tenant: %s)", a.identity.TenantSlug)
	}

	// 2. Initial heartbeat & inventory
	a.sendHeartbeat(ctx)
	go a.sendInventory(ctx)

	// 3. Heartbeat & Inventory tickers
	interval := time.Duration(a.cfg.HeartbeatSec) * time.Second
	if interval < 5*time.Second {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Periodic full inventory scan every 1 hour
	invTicker := time.NewTicker(1 * time.Hour)
	defer invTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[LOGGER Agent] Shutting down gracefully...")
			return nil
		case <-invTicker.C:
			go a.sendInventory(ctx)
		case <-ticker.C:
			// Apply random jitter (+/- 2 seconds) to avoid synchronization spikes
			jitter := time.Duration(rand.Intn(4)-2) * time.Second
			time.Sleep(jitter)
			a.sendHeartbeat(ctx)
		}
	}
}

func (a *Agent) sendInventory(ctx context.Context) {
	log.Println("[LOGGER Agent] Collecting host inventory, software packages, and patches...")
	inv, err := collector.Collect()
	if err != nil {
		log.Printf("[LOGGER Agent] Error collecting inventory: %v", err)
		return
	}

	inv.AgentUUID = a.identity.AgentUUID
	inv.Hostname = a.identity.Hostname
	inv.IPAddress = a.identity.IPAddress
	inv.MACAddress = a.identity.MACAddress

	var resp models.AgentInventoryResponse
	if err := a.client.PostJSON(ctx, "/api/agent/v1/inventory", inv, &resp); err != nil {
		log.Printf("[LOGGER Agent] Inventory upload error: %v", err)
		return
	}

	log.Printf("[LOGGER Agent] Inventory reported successfully: %d software packages, %d patches (Server detected %d CVEs)",
		resp.ProcessedSoftware, resp.ProcessedPatches, resp.DetectedVulns)
}

func (a *Agent) enroll(ctx context.Context) error {
	log.Println("[LOGGER Agent] Enrolling with LOGGER server...")

	req := models.AgentEnrollRequest{
		EnrollmentToken:   a.cfg.EnrollmentToken,
		AgentUUID:         a.identity.AgentUUID,
		Hostname:          a.identity.Hostname,
		FQDN:              a.identity.FQDN,
		OSType:            a.identity.OSType,
		OSFamily:          a.identity.OSFamily,
		OSName:            a.identity.OSName,
		OSVersion:         a.identity.OSVersion,
		OSBuild:           a.identity.OSBuild,
		KernelVersion:     a.identity.KernelVersion,
		Architecture:      a.identity.Architecture,
		AgentVersion:      version.Version,
		IPAddress:         a.identity.IPAddress,
		MACAddress:        a.identity.MACAddress,
		DeviceFingerprint: a.identity.DeviceFingerprint,
	}

	var resp models.AgentEnrollResponse
	if err := a.client.PostJSON(ctx, "/api/agent/v1/enroll", req, &resp); err != nil {
		return err
	}

	a.identity.AuthToken = resp.AuthToken
	a.identity.TenantSlug = resp.TenantSlug
	a.policyRev = resp.PolicyRevision
	a.client.SetAuthToken(resp.AuthToken)

	// Persist updated identity with credentials
	if err := identity.SaveIdentity(a.cfg.IdentityFile, a.identity); err != nil {
		log.Printf("[LOGGER Agent] Warning saving identity: %v", err)
	}

	log.Printf("[LOGGER Agent] Enrollment successful! Assigned to tenant '%s', Agent ID: %s",
		resp.TenantSlug, resp.AgentID.String())

	return nil
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	req := models.AgentHeartbeatRequest{
		AgentUUID:      a.identity.AgentUUID,
		Hostname:       a.identity.Hostname,
		AgentVersion:   version.Version,
		Status:         "healthy",
		PolicyRevision: a.policyRev,
		IPAddress:      a.identity.IPAddress,
		MACAddress:     a.identity.MACAddress,
		RebootRequired: false,
		Metrics: models.AgentResourceMetrics{
			CPUPercent:     0.5,
			RAMRSSBytes:    m.Sys,
			SpoolDiskBytes: 0,
			QueueDepth:     0,
			EPSOut:         0.0,
		},
	}

	var resp models.AgentHeartbeatResponse
	if err := a.client.PostJSON(ctx, "/api/agent/v1/heartbeat", req, &resp); err != nil {
		log.Printf("[LOGGER Agent] Heartbeat error: %v", err)
		return
	}

	if resp.PolicyNeedsUpdate {
		log.Printf("[LOGGER Agent] Server reports policy update available (Rev %d -> %d)",
			a.policyRev, resp.CurrentPolicyRevision)
		a.policyRev = resp.CurrentPolicyRevision
	}
}
