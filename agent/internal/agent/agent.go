package agent

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"runtime"
	"time"

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
		if a.cfg.EnrollmentToken == "" {
			return fmt.Errorf("agent is unenrolled and no enrollment token was provided")
		}
		if err := a.enroll(ctx); err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}
	} else {
		log.Printf("[LOGGER Agent] Authenticated with existing credentials (Tenant: %s)", a.identity.TenantSlug)
	}

	// 2. Initial heartbeat
	a.sendHeartbeat(ctx)

	// 3. Heartbeat ticker with jitter
	interval := time.Duration(a.cfg.HeartbeatSec) * time.Second
	if interval < 5*time.Second {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[LOGGER Agent] Shutting down gracefully...")
			return nil
		case <-ticker.C:
			// Apply random jitter (+/- 2 seconds) to avoid synchronization spikes
			jitter := time.Duration(rand.Intn(4)-2) * time.Second
			time.Sleep(jitter)
			a.sendHeartbeat(ctx)
		}
	}
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
