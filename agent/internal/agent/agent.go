package agent

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/syslog-platform/logger/agent/internal/collector"
	"github.com/syslog-platform/logger/agent/internal/config"
	"github.com/syslog-platform/logger/agent/internal/dlp"
	"github.com/syslog-platform/logger/agent/internal/edr"
	"github.com/syslog-platform/logger/agent/internal/fim"
	"github.com/syslog-platform/logger/agent/internal/identity"
	"github.com/syslog-platform/logger/agent/internal/netmon"
	"github.com/syslog-platform/logger/agent/internal/ransomware"
	"github.com/syslog-platform/logger/agent/internal/transport"
	"github.com/syslog-platform/logger/agent/internal/updater"
	"github.com/syslog-platform/logger/agent/internal/version"
	"github.com/syslog-platform/logger/internal/models"
)

// Agent represents the running LOGGER Agent daemon instance
type Agent struct {
	cfg           *config.Config
	identity      *identity.Info
	client        *transport.Client
	policyRev     int
	currentPolicy *models.EndpointPolicyConfig
	hbTicker      *time.Ticker
	invTicker     *time.Ticker
	fimTicker     *time.Ticker
	fimScanner    *fim.Scanner
	dlpTicker     *time.Ticker
	dlpScanner    *dlp.Scanner
	edrTicker                *time.Ticker
	edrScanner               *edr.Scanner
	netmonTicker             *time.Ticker
	netmonScanner            *netmon.Scanner
	ransomTicker             *time.Ticker
	shield                   *ransomware.Shield
	isUpgrading              bool
	lastUpgradeAttempt       time.Time
	lastUpgradeFailedVersion string
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
		cfg:           cfg,
		identity:      idInfo,
		client:        client,
		policyRev:     1,
		fimScanner:    fim.NewScanner(),
		dlpScanner:    dlp.NewScanner(),
		edrScanner:    edr.NewScanner(),
		netmonScanner: netmon.NewScanner(),
		shield:        ransomware.NewShield(),
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

	// 2. Heartbeat, Inventory, FIM & DLP tickers
	interval := time.Duration(a.cfg.HeartbeatSec) * time.Second
	if a.currentPolicy != nil && a.currentPolicy.HeartbeatIntervalSec >= 5 {
		interval = time.Duration(a.currentPolicy.HeartbeatIntervalSec) * time.Second
	} else if interval < 5*time.Second {
		interval = 30 * time.Second
	}

	a.hbTicker = time.NewTicker(interval)
	defer a.hbTicker.Stop()

	invInterval := 1 * time.Hour
	if a.currentPolicy != nil && a.currentPolicy.InventoryIntervalSec >= 60 {
		invInterval = time.Duration(a.currentPolicy.InventoryIntervalSec) * time.Second
	}
	a.invTicker = time.NewTicker(invInterval)
	defer a.invTicker.Stop()

	fimInterval := 5 * time.Minute
	if a.currentPolicy != nil && a.currentPolicy.FIMScanIntervalSec >= 30 {
		fimInterval = time.Duration(a.currentPolicy.FIMScanIntervalSec) * time.Second
	}
	a.fimTicker = time.NewTicker(fimInterval)
	defer a.fimTicker.Stop()

	dlpInterval := 30 * time.Second
	if a.currentPolicy != nil && a.currentPolicy.USBScanIntervalSec >= 10 {
		dlpInterval = time.Duration(a.currentPolicy.USBScanIntervalSec) * time.Second
	}
	a.dlpTicker = time.NewTicker(dlpInterval)
	defer a.dlpTicker.Stop()

	edrInterval := 15 * time.Second
	if a.currentPolicy != nil && a.currentPolicy.EDRScanIntervalSec >= 5 {
		edrInterval = time.Duration(a.currentPolicy.EDRScanIntervalSec) * time.Second
	}
	a.edrTicker = time.NewTicker(edrInterval)
	defer a.edrTicker.Stop()

	netmonInterval := 20 * time.Second
	a.netmonTicker = time.NewTicker(netmonInterval)
	defer a.netmonTicker.Stop()

	ransomInterval := 30 * time.Second
	a.ransomTicker = time.NewTicker(ransomInterval)
	defer a.ransomTicker.Stop()

	// Initial heartbeat, inventory, FIM, DLP, EDR, NetMon & Anti-Ransomware scans
	a.sendHeartbeat(ctx)
	go a.sendInventory(ctx)
	go a.sendFIMScan(ctx)
	go a.sendDLPScan(ctx)
	go a.sendEDRScan(ctx)
	go a.sendNetworkScan(ctx)
	go a.sendRansomwareScan(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("[LOGGER Agent] Shutting down gracefully...")
			return nil
		case <-a.invTicker.C:
			go a.sendInventory(ctx)
		case <-a.fimTicker.C:
			go a.sendFIMScan(ctx)
		case <-a.dlpTicker.C:
			go a.sendDLPScan(ctx)
		case <-a.edrTicker.C:
			go a.sendEDRScan(ctx)
		case <-a.netmonTicker.C:
			go a.sendNetworkScan(ctx)
		case <-a.ransomTicker.C:
			go a.sendRansomwareScan(ctx)
		case <-a.hbTicker.C:
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

	if resp.Policy != nil {
		a.currentPolicy = resp.Policy
		if resp.Policy.HeartbeatIntervalSec >= 5 && a.hbTicker != nil {
			a.hbTicker.Reset(time.Duration(resp.Policy.HeartbeatIntervalSec) * time.Second)
		}
		if resp.Policy.InventoryIntervalSec >= 60 && a.invTicker != nil {
			a.invTicker.Reset(time.Duration(resp.Policy.InventoryIntervalSec) * time.Second)
		}
	}

	// Persist updated identity with credentials
	if err := identity.SaveIdentity(a.cfg.IdentityFile, a.identity); err != nil {
		log.Printf("[LOGGER Agent] Warning saving identity: %v", err)
	}

	log.Printf("[LOGGER Agent] Enrollment successful! Assigned to tenant '%s', Agent ID: %s",
		resp.TenantSlug, resp.AgentID.String())

	return nil
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	metrics := collector.GetHostHardwareStats()
	rebootReq := collector.IsRebootRequired()

	req := models.AgentHeartbeatRequest{
		AgentUUID:      a.identity.AgentUUID,
		Hostname:       a.identity.Hostname,
		AgentVersion:   version.Version,
		Status:         "healthy",
		PolicyRevision: a.policyRev,
		IPAddress:      a.identity.IPAddress,
		MACAddress:     a.identity.MACAddress,
		RebootRequired: rebootReq,
		Metrics:        metrics,
	}

	var resp models.AgentHeartbeatResponse
	if err := a.client.PostJSON(ctx, "/api/agent/v1/heartbeat", req, &resp); err != nil {
		log.Printf("[LOGGER Agent] Heartbeat error: %v", err)
		return
	}

	if resp.PolicyNeedsUpdate {
		a.policyRev = resp.CurrentPolicyRevision
		policy := resp.Policy
		if policy == nil {
			var fetched models.EndpointPolicyConfig
			if err := a.client.GetJSON(ctx, "/api/agent/v1/config?agent_uuid="+a.identity.AgentUUID, &fetched); err == nil {
				policy = &fetched
			}
		}

		if policy != nil {
			a.currentPolicy = policy
			log.Printf("[LOGGER Agent] Applied Central Policy Rev %d: Heartbeat=%ds, Inv=%ds, CPU Limit=%d%%, Max RAM=%dMB, Spool=%dMB, Channels=%v",
				a.policyRev, policy.HeartbeatIntervalSec, policy.InventoryIntervalSec,
				policy.MaxCPUPercent, policy.MaxRAMMB, policy.SpoolMaxDiskMB, policy.EventChannels)

			if policy.HeartbeatIntervalSec >= 5 && a.hbTicker != nil {
				a.hbTicker.Reset(time.Duration(policy.HeartbeatIntervalSec) * time.Second)
			}
			if policy.InventoryIntervalSec >= 60 && a.invTicker != nil {
				a.invTicker.Reset(time.Duration(policy.InventoryIntervalSec) * time.Second)
			}
			if policy.FIMScanIntervalSec >= 30 && a.fimTicker != nil {
				a.fimTicker.Reset(time.Duration(policy.FIMScanIntervalSec) * time.Second)
			}
			if policy.USBScanIntervalSec >= 10 && a.dlpTicker != nil {
				a.dlpTicker.Reset(time.Duration(policy.USBScanIntervalSec) * time.Second)
			}
			if policy.EDRScanIntervalSec >= 5 && a.edrTicker != nil {
				a.edrTicker.Reset(time.Duration(policy.EDRScanIntervalSec) * time.Second)
			}
		} else {
			log.Printf("[LOGGER Agent] Server reports policy update available (Rev %d)", a.policyRev)
		}
	}

	// Auto-Update check: server offers newer version (strictly newer, with failure cooldown)
	if resp.UpgradeAvailable && resp.TargetVersion != "" && version.IsNewer(resp.TargetVersion, version.Version) && !a.isUpgrading {
		if a.lastUpgradeFailedVersion == resp.TargetVersion && time.Since(a.lastUpgradeAttempt) < 15*time.Minute {
			// Do not re-attempt failed upgrade continuously on every heartbeat
			return
		}
		a.isUpgrading = true
		a.lastUpgradeAttempt = time.Now()
		go func() {
			log.Printf("[LOGGER Agent] Server offered auto-upgrade to %s (Current: %s). Starting download...",
				resp.TargetVersion, version.Version)
			if err := updater.ApplyUpgrade(context.Background(), a.cfg.ServerURL, resp.DownloadURL, resp.TargetVersion); err != nil {
				log.Printf("[LOGGER Auto-Updater] Upgrade failed: %v", err)
				a.lastUpgradeFailedVersion = resp.TargetVersion
				a.isUpgrading = false
			}
		}()
	}

	// Remote task execution (Patch remediation, scans, safe reboots)
	if len(resp.PendingTasks) > 0 {
		for _, task := range resp.PendingTasks {
			go a.executeTask(context.Background(), task)
		}
	}
}

func (a *Agent) sendFIMScan(ctx context.Context) {
	if a.currentPolicy != nil && a.currentPolicy.FIMEnabled == false && a.currentPolicy.FIMScanIntervalSec > 0 {
		return
	}
	if a.fimScanner == nil {
		return
	}

	var customPaths, excludePaths []string
	if a.currentPolicy != nil {
		customPaths = a.currentPolicy.FIMPaths
		excludePaths = a.currentPolicy.FIMExcludePaths
	}

	events, baselines := a.fimScanner.Scan(customPaths, excludePaths)
	if len(events) == 0 && len(baselines) == 0 {
		return
	}

	if len(events) > 0 {
		log.Printf("[LOGGER FIM] Detected %d integrity deviation events on host!", len(events))
	}

	sub := models.AgentFIMSubmission{
		AgentUUID:     a.identity.AgentUUID,
		Hostname:      a.identity.Hostname,
		Events:        events,
		BaselineItems: baselines,
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := a.client.PostJSON(ctx, "/api/agent/v1/fim", sub, &resp); err != nil {
		log.Printf("[LOGGER FIM] Error submitting FIM telemetry: %v", err)
	}
}

func (a *Agent) sendDLPScan(ctx context.Context) {
	if a.currentPolicy != nil && a.currentPolicy.USBControlEnabled == false && a.currentPolicy.USBScanIntervalSec > 0 {
		return
	}
	if a.dlpScanner == nil {
		return
	}

	devices, events := a.dlpScanner.Scan(a.currentPolicy)
	if len(devices) == 0 && len(events) == 0 {
		return
	}

	if len(events) > 0 {
		log.Printf("[LOGGER DLP] Detected %d USB storage hardware events!", len(events))
	}

	sub := models.AgentUSBSubmission{
		AgentUUID: a.identity.AgentUUID,
		Devices:   devices,
		Events:    events,
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := a.client.PostJSON(ctx, "/api/agent/v1/usb", sub, &resp); err != nil {
		log.Printf("[LOGGER DLP] Error submitting USB telemetry: %v", err)
	}
}

func (a *Agent) sendEDRScan(ctx context.Context) {
	if a.currentPolicy != nil && a.currentPolicy.EDRBehaviorEnabled == false && a.currentPolicy.EDRScanIntervalSec > 0 {
		return
	}
	if a.edrScanner == nil {
		return
	}

	anomalies := a.edrScanner.Scan(a.currentPolicy)
	if len(anomalies) == 0 {
		return
	}

	log.Printf("[LOGGER EDR] Detected %d behavioral anomaly / malicious script events!", len(anomalies))

	sub := models.AgentBehaviorSubmission{
		AgentUUID: a.identity.AgentUUID,
		Anomalies: anomalies,
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := a.client.PostJSON(ctx, "/api/agent/v1/behavior", sub, &resp); err != nil {
		log.Printf("[LOGGER EDR] Error submitting behavior telemetry: %v", err)
	}
}

func (a *Agent) sendNetworkScan(ctx context.Context) {
	if a.currentPolicy != nil && a.currentPolicy.EDRNetMonEnabled == false && a.currentPolicy.EDRDNSAuditEnabled == false && a.currentPolicy.EDRBeaconIntervalSec > 0 {
		return
	}
	if a.netmonScanner == nil {
		return
	}

	conns, dnsQueries := a.netmonScanner.Scan(a.currentPolicy)
	if len(conns) == 0 && len(dnsQueries) == 0 {
		return
	}

	if len(conns) > 0 || len(dnsQueries) > 0 {
		log.Printf("[LOGGER NetMon] Observed %d socket connection(s), %d DNS query(ies)", len(conns), len(dnsQueries))
	}

	sub := models.AgentNetworkSubmission{
		AgentUUID:   a.identity.AgentUUID,
		Connections: conns,
		DNSQueries:  dnsQueries,
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := a.client.PostJSON(ctx, "/api/agent/v1/network", sub, &resp); err != nil {
		log.Printf("[LOGGER NetMon] Error submitting network telemetry: %v", err)
	}
}

func (a *Agent) sendRansomwareScan(ctx context.Context) {
	if a.shield == nil {
		return
	}

	submission := a.shield.Inspect()
	submission.AgentUUID = a.identity.AgentUUID

	if len(submission.Incidents) > 0 {
		log.Printf("[LOGGER Anti-Ransomware] ⚠️ SHIELD ALERT: %d ransomware incident(s) detected and contained!", len(submission.Incidents))
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := a.client.PostJSON(ctx, "/api/agent/v1/ransomware", submission, &resp); err != nil {
		log.Printf("[LOGGER Anti-Ransomware] Error submitting ransomware telemetry: %v", err)
	}
}

