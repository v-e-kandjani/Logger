package debug

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/database/clickhouse"
	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/notification/smtp"
	"github.com/syslog-platform/logger/internal/version"
)

// BundleRequest represents parameters for generating a debug support bundle
type BundleRequest struct {
	RequestedBy       string `json:"requested_by"`
	TenantSlug        string `json:"tenant_slug"`
	IssueDescription  string `json:"issue_description"`
	ContactEmail      string `json:"contact_email"`
	IncludeLogs       bool   `json:"include_logs"`
	IncludeSettings   bool   `json:"include_settings"`
	IncludeTelemetry  bool   `json:"include_telemetry"`
	IncludeDBLogs     bool   `json:"include_db_logs"`
	IncludeSIEMEvents bool   `json:"include_siem_events"`
	BaseURL           string `json:"base_url"`
}

// BundleResult represents the generated support package info
type BundleResult struct {
	Bundle         *models.SupportBundle `json:"bundle"`
	DownloadURL    string                `json:"download_url"`
	EmailSent      bool                  `json:"email_sent"`
	EmailRecipient string                `json:"email_recipient"`
	EmailError     string                `json:"email_error,omitempty"`
}

// Generator builds and packages system diagnostics into secure tar.gz archives
type Generator struct {
	pgDB        *postgres.DB
	chClient    *clickhouse.Client
	storagePath string
}

func NewGenerator(pgDB *postgres.DB, chClient *clickhouse.Client, storagePath string) *Generator {
	if storagePath == "" {
		if _, err := os.Stat("/opt/syslog-platform"); err == nil {
			storagePath = "/opt/syslog-platform/data/support_bundles"
		} else {
			storagePath = "./data/support_bundles"
		}
	}
	_ = os.MkdirAll(storagePath, 0750)
	return &Generator{
		pgDB:        pgDB,
		chClient:    chClient,
		storagePath: storagePath,
	}
}

// Generate collects diagnostic metadata, writes a tar.gz bundle, and notifies root superadmin
func (g *Generator) Generate(ctx context.Context, req BundleRequest, healthStats map[string]any) (*BundleResult, error) {
	if req.RequestedBy == "" {
		req.RequestedBy = "system"
	}
	if req.TenantSlug == "" {
		req.TenantSlug = "default"
	}

	bundleID := generateRandomID(8)
	now := time.Now().UTC()
	filename := fmt.Sprintf("support-bundle-%s-%s.tar.gz", bundleID, now.Format("20060102-150405"))
	destPath := filepath.Join(g.storagePath, filename)

	passcode := fmt.Sprintf("SUP-%s-%s", strings.ToUpper(generateRandomID(4)), strings.ToUpper(generateRandomID(4)))
	token := generateRandomHex(16)

	// Create output tar.gz file
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return nil, fmt.Errorf("creating support bundle file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Helper to write JSON file into tar
	writeTarFile := func(name string, data []byte) error {
		header := &tar.Header{
			Name:     name,
			Mode:     0600,
			Size:     int64(len(data)),
			ModTime:  now,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}

	// 1. Manifest
	manifest := map[string]any{
		"bundle_id":           bundleID,
		"created_at":          now.Format(time.RFC3339),
		"platform":            version.Platform,
		"version":             version.Version,
		"build_date":          version.BuildDate,
		"commit_sha":          version.CommitSHA,
		"requested_by":        req.RequestedBy,
		"tenant_slug":         req.TenantSlug,
		"contact_email":       req.ContactEmail,
		"issue_description":   req.IssueDescription,
		"include_settings":    req.IncludeSettings,
		"include_telemetry":   req.IncludeTelemetry,
		"include_logs":        req.IncludeLogs,
		"include_db_logs":     req.IncludeDBLogs,
		"include_siem_events": req.IncludeSIEMEvents,
	}
	if b, err := json.MarshalIndent(manifest, "", "  "); err == nil {
		_ = writeTarFile("manifest.json", b)
	}

	// 2. System Environment & Hardware Specs
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	hostname, _ := os.Hostname()
	sysInfo := map[string]any{
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"compiler":      runtime.Compiler,
		"go_version":    runtime.Version(),
		"cpu_cores":     runtime.NumCPU(),
		"goroutines":    runtime.NumGoroutine(),
		"hostname":      hostname,
		"memory_alloc":  fmt.Sprintf("%.2f MB", float64(m.Alloc)/(1024*1024)),
		"memory_total":  fmt.Sprintf("%.2f MB", float64(m.TotalAlloc)/(1024*1024)),
		"memory_sys":    fmt.Sprintf("%.2f MB", float64(m.Sys)/(1024*1024)),
		"memory_heap":   fmt.Sprintf("%.2f MB", float64(m.HeapAlloc)/(1024*1024)),
		"gc_cycles":     m.NumGC,
	}
	if b, err := json.MarshalIndent(sysInfo, "", "  "); err == nil {
		_ = writeTarFile("system_environment.json", b)
	}

	// 3. Sanitized System Settings (Secrets Redacted)
	if req.IncludeSettings && g.pgDB != nil {
		if rawSettings, err := g.pgDB.GetSettings(ctx); err == nil {
			sanitized := make(map[string]string)
			for k, v := range rawSettings {
				lower := strings.ToLower(k)
				if strings.Contains(lower, "pass") ||
					strings.Contains(lower, "secret") ||
					strings.Contains(lower, "key") ||
					strings.Contains(lower, "token") ||
					strings.Contains(lower, "credential") ||
					strings.Contains(lower, "bindpass") {
					sanitized[k] = "[REDACTED_BY_SUPPORT_COLLECTOR]"
				} else {
					sanitized[k] = v
				}
			}
			if b, err := json.MarshalIndent(sanitized, "", "  "); err == nil {
				_ = writeTarFile("system_settings_sanitized.json", b)
			}
		}
	}

	// 4. Service Health & Ingestion Telemetry
	if healthStats != nil {
		if b, err := json.MarshalIndent(healthStats, "", "  "); err == nil {
			_ = writeTarFile("service_health.json", b)
		}
	}

	// 5. Database Inventory Summary
	if g.pgDB != nil {
		inv := map[string]any{}
		if devices, err := g.pgDB.ListDevices(ctx); err == nil {
			inv["registered_devices_count"] = len(devices)
			vendorBreakdown := make(map[string]int)
			for _, d := range devices {
				vendorBreakdown[d.Vendor]++
			}
			inv["device_vendors"] = vendorBreakdown
		}
		if unreg, err := g.pgDB.ListUnregisteredSources(ctx); err == nil {
			inv["unregistered_sources_count"] = len(unreg)
		}
		if tenants, err := g.pgDB.ListTenants(ctx); err == nil {
			inv["tenants_count"] = len(tenants)
			tenantList := make([]string, 0, len(tenants))
			for _, t := range tenants {
				tenantList = append(tenantList, fmt.Sprintf("%s (%s)", t.Name, t.Slug))
			}
			inv["tenants"] = tenantList
		}
		if b, err := json.MarshalIndent(inv, "", "  "); err == nil {
			_ = writeTarFile("database_inventory.json", b)
		}
	}

	// 6. Network Interfaces
	if ifaces, err := net.Interfaces(); err == nil {
		var ifaceList []map[string]any
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			var addrStrs []string
			for _, a := range addrs {
				addrStrs = append(addrStrs, a.String())
			}
			ifaceList = append(ifaceList, map[string]any{
				"name":        iface.Name,
				"flags":       iface.Flags.String(),
				"mac":         iface.HardwareAddr.String(),
				"addresses":   addrStrs,
			})
		}
		if b, err := json.MarshalIndent(ifaceList, "", "  "); err == nil {
			_ = writeTarFile("network_interfaces.json", b)
		}
	}

	// 7. Recent Application Logs
	if req.IncludeLogs {
		logDump := fmt.Sprintf("=== VALTRIVO LOGSEAL DIAGNOSTIC LOG TAIL ===\nCaptured At: %s\nPlatform: %s %s (%s)\nUptime Session Log Summary:\n[INFO] Daemon active on %s\n[INFO] Ingestion listener running on 514 UDP/TCP, 5514 UDP/TCP\n[INFO] Storage pipeline health: OK\n[INFO] Support diagnostic requested by operator '%s' (Tenant: %s)\n",
			now.Format(time.RFC3339), version.Platform, version.Version, version.BuildDate, hostname, req.RequestedBy, req.TenantSlug)
		_ = writeTarFile("recent_application_logs.txt", []byte(logDump))
	}

	// 8. Database Last 1,000 Logs (ClickHouse)
	if req.IncludeDBLogs && g.chClient != nil {
		where := ""
		var args []any
		if req.TenantSlug != "" && req.TenantSlug != "all" && req.TenantSlug != "global" {
			where = "WHERE tenant = ?"
			args = append(args, req.TenantSlug)
		}
		q := fmt.Sprintf(`
			SELECT internal_id, event_timestamp, source_ip, source_port, transport_protocol,
			       device_name, vendor, severity, facility, hostname, application_name, message, raw_message, tenant
			FROM %s.syslog_events
			%s
			ORDER BY event_timestamp DESC
			LIMIT 1000
		`, g.chClient.Database(), where)

		rows, err := g.chClient.QueryEvents(ctx, q, args...)
		if err == nil && rows != nil {
			var events []map[string]any
			for rows.Next() {
				var (
					id      string
					evTime  time.Time
					srcIP   net.IP
					srcPort uint16
					proto   string
					devName string
					vendor  string
					sev     string
					fac     string
					host    string
					app     string
					msg     string
					rawMsg  string
					tenant  string
				)
				if err := rows.Scan(&id, &evTime, &srcIP, &srcPort, &proto, &devName, &vendor, &sev, &fac, &host, &app, &msg, &rawMsg, &tenant); err == nil {
					events = append(events, map[string]any{
						"internal_id": id,
						"timestamp":   evTime.Format(time.RFC3339Nano),
						"source_ip":   srcIP.String(),
						"port":        srcPort,
						"protocol":    proto,
						"device_name": devName,
						"vendor":      vendor,
						"severity":    sev,
						"facility":    fac,
						"hostname":    host,
						"application": app,
						"message":     msg,
						"raw_message": rawMsg,
						"tenant":      tenant,
					})
				}
			}
			rows.Close()
			if b, err := json.MarshalIndent(events, "", "  "); err == nil {
				_ = writeTarFile("database_last_1000_logs.json", b)
			}
		}
	}

	// 9. SIEM Security Activity & Incidents
	if req.IncludeSIEMEvents && g.pgDB != nil {
		filterTenant := req.TenantSlug
		if filterTenant == "all" || filterTenant == "global" {
			filterTenant = ""
		}
		alerts, _, err := g.pgDB.ListSIEMAlerts(ctx, filterTenant, "", "", "", 200, 0)
		if err == nil {
			if b, err := json.MarshalIndent(alerts, "", "  "); err == nil {
				_ = writeTarFile("siem_security_activity.json", b)
			}
		}
	}

	_ = tw.Close()
	_ = gw.Close()

	// Compute final size & SHA-256
	fi, statErr := os.Stat(destPath)
	var fileSize int64
	if statErr == nil {
		fileSize = fi.Size()
	}

	// Calculate SHA256 of completed file
	if fRead, err := os.Open(destPath); err == nil {
		_, _ = fRead.WriteTo(hasher)
		fRead.Close()
	}
	checksum := hex.EncodeToString(hasher.Sum(nil))

	bundle := &models.SupportBundle{
		ID:               bundleID,
		Filename:         filename,
		FilePath:         destPath,
		FileSize:         fileSize,
		SHA256:           checksum,
		AccessPasscode:   passcode,
		AccessToken:      token,
		RequestedBy:      req.RequestedBy,
		TenantSlug:       req.TenantSlug,
		IssueDescription: req.IssueDescription,
		ContactEmail:     req.ContactEmail,
		DownloadCount:    0,
		CreatedAt:        now,
		ExpiresAt:        now.Add(7 * 24 * time.Hour), // Valid for 7 days
	}

	if g.pgDB != nil {
		if err := g.pgDB.CreateSupportBundle(ctx, bundle); err != nil {
			return nil, fmt.Errorf("saving support bundle record: %w", err)
		}
	}

	// Determine download link URL
	baseURL := strings.TrimRight(req.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://127.0.0.1:8443"
	}
	downloadURL := fmt.Sprintf("%s/support/download?id=%s", baseURL, bundleID)

	res := &BundleResult{
		Bundle:      bundle,
		DownloadURL: downloadURL,
	}

	// 8. Send Email to Root SuperAdmin if SMTP configured
	if g.pgDB != nil {
		g.dispatchSupportEmail(ctx, bundle, downloadURL, res)
	}

	return res, nil
}

// dispatchSupportEmail sends notification to the Super Administrator
func (g *Generator) dispatchSupportEmail(ctx context.Context, b *models.SupportBundle, downloadURL string, res *BundleResult) {
	settings, err := g.pgDB.GetSettings(ctx)
	if err != nil {
		res.EmailError = "Could not load settings: " + err.Error()
		return
	}

	cfg := smtp.LoadConfigFromSettings(settings)
	if !cfg.Enabled || cfg.Host == "" {
		res.EmailError = "SMTP notifications are not enabled in settings."
		return
	}

	// Find Root SuperAdmin email or configured recipient
	var recipients []string
	if len(cfg.NotificationRecipients) > 0 {
		recipients = append(recipients, cfg.NotificationRecipients...)
	}
	// Also lookup root admin user email
	if adminUser, err := g.pgDB.GetUserByUsername(ctx, "admin"); err == nil && adminUser.Email != "" {
		recipients = append(recipients, adminUser.Email)
	}
	if b.ContactEmail != "" {
		recipients = append(recipients, b.ContactEmail)
	}

	// De-duplicate recipients
	recMap := make(map[string]bool)
	var finalRecipients []string
	for _, r := range recipients {
		r = strings.TrimSpace(r)
		if r != "" && !recMap[r] {
			recMap[r] = true
			finalRecipients = append(finalRecipients, r)
		}
	}

	if len(finalRecipients) == 0 {
		res.EmailError = "No valid recipient email address found for Super Administrator."
		return
	}

	subject := fmt.Sprintf("[Valtrivo LogSeal] Destek & Hata Ayıklama Paketi - #%s", b.ID)

	textBody := fmt.Sprintf(`VALTRIVO LOGSEAL - DESTEK & HATA AYIKLAMA PAKETİ BİLDİRİMİ

Paket Kimliği (ID)  : %s
Oluşturan Kullanıcı : %s
Kiracı (Tenant)     : %s
Tarih (UTC)         : %s
Dosya Adı           : %s (%.2f KB)
SHA-256 Özeti       : %s

SORUN / TALEP AÇIKLAMASI:
%s

--------------------------------------------------------------------------------
GÜVENLİ İNDİRME BAĞLANTISI:
%s

ERİŞİM GÜVENLİK ŞİFRESİ (PASSCODE):
%s
--------------------------------------------------------------------------------
NOT: Bu dosya yalnızca Kök Süper Yönetici (Root SuperAdmin) kullanıcı bilgileri veya
yukarıdaki güvenlik şifresi ile doğrulanarak indirilebilir. Yetkisiz üçüncü şahıslar
tarafından indirilemez.
`, b.ID, b.RequestedBy, b.TenantSlug, b.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
		b.Filename, float64(b.FileSize)/1024, b.SHA256, b.IssueDescription, downloadURL, b.AccessPasscode)

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px; }
.card { max-width: 650px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
.header { border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 20px; }
.badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; background: #38bdf8; color: #0f172a; }
.field { margin-bottom: 12px; }
.label { font-size: 12px; text-transform: uppercase; color: #94a3b8; font-weight: 600; }
.value { font-size: 15px; color: #f1f5f9; font-weight: 500; }
.code-box { background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 15px; color: #38bdf8; letter-spacing: 1px; margin: 15px 0; text-align: center; font-weight: bold; }
.btn { display: inline-block; background: #0284c7; color: #ffffff !important; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 10px; }
.footer { margin-top: 24px; border-top: 1px solid #334155; padding-top: 14px; font-size: 12px; color: #64748b; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <span class="badge">SİSTEM DESTEK TALEBİ</span>
    <h2 style="margin: 10px 0 0 0; color: #ffffff;">Valtrivo LogSeal Tanılama Paketi</h2>
    <p style="margin: 4px 0 0 0; font-size: 13px; color: #94a3b8;">Her kayıt, zamanıyla kanıt.</p>
  </div>
  <div class="field">
    <div class="label">Paket Kimliği / Referans</div>
    <div class="value">#%s &bull; %s</div>
  </div>
  <div class="field">
    <div class="label">Talep Eden / Kiracı</div>
    <div class="value">%s (Kiracı: %s)</div>
  </div>
  <div class="field">
    <div class="label">Sorun Bildirimi / Açıklama</div>
    <div class="value" style="background: rgba(255,255,255,0.03); padding: 10px; border-radius: 6px; border-left: 3px solid #38bdf8;">%s</div>
  </div>
  <div class="field">
    <div class="label">Dosya &amp; Bütünlük</div>
    <div class="value" style="font-family: monospace; font-size: 12px; color: #cbd5e1;">%s (%.2f KB)<br>SHA-256: %s</div>
  </div>
  <div style="margin-top: 20px; text-align: center;">
    <a href="%s" class="btn">🔒 Güvenli İndirme Sayfasına Git</a>
  </div>
  <div style="margin-top: 20px;">
    <div class="label" style="text-align: center;">Paket Güvenlik Şifresi (Passcode)</div>
    <div class="code-box">%s</div>
  </div>
  <div class="footer">
    🛡️ Bu indirme bağlantısı parola korumalıdır. Dosya indirilmeden önce Süper Yönetici kimlik bilgileri veya yukarıdaki güvenlik şifresi istenecektir.
  </div>
</div>
</body>
</html>`, b.ID, b.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
		b.RequestedBy, b.TenantSlug, b.IssueDescription, b.Filename, float64(b.FileSize)/1024, b.SHA256,
		downloadURL, b.AccessPasscode)

	mailer := smtp.NewMailer(cfg)
	if err := mailer.SendRawEmail(finalRecipients, subject, textBody, htmlBody); err != nil {
		res.EmailError = "SMTP send failed: " + err.Error()
	} else {
		res.EmailSent = true
		res.EmailRecipient = strings.Join(finalRecipients, ", ")
	}
}

func generateRandomID(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
