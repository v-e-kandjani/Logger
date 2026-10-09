package smtp

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// Config holds SMTP transmission settings
type Config struct {
	Enabled                bool          `json:"enabled"`
	Host                   string        `json:"host"`
	Port                   int           `json:"port"`
	Encryption             string        `json:"encryption"` // "STARTTLS", "SSL/TLS", "None"
	InsecureSkipVerify     bool          `json:"insecure_skip_verify"`
	Username               string        `json:"username"`
	Password               string        `json:"password"`
	FromAddress            string        `json:"from_address"`
	FromName               string        `json:"from_name"`
	NotifyOnAssignment     bool          `json:"notify_on_assignment"`
	NotifyOnCritical       bool          `json:"notify_on_critical"`
	NotificationRecipients []string      `json:"notification_recipients"`
	PortalURL              string        `json:"portal_url"`
	Timeout                time.Duration `json:"timeout"`
}

// Mailer manages outgoing notifications
type Mailer struct {
	cfg Config
}

// NewMailer creates a new SMTP notification client
func NewMailer(cfg Config) *Mailer {
	if cfg.Port <= 0 {
		if cfg.Encryption == "SSL/TLS" {
			cfg.Port = 465
		} else {
			cfg.Port = 587
		}
	}
	if cfg.FromName == "" {
		cfg.FromName = "Valtrivo LogSeal SIEM"
	}
	if cfg.FromAddress == "" {
		cfg.FromAddress = "noreply@syslog.local"
	}
	if cfg.PortalURL == "" {
		cfg.PortalURL = "http://localhost:8080"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Mailer{cfg: cfg}
}

// LoadConfigFromSettings builds Config from system_settings map
func LoadConfigFromSettings(s map[string]string) Config {
	port, _ := strconv.Atoi(s["smtp_port"])
	if port <= 0 {
		port = 587
	}
	enc := strings.ToUpper(strings.TrimSpace(s["smtp_encryption"]))
	if enc == "" {
		enc = "STARTTLS"
	}

	var recipients []string
	if raw := strings.TrimSpace(s["smtp_notification_recipients"]); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				recipients = append(recipients, part)
			}
		}
	}

	portalURL := strings.TrimRight(strings.TrimSpace(s["smtp_portal_url"]), "/")
	if portalURL == "" {
		portalURL = "http://localhost:8080"
	}

	return Config{
		Enabled:                s["smtp_enabled"] == "true" || s["smtp_enabled"] == "1",
		Host:                   strings.TrimSpace(s["smtp_host"]),
		Port:                   port,
		Encryption:             enc,
		InsecureSkipVerify:     s["smtp_insecure_skip_verify"] == "true" || s["smtp_insecure_skip_verify"] == "1",
		Username:               strings.TrimSpace(s["smtp_username"]),
		Password:               s["smtp_password"],
		FromAddress:            strings.TrimSpace(s["smtp_from_address"]),
		FromName:               strings.TrimSpace(s["smtp_from_name"]),
		NotifyOnAssignment:     s["smtp_notify_on_assignment"] == "true" || s["smtp_notify_on_assignment"] == "1",
		NotifyOnCritical:       s["smtp_notify_on_critical"] == "true" || s["smtp_notify_on_critical"] == "1",
		NotificationRecipients: recipients,
		PortalURL:              portalURL,
		Timeout:                15 * time.Second,
	}
}

// SendRawEmail sends a MIME message over SMTP with configured security
func (m *Mailer) SendRawEmail(to []string, subject, textBody, htmlBody string) error {
	if m.cfg.Host == "" {
		return fmt.Errorf("SMTP host is not configured")
	}
	if len(to) == 0 {
		return fmt.Errorf("recipient email address list is empty")
	}

	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	fromHeader := fmt.Sprintf("%s <%s>", m.cfg.FromName, m.cfg.FromAddress)
	toHeader := strings.Join(to, ", ")

	boundary := fmt.Sprintf("bnd_%d_%d", time.Now().UnixNano(), m.cfg.Port)

	// Build MIME multipart message
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", fromHeader))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", toHeader))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString("\r\n")

	// Text Part
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	msg.WriteString(textBody)
	msg.WriteString("\r\n\r\n")

	// HTML Part
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	msg.WriteString(htmlBody)
	msg.WriteString("\r\n\r\n")

	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	rawBytes := []byte(msg.String())

	// Connect according to encryption mode
	tlsConfig := &tls.Config{
		InsecureSkipVerify: m.cfg.InsecureSkipVerify,
		ServerName:         m.cfg.Host,
	}

	if m.cfg.Encryption == "SSL/TLS" {
		// Port 465 direct TLS dial
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: m.cfg.Timeout}, "tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tls dial to smtp (%s): %w", addr, err)
		}
		defer conn.Close()

		c, err := smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			return fmt.Errorf("smtp handshake: %w", err)
		}
		defer c.Quit()

		if m.cfg.Username != "" && m.cfg.Password != "" {
			auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth failed: %w", err)
			}
		}

		if err := c.Mail(m.cfg.FromAddress); err != nil {
			return err
		}
		for _, recipient := range to {
			if err := c.Rcpt(recipient); err != nil {
				return err
			}
		}

		w, err := c.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write(rawBytes); err != nil {
			return err
		}
		return w.Close()
	}

	// Plain or STARTTLS (e.g. port 25 or 587)
	conn, err := net.DialTimeout("tcp", addr, m.cfg.Timeout)
	if err != nil {
		return fmt.Errorf("dialing smtp (%s): %w", addr, err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client error: %w", err)
	}
	defer c.Quit()

	if m.cfg.Encryption == "STARTTLS" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("starttls negotiation failed: %w", err)
			}
		}
	}

	if m.cfg.Username != "" && m.cfg.Password != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp authentication failed: %w", err)
		}
	}

	if err := c.Mail(m.cfg.FromAddress); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := c.Rcpt(recipient); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(rawBytes); err != nil {
		return err
	}
	return w.Close()
}

// SendTestEmail sends a quick diagnostic message to confirm delivery
func (m *Mailer) SendTestEmail(to string) error {
	subject := "[Valtrivo SIEM] SMTP Integration Test"
	textBody := fmt.Sprintf("Valtrivo LogSeal SIEM SMTP test succeeded.\nTimestamp: %s\nHost: %s:%d\nMode: %s\n",
		time.Now().Format(time.RFC3339), m.cfg.Host, m.cfg.Port, m.cfg.Encryption)

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f1f5f9; margin: 0; padding: 24px; }
  .card { max-width: 560px; margin: 0 auto; background: #161f30; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }
  h2 { margin: 12px 0; color: #fff; font-size: 20px; }
  p { color: #94a3b8; line-height: 1.6; font-size: 14px; }
  .meta { background: #0f172a; padding: 12px 16px; border-radius: 8px; font-family: monospace; font-size: 13px; color: #cbd5e1; margin-top: 16px; }
</style>
</head>
<body>
  <div class="card">
    <span class="badge">SMTP READY</span>
    <h2>Valtrivo LogSeal SIEM &bull; Mail Dispatch Verification</h2>
    <p>This confirmation confirms that SMTP transmission is correctly configured and operational on your Valtrivo LogSeal cluster.</p>
    <div class="meta">
      Server: %s:%d<br>
      Encryption: %s<br>
      Timestamp: %s
    </div>
  </div>
</body>
</html>`, m.cfg.Host, m.cfg.Port, m.cfg.Encryption, time.Now().Format("2006-01-02 15:04:05 MST"))

	return m.SendRawEmail([]string{to}, subject, textBody, htmlBody)
}

// SendAlertAssignmentEmail sends an incident task assignment notification to an analyst
func (m *Mailer) SendAlertAssignmentEmail(to string, alert *models.SIEMAlert, assignedBy string) error {
	if !m.cfg.Enabled || !m.cfg.NotifyOnAssignment {
		return nil
	}
	if to == "" {
		return fmt.Errorf("no email address for assigned analyst")
	}

	severityColor := "#ef4444" // CRITICAL
	if alert.Severity == "HIGH" {
		severityColor = "#f97316"
	} else if alert.Severity == "MEDIUM" {
		severityColor = "#eab308"
	} else if alert.Severity == "LOW" {
		severityColor = "#3b82f6"
	}

	subject := fmt.Sprintf("[SIEM Task Assignment] [%s] %s", alert.Severity, alert.RuleName)
	portalLink := fmt.Sprintf("%s/#siem", m.cfg.PortalURL)

	textBody := fmt.Sprintf("SIEM Incident Assigned to You\n\nRule: %s\nSeverity: %s (Risk: %d)\nAssigned by: %s\nStatus: %s\nSource IP: %s\nDestination IP: %s\nSummary: %s\n\nInspect: %s\n",
		alert.RuleName, alert.Severity, alert.RiskScore, assignedBy, alert.Status, alert.SourceIP, alert.DestinationIP, alert.Summary, portalLink)

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; margin: 0; padding: 24px; }
  .card { max-width: 620px; margin: 0 auto; background: #161f30; border: 1px solid rgba(255,255,255,0.12); border-radius: 12px; padding: 32px; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; color: #fff; background: %s; }
  h2 { margin: 12px 0 6px 0; color: #fff; font-size: 20px; }
  p.lead { color: #94a3b8; font-size: 14px; margin-top: 0; }
  .table-box { width: 100%%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }
  .table-box td { padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.06); }
  .table-box td.label { color: #64748b; font-weight: 600; width: 35%%; }
  .table-box td.val { color: #f8fafc; font-weight: 500; }
  .summary-box { background: #0f172a; border-left: 3px solid %s; padding: 14px 18px; border-radius: 0 8px 8px 0; color: #cbd5e1; font-size: 13px; margin: 18px 0; line-height: 1.5; }
  .btn { display: inline-block; background: #4f46e5; color: #ffffff !important; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; }
  .footer { font-size: 11px; color: #64748b; margin-top: 24px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px; }
</style>
</head>
<body>
  <div class="card">
    <span class="badge">%s SEVERITY &bull; RISK %d</span>
    <h2>Security Incident Assigned to You</h2>
    <p class="lead">You have been designated as lead analyst for investigating this SIEM detection incident.</p>
    
    <div class="summary-box">
      <strong>Incident Summary:</strong><br>
      %s
    </div>

    <table class="table-box">
      <tr><td class="label">Detection Rule</td><td class="val"><strong>%s</strong></td></tr>
      <tr><td class="label">Assigned By</td><td class="val">%s</td></tr>
      <tr><td class="label">Triggered At</td><td class="val">%s</td></tr>
      <tr><td class="label">Source IP</td><td class="val"><code>%s</code></td></tr>
      <tr><td class="label">Destination IP</td><td class="val"><code>%s</code></td></tr>
      <tr><td class="label">MITRE ATT&amp;CK</td><td class="val">%s (%s)</td></tr>
      <tr><td class="label">Event Count</td><td class="val">%d events</td></tr>
    </table>

    <div style="margin-top: 24px; text-align: center;">
      <a href="%s" class="btn">Open Investigation Triage</a>
    </div>

    <div class="footer">
      Valtrivo LogSeal SIEM Automated Task Dispatch &bull; Law No. 5651 Compliant
    </div>
  </div>
</body>
</html>`, severityColor, severityColor, alert.Severity, alert.RiskScore, alert.Summary, alert.RuleName, assignedBy,
		alert.LastSeen.Format("2006-01-02 15:04:05 MST"), alert.SourceIP, alert.DestinationIP, alert.MitreTactic, alert.MitreTechnique, alert.EventCount, portalLink)

	return m.SendRawEmail([]string{to}, subject, textBody, htmlBody)
}

// SendCriticalAlertEmail broadcasts a high-priority notice to SOC broadcast list
func (m *Mailer) SendCriticalAlertEmail(alert *models.SIEMAlert) error {
	if !m.cfg.Enabled || !m.cfg.NotifyOnCritical || len(m.cfg.NotificationRecipients) == 0 {
		return nil
	}

	subject := fmt.Sprintf("[CRITICAL SIEM ALERT] %s - %s", alert.RuleName, alert.SourceIP)
	portalLink := fmt.Sprintf("%s/#siem", m.cfg.PortalURL)

	textBody := fmt.Sprintf("CRITICAL SIEM ALERT TRIGGERED\n\nRule: %s\nRisk Score: %d\nSource: %s\nDestination: %s\nSummary: %s\n\nTriage: %s\n",
		alert.RuleName, alert.RiskScore, alert.SourceIP, alert.DestinationIP, alert.Summary, portalLink)

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px; }
  .card { max-width: 620px; margin: 0 auto; background: #161f30; border: 1px solid #ef4444; border-radius: 12px; padding: 28px; }
  .badge { background: #ef4444; color: #fff; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 12px; }
  h2 { color: #fca5a5; margin: 10px 0; }
  .btn { display: inline-block; background: #ef4444; color: #fff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 16px; }
</style>
</head>
<body>
  <div class="card">
    <span class="badge">CRITICAL INCIDENT</span>
    <h2>Immediate SOC Attention Required</h2>
    <p>A Critical correlation rule has reached trigger threshold: <strong>%s</strong></p>
    <p>Summary: %s</p>
    <p>Source IP: <code>%s</code> &bull; Destination IP: <code>%s</code> &bull; Events: %d</p>
    <a href="%s" class="btn">View Live Incident Stream</a>
  </div>
</body>
</html>`, alert.RuleName, alert.Summary, alert.SourceIP, alert.DestinationIP, alert.EventCount, portalLink)

	return m.SendRawEmail(m.cfg.NotificationRecipients, subject, textBody, htmlBody)
}
