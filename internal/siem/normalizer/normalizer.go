package normalizer

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

var (
	// Regex patterns for extracting fields from common syslog formats
	reIPv4           = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reSSHFailed      = regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?([a-zA-Z0-9_\-\.]+) from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+)`)
	reSSHAccepted    = regexp.MustCompile(`Accepted (?:password|publickey) for ([a-zA-Z0-9_\-\.]+) from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+)`)
	reSudoFailed     = regexp.MustCompile(`sudo:.*authentication failure; logname=.*user=([a-zA-Z0-9_\-\.]+)`)
	reUserAdd        = regexp.MustCompile(`new user: name=([a-zA-Z0-9_\-\.]+)`)
	reWinEventID     = regexp.MustCompile(`(?i)(?:EventID|Event\[ID\]|ID)[=:\s]+(\d+)`)
)

// Normalizer converts vendor-specific LogEvents into vendor-neutral NormalizedEvents
type Normalizer struct{}

// NewNormalizer creates a new Normalizer instance
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// Normalize inspects a raw or partially parsed LogEvent and produces a standardized SIEM event
func (n *Normalizer) Normalize(event *models.LogEvent) *models.NormalizedEvent {
	norm := &models.NormalizedEvent{
		EventID:         uuid.New(),
		Timestamp:       event.EventTimestamp,
		ReceivedAt:      event.ReceivedAt,
		DeviceID:        event.DeviceID,
		DeviceName:      event.DeviceName,
		Vendor:          event.Vendor,
		Product:         event.Product,
		Severity:        event.Severity,
		RiskScore:       10,
		EventCategory:   "system",
		EventAction:     "general-activity",
		EventOutcome:    "unknown",
		Message:         event.Message,
		RawMessage:      event.RawMessage,
		Extra:           make(map[string]string),
	}

	if event.SourceIP != nil {
		norm.SourceIP = event.SourceIP.String()
	}
	norm.SourcePort = event.SourcePort

	// Identify vendor-specific normalization path
	vendorLower := strings.ToLower(event.Vendor)
	rawLower := strings.ToLower(event.RawMessage)

	switch {
	case strings.Contains(vendorLower, "fortinet") || strings.Contains(rawLower, "fortigate") || strings.Contains(rawLower, "devname="):
		n.normalizeFortinet(event, norm)
	case strings.Contains(vendorLower, "watchguard") || strings.Contains(rawLower, "firebox") || strings.Contains(rawLower, "msg_id="):
		n.normalizeWatchGuard(event, norm)
	case strings.Contains(vendorLower, "cisco") || strings.Contains(rawLower, "%asa-") || strings.Contains(rawLower, "%ios-"):
		n.normalizeCisco(event, norm)
	case strings.Contains(vendorLower, "linux") || strings.Contains(rawLower, "sshd") || strings.Contains(rawLower, "sudo:") || strings.Contains(rawLower, "pam_unix") || strings.Contains(rawLower, "password for "):
		n.normalizeLinuxAuth(event, norm)
	case strings.Contains(rawLower, "microsoft-windows") || strings.Contains(rawLower, "eventid") || strings.Contains(rawLower, "event[id]"):
		n.normalizeWindows(event, norm)
	default:
		n.normalizeGeneric(event, norm)
	}

	return norm
}

// normalizeFortinet parses key-value pairs typical of FortiGate UTM / Next-Gen firewalls
// Example: type=traffic subtype=forward action=deny srcip=192.168.1.50 dstip=10.0.0.1 srcport=54123 dstport=443 user="admin"
func (n *Normalizer) normalizeFortinet(event *models.LogEvent, norm *models.NormalizedEvent) {
	norm.Vendor = "Fortinet"
	norm.Product = "FortiGate"

	kv := parseKeyValuePairs(event.RawMessage)

	if src := kv["srcip"]; src != "" {
		norm.SourceIP = src
	}
	if dst := kv["dstip"]; dst != "" {
		norm.DestinationIP = dst
	}
	if sp, err := strconv.Atoi(kv["srcport"]); err == nil && sp > 0 {
		norm.SourcePort = uint16(sp)
	}
	if dp, err := strconv.Atoi(kv["dstport"]); err == nil && dp > 0 {
		norm.DestinationPort = uint16(dp)
	}
	if u := kv["user"]; u != "" {
		norm.Username = strings.Trim(u, "\"")
	}

	action := strings.ToLower(kv["action"])
	logType := strings.ToLower(kv["type"])
	subtype := strings.ToLower(kv["subtype"])

	switch {
	case logType == "utm" || subtype == "ips" || subtype == "virus" || subtype == "waf":
		norm.EventCategory = "threat"
		norm.EventAction = "malware-blocked"
		norm.EventOutcome = "blocked"
		norm.Severity = "CRITICAL"
		norm.RiskScore = 85
		norm.MitreTactic = "Initial Access"
		norm.MitreTechnique = "T1190"
	case action == "deny" || action == "block" || action == "drop":
		norm.EventCategory = "network"
		norm.EventAction = "connection-denied"
		norm.EventOutcome = "blocked"
		norm.Severity = "WARNING"
		norm.RiskScore = 30
		norm.MitreTactic = "Discovery"
		norm.MitreTechnique = "T1046"
	case action == "accept" || action == "allow" || action == "permit":
		norm.EventCategory = "network"
		norm.EventAction = "connection-allowed"
		norm.EventOutcome = "allowed"
		norm.Severity = "INFORMATIONAL"
		norm.RiskScore = 5
	case subtype == "auth" || strings.Contains(event.RawMessage, "login"):
		norm.EventCategory = "authentication"
		if action == "failed" || strings.Contains(strings.ToLower(event.RawMessage), "failed") {
			norm.EventAction = "login-failed"
			norm.EventOutcome = "failure"
			norm.Severity = "HIGH"
			norm.RiskScore = 65
			norm.MitreTactic = "Credential Access"
			norm.MitreTechnique = "T1110"
		} else {
			norm.EventAction = "login-success"
			norm.EventOutcome = "success"
			norm.Severity = "INFORMATIONAL"
			norm.RiskScore = 10
		}
	}
}

// normalizeWatchGuard parses WatchGuard Firebox logs
// Example: 2026-10-04T22:49:47 WatchGuard-Firebox firewall: disp="Deny" src="192.168.1.100" dst="10.0.0.1" src_port="41234" dst_port="22"
func (n *Normalizer) normalizeWatchGuard(event *models.LogEvent, norm *models.NormalizedEvent) {
	norm.Vendor = "WatchGuard"
	norm.Product = "Firebox"

	kv := parseKeyValuePairs(event.RawMessage)

	if src := kv["src"]; src != "" {
		norm.SourceIP = strings.Trim(src, "\"")
	}
	if dst := kv["dst"]; dst != "" {
		norm.DestinationIP = strings.Trim(dst, "\"")
	}
	if sp, err := strconv.Atoi(strings.Trim(kv["src_port"], "\"")); err == nil && sp > 0 {
		norm.SourcePort = uint16(sp)
	}
	if dp, err := strconv.Atoi(strings.Trim(kv["dst_port"], "\"")); err == nil && dp > 0 {
		norm.DestinationPort = uint16(dp)
	}
	if u := kv["user"]; u != "" {
		norm.Username = strings.Trim(u, "\"")
	}

	disp := strings.ToLower(strings.Trim(kv["disp"], "\""))
	rawLower := strings.ToLower(event.RawMessage)

	if disp == "deny" || disp == "drop" || strings.Contains(rawLower, " denied ") {
		norm.EventCategory = "network"
		norm.EventAction = "connection-denied"
		norm.EventOutcome = "blocked"
		norm.Severity = "WARNING"
		norm.RiskScore = 30
		norm.MitreTactic = "Discovery"
		norm.MitreTechnique = "T1046"
	} else if disp == "allow" {
		norm.EventCategory = "network"
		norm.EventAction = "connection-allowed"
		norm.EventOutcome = "allowed"
		norm.Severity = "INFORMATIONAL"
		norm.RiskScore = 5
	}

	if strings.Contains(rawLower, "login") || strings.Contains(rawLower, "auth") {
		norm.EventCategory = "authentication"
		if strings.Contains(rawLower, "fail") || strings.Contains(rawLower, "deny") {
			norm.EventAction = "login-failed"
			norm.EventOutcome = "failure"
			norm.Severity = "HIGH"
			norm.RiskScore = 65
			norm.MitreTactic = "Credential Access"
			norm.MitreTechnique = "T1110"
		} else {
			norm.EventAction = "login-success"
			norm.EventOutcome = "success"
			norm.Severity = "INFORMATIONAL"
			norm.RiskScore = 10
		}
	}
}

// normalizeCisco parses Cisco ASA and IOS syslog messages
// Example: %ASA-4-106023: Deny tcp src outside:198.51.100.1/4321 dst inside:10.0.0.5/80 by access-group
func (n *Normalizer) normalizeCisco(event *models.LogEvent, norm *models.NormalizedEvent) {
	norm.Vendor = "Cisco"
	norm.Product = "ASA/IOS"

	raw := event.RawMessage
	rawLower := strings.ToLower(raw)

	if strings.Contains(rawLower, "deny") || strings.Contains(rawLower, "dropped") {
		norm.EventCategory = "network"
		norm.EventAction = "connection-denied"
		norm.EventOutcome = "blocked"
		norm.Severity = "WARNING"
		norm.RiskScore = 30
		norm.MitreTactic = "Discovery"
		norm.MitreTechnique = "T1046"
	}

	if strings.Contains(rawLower, "%asa-6-605005") || strings.Contains(rawLower, "login permitted") {
		norm.EventCategory = "authentication"
		norm.EventAction = "login-success"
		norm.EventOutcome = "success"
		norm.Severity = "INFORMATIONAL"
		norm.RiskScore = 10
	} else if strings.Contains(rawLower, "%asa-6-605004") || strings.Contains(rawLower, "login failed") {
		norm.EventCategory = "authentication"
		norm.EventAction = "login-failed"
		norm.EventOutcome = "failure"
		norm.Severity = "HIGH"
		norm.RiskScore = 65
		norm.MitreTactic = "Credential Access"
		norm.MitreTechnique = "T1110"
	}

	// Extract IP addresses if found
	ips := reIPv4.FindAllString(raw, -1)
	if len(ips) > 0 && norm.SourceIP == "" {
		norm.SourceIP = ips[0]
	}
	if len(ips) > 1 {
		norm.DestinationIP = ips[1]
	}
}

// normalizeLinuxAuth parses OpenSSH, PAM, and Sudo authentication records
func (n *Normalizer) normalizeLinuxAuth(event *models.LogEvent, norm *models.NormalizedEvent) {
	norm.Vendor = "Linux"
	norm.Product = "OS/Auth"

	raw := event.RawMessage

	if matches := reSSHFailed.FindStringSubmatch(raw); len(matches) == 4 {
		norm.EventCategory = "authentication"
		norm.EventAction = "login-failed"
		norm.EventOutcome = "failure"
		norm.Username = matches[1]
		norm.SourceIP = matches[2]
		if port, err := strconv.Atoi(matches[3]); err == nil {
			norm.SourcePort = uint16(port)
		}
		norm.Severity = "HIGH"
		norm.RiskScore = 70
		norm.MitreTactic = "Credential Access"
		norm.MitreTechnique = "T1110"
		return
	}

	if matches := reSSHAccepted.FindStringSubmatch(raw); len(matches) == 4 {
		norm.EventCategory = "authentication"
		norm.EventAction = "login-success"
		norm.EventOutcome = "success"
		norm.Username = matches[1]
		norm.SourceIP = matches[2]
		if port, err := strconv.Atoi(matches[3]); err == nil {
			norm.SourcePort = uint16(port)
		}
		norm.Severity = "INFORMATIONAL"
		norm.RiskScore = 10
		return
	}

	if matches := reSudoFailed.FindStringSubmatch(raw); len(matches) == 2 {
		norm.EventCategory = "system"
		norm.EventAction = "privilege-escalation"
		norm.EventOutcome = "failure"
		norm.Username = matches[1]
		norm.Severity = "HIGH"
		norm.RiskScore = 75
		norm.MitreTactic = "Privilege Escalation"
		norm.MitreTechnique = "T1548.003"
		return
	}

	if matches := reUserAdd.FindStringSubmatch(raw); len(matches) == 2 {
		norm.EventCategory = "configuration"
		norm.EventAction = "account-created"
		norm.EventOutcome = "success"
		norm.Username = matches[1]
		norm.Severity = "MEDIUM"
		norm.RiskScore = 50
		norm.MitreTactic = "Persistence"
		norm.MitreTechnique = "T1136.001"
		return
	}

	// General fallback for Linux authentication
	rawLower := strings.ToLower(raw)
	if strings.Contains(rawLower, "failure") || strings.Contains(rawLower, "failed") {
		norm.EventCategory = "authentication"
		norm.EventAction = "login-failed"
		norm.EventOutcome = "failure"
		norm.Severity = "HIGH"
		norm.RiskScore = 60
		norm.MitreTactic = "Credential Access"
		norm.MitreTechnique = "T1110"
	}
}

// normalizeWindows parses Windows Event logs
// 4625: An account failed to log on
// 4624: An account was successfully logged on
// 4720: A user account was created
func (n *Normalizer) normalizeWindows(event *models.LogEvent, norm *models.NormalizedEvent) {
	norm.Vendor = "Microsoft"
	norm.Product = "Windows"

	raw := event.RawMessage
	rawLower := strings.ToLower(raw)

	if matches := reWinEventID.FindStringSubmatch(raw); len(matches) == 2 {
		eventID := matches[1]
		switch eventID {
		case "4625":
			norm.EventCategory = "authentication"
			norm.EventAction = "login-failed"
			norm.EventOutcome = "failure"
			norm.Severity = "HIGH"
			norm.RiskScore = 70
			norm.MitreTactic = "Credential Access"
			norm.MitreTechnique = "T1110"
		case "4624":
			norm.EventCategory = "authentication"
			norm.EventAction = "login-success"
			norm.EventOutcome = "success"
			norm.Severity = "INFORMATIONAL"
			norm.RiskScore = 10
		case "4720":
			norm.EventCategory = "configuration"
			norm.EventAction = "account-created"
			norm.EventOutcome = "success"
			norm.Severity = "MEDIUM"
			norm.RiskScore = 50
			norm.MitreTactic = "Persistence"
			norm.MitreTechnique = "T1136.001"
		}
	} else if strings.Contains(rawLower, "logon failed") || strings.Contains(rawLower, "login failed") {
		norm.EventCategory = "authentication"
		norm.EventAction = "login-failed"
		norm.EventOutcome = "failure"
		norm.Severity = "HIGH"
		norm.RiskScore = 65
		norm.MitreTactic = "Credential Access"
		norm.MitreTechnique = "T1110"
	}
}

// normalizeGeneric acts as fallback parser for any generic syslog line
func (n *Normalizer) normalizeGeneric(event *models.LogEvent, norm *models.NormalizedEvent) {
	rawLower := strings.ToLower(event.RawMessage)

	switch {
	case strings.Contains(rawLower, "denied") || strings.Contains(rawLower, "dropped") || strings.Contains(rawLower, "blocked"):
		norm.EventCategory = "network"
		norm.EventAction = "connection-denied"
		norm.EventOutcome = "blocked"
		norm.Severity = "WARNING"
		norm.RiskScore = 30
		norm.MitreTactic = "Discovery"
		norm.MitreTechnique = "T1046"
	case strings.Contains(rawLower, "failed password") || strings.Contains(rawLower, "login failed") || strings.Contains(rawLower, "authentication failure"):
		norm.EventCategory = "authentication"
		norm.EventAction = "login-failed"
		norm.EventOutcome = "failure"
		norm.Severity = "HIGH"
		norm.RiskScore = 65
		norm.MitreTactic = "Credential Access"
		norm.MitreTechnique = "T1110"
	case strings.Contains(rawLower, "login successful") || strings.Contains(rawLower, "accepted password"):
		norm.EventCategory = "authentication"
		norm.EventAction = "login-success"
		norm.EventOutcome = "success"
		norm.Severity = "INFORMATIONAL"
		norm.RiskScore = 10
	case strings.Contains(rawLower, "exploit") || strings.Contains(rawLower, "malware") || strings.Contains(rawLower, "trojan"):
		norm.EventCategory = "threat"
		norm.EventAction = "malware-blocked"
		norm.EventOutcome = "blocked"
		norm.Severity = "CRITICAL"
		norm.RiskScore = 90
		norm.MitreTactic = "Execution"
		norm.MitreTechnique = "T1204"
	}

	// Extract any IP address if not already set
	if norm.SourceIP == "" {
		if ips := reIPv4.FindAllString(event.RawMessage, -1); len(ips) > 0 {
			norm.SourceIP = ips[0]
			if len(ips) > 1 {
				norm.DestinationIP = ips[1]
			}
		}
	}
}

// parseKeyValuePairs splits key=value or key="value" strings into map
func parseKeyValuePairs(s string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Fields(s)
	for _, pair := range pairs {
		if idx := strings.IndexByte(pair, '='); idx > 0 {
			k := strings.ToLower(pair[:idx])
			v := strings.Trim(pair[idx+1:], "\"")
			result[k] = v
		}
	}
	return result
}
