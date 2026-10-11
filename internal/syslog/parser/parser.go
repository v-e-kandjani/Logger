package parser

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

var facilityMap = map[uint8]string{
	0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
	6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
	12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
	16: "local0", 17: "local1", 18: "local2", 19: "local3",
	20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

var severityMap = map[uint8]string{
	0: "EMERGENCY",
	1: "ALERT",
	2: "CRITICAL",
	3: "ERROR",
	4: "WARNING",
	5: "NOTICE",
	6: "INFORMATIONAL",
	7: "DEBUG",
}

// FacilityToString maps code to human readable name
func FacilityToString(code uint8) string {
	if name, ok := facilityMap[code]; ok {
		return name
	}
	return fmt.Sprintf("facility_%d", code)
}

// SeverityToString maps code to standard severity name
func SeverityToString(code uint8) string {
	if name, ok := severityMap[code]; ok {
		return name
	}
	return "UNKNOWN"
}

// Parser defines the syslog line parsing interface
type Parser interface {
	Parse(raw []byte, sourceIP net.IP, sourcePort uint16, proto string) (*models.LogEvent, error)
}

// UniversalSyslogParser handles RFC 3164, RFC 5424, and vendor fallback formats
type UniversalSyslogParser struct {
	nodeName string
}

// NewUniversalParser instantiates parser with collector node metadata
func NewUniversalParser(nodeName string) *UniversalSyslogParser {
	return &UniversalSyslogParser{nodeName: nodeName}
}

// Parse extracts PRI, headers, timestamps, and messages while guaranteeing raw_message retention
func (p *UniversalSyslogParser) Parse(raw []byte, sourceIP net.IP, sourcePort uint16, proto string) (*models.LogEvent, error) {
	now := time.Now().UTC()
	rawStr := strings.TrimSpace(string(raw))

	event := &models.LogEvent{
		InternalID:         uuid.New(),
		ReceivedAt:         now,
		EventTimestamp:     now,
		SourceIP:           sourceIP,
		SourcePort:         sourcePort,
		TransportProtocol:  proto,
		CollectorNode:      p.nodeName,
		RawMessage:         rawStr,
		FacilityCode:       1, // user fallback
		Facility:           "user",
		SeverityCode:       6, // info fallback
		Severity:           "INFORMATIONAL",
		ParserStatus:       "FAILED",
		IngestionTimestamp: now,
	}

	if len(rawStr) == 0 {
		event.Message = "<empty payload>"
		return event, nil
	}

	// 1. Extract PRI Header <PRIVAL>
	cursor := 0
	if rawStr[0] == '<' {
		endPri := strings.IndexByte(rawStr, '>')
		if endPri > 1 && endPri <= 5 {
			priVal, err := strconv.Atoi(rawStr[1:endPri])
			if err == nil && priVal >= 0 && priVal <= 191 {
				event.FacilityCode = uint8(priVal / 8)
				event.SeverityCode = uint8(priVal % 8)
				event.Facility = FacilityToString(event.FacilityCode)
				event.Severity = SeverityToString(event.SeverityCode)
				cursor = endPri + 1
			}
		}
	}

	remainder := strings.TrimSpace(rawStr[cursor:])

	// 2. Check for RFC 5424: starts with version number "1 "
	if strings.HasPrefix(remainder, "1 ") {
		if p.parseRFC5424(remainder[2:], event) {
			p.enrichVendorAndProduct(event)
			event.ParserStatus = "SUCCESS"
			return event, nil
		}
	}

	// 3. Fallback to RFC 3164 (BSD style: "Mmm dd hh:mm:ss hostname tag: msg")
	if p.parseRFC3164(remainder, event) {
		p.enrichVendorAndProduct(event)
		event.ParserStatus = "SUCCESS"
		return event, nil
	}

	// 4. WatchGuard Fireware Specific Syslog Parser:
	// Format: "2026-10-04T22:49:47 WatchGuard-Firebox ... msg_id=... Allow/Deny src=... dst=..."
	if p.parseWatchGuard(remainder, event) {
		p.enrichVendorAndProduct(event)
		event.ParserStatus = "SUCCESS"
		return event, nil
	}

	// 5. Vendor/Malformed Fallback: Preserve everything, tag status PARTIAL
	event.ParserStatus = "PARTIAL"
	event.Message = remainder
	if event.Hostname == "" {
		event.Hostname = sourceIP.String()
	}
	p.enrichVendorAndProduct(event)
	return event, nil
}

// WatchGuard Firebox parser:
// Handles ISO timestamps followed by WatchGuard hostname and key-value attributes (e.g. msg_id, src, dst, proto, etc.)
func (p *UniversalSyslogParser) parseWatchGuard(s string, event *models.LogEvent) bool {
	fields := strings.SplitN(s, " ", 3)
	if len(fields) < 2 {
		return false
	}

	// Parse WatchGuard timestamp: e.g. "2026-10-04T19:49:47" or "2026-10-04 19:49:47"
	t, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05", fields[0])
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", fields[0])
		}
	}

	if err != nil {
		return false
	}

	event.EventTimestamp = t.UTC()
	event.Hostname = fields[1]
	event.Vendor = "WatchGuard"
	event.Product = "Firebox"

	if len(fields) == 3 {
		msgPart := fields[2]
		event.Message = msgPart

		// Extract msg_id if present: "msg_id=1A00-0021" or "msg_id=\"3000-0148\""
		if idx := strings.Index(msgPart, "msg_id="); idx != -1 {
			idSub := msgPart[idx+7:]
			idSub = strings.Trim(idSub, "\"")
			endIdx := strings.IndexAny(idSub, " \"")
			if endIdx != -1 {
				event.MessageID = idSub[:endIdx]
			} else {
				event.MessageID = idSub
			}
		}

		// Extract process/process_id or disp: "firewall:" or "disp=\"Allow\""
		if idx := strings.Index(msgPart, "disp="); idx != -1 {
			dispSub := msgPart[idx+5:]
			dispSub = strings.Trim(dispSub, "\"")
			endIdx := strings.IndexAny(dispSub, " \"")
			if endIdx != -1 {
				event.ApplicationName = "Firewall (" + dispSub[:endIdx] + ")"
			}
		}
		if event.ApplicationName == "" {
			event.ApplicationName = "Fireware"
		}
	}

	return true
}

// enrichVendorAndProduct examines event headers and message signatures to detect WatchGuard and other major vendors
func (p *UniversalSyslogParser) enrichVendorAndProduct(event *models.LogEvent) {
	lowerHost := strings.ToLower(event.Hostname)
	lowerRaw := strings.ToLower(event.RawMessage)
	lowerApp := strings.ToLower(event.ApplicationName)

	// 1. WatchGuard Firebox / Fireware FW Detection
	isWG := strings.Contains(lowerHost, "watchguard") ||
		strings.Contains(lowerHost, "firebox") ||
		strings.Contains(lowerHost, "xtm") ||
		strings.Contains(lowerRaw, "watchguard") ||
		strings.Contains(lowerRaw, "firebox") ||
		strings.Contains(lowerRaw, "fireware") ||
		strings.Contains(event.RawMessage, "msg_id=\"3") ||
		strings.Contains(event.RawMessage, "msg_id=\"02") ||
		strings.Contains(event.RawMessage, "msg_id=\"3e") ||
		strings.Contains(event.RawMessage, "msg_id=\"1a") ||
		(strings.Contains(lowerApp, "firewall") && strings.Contains(event.RawMessage, "msg_id="))

	if isWG {
		if event.Vendor == "" || event.Vendor == "Generic" {
			event.Vendor = "WatchGuard"
		}
		if event.Product == "" || event.Product == "Unknown" {
			event.Product = "Firebox"
		}

		// Extract msg_id if not present
		if event.MessageID == "" {
			if idx := strings.Index(event.RawMessage, "msg_id="); idx != -1 {
				sub := event.RawMessage[idx+7:]
				sub = strings.Trim(sub, "\"")
				end := strings.IndexAny(sub, " \"")
				if end != -1 {
					event.MessageID = sub[:end]
				} else {
					event.MessageID = sub
				}
			}
		}

		// Extract WatchGuard action / disposition
		action := ""
		if idx := strings.Index(event.RawMessage, "disp=\""); idx != -1 {
			sub := event.RawMessage[idx+6:]
			end := strings.IndexByte(sub, '"')
			if end != -1 {
				action = sub[:end]
			}
		} else if strings.Contains(event.RawMessage, " Allow ") || strings.Contains(event.RawMessage, " allow ") {
			action = "Allow"
		} else if strings.Contains(event.RawMessage, " Deny ") || strings.Contains(event.RawMessage, " deny ") {
			action = "Deny"
		} else if strings.Contains(event.RawMessage, " Drop ") || strings.Contains(event.RawMessage, " drop ") {
			action = "Drop"
		}

		if action != "" {
			if event.ApplicationName == "" || strings.EqualFold(event.ApplicationName, "firewall") {
				event.ApplicationName = fmt.Sprintf("Firewall (%s)", action)
			}
		} else if event.ApplicationName == "" {
			event.ApplicationName = "Fireware"
		}
		return
	}

	// 2. Fortinet FortiGate Detection (FortiLens Synergy)
	if strings.Contains(lowerRaw, "devname=") || strings.Contains(lowerRaw, "fortigate") || strings.Contains(lowerHost, "fortigate") ||
		strings.Contains(lowerRaw, "type=utm") || strings.Contains(lowerRaw, "type=traffic") {
		if event.Vendor == "" || event.Vendor == "Generic" {
			event.Vendor = "Fortinet"
		}
		if event.Product == "" || event.Product == "Unknown" {
			event.Product = "FortiGate"
		}

		logType := extractKV(event.RawMessage, "type")
		subtype := extractKV(event.RawMessage, "subtype")
		action := extractKV(event.RawMessage, "action")
		threat := extractKV(event.RawMessage, "threat")
		if threat == "" {
			threat = extractKV(event.RawMessage, "attack")
		}
		if threat == "" {
			threat = extractKV(event.RawMessage, "virus")
		}

		if logType == "utm" {
			appName := "FortiGate UTM"
			if subtype != "" {
				appName += fmt.Sprintf(" [%s]", strings.ToUpper(subtype))
			}
			if threat != "" {
				appName += fmt.Sprintf(": %s", threat)
			}
			if action != "" {
				appName += fmt.Sprintf(" (%s)", strings.Title(action))
			}
			event.ApplicationName = appName
			if event.SeverityCode > 2 {
				event.SeverityCode = 2
				event.Severity = "CRITICAL"
			}
		} else if logType == "traffic" {
			appName := "FortiGate Traffic"
			if action != "" {
				appName += fmt.Sprintf(" (%s)", strings.Title(action))
			}
			event.ApplicationName = appName
			if action == "deny" || action == "drop" || action == "block" {
				if event.SeverityCode > 4 {
					event.SeverityCode = 4
					event.Severity = "WARNING"
				}
			}
		} else if logType == "event" && subtype == "vpn" {
			event.ApplicationName = "FortiGate VPN"
			if action != "" {
				event.ApplicationName += fmt.Sprintf(" (%s)", strings.Title(action))
			}
		} else if action != "" {
			event.ApplicationName = fmt.Sprintf("FortiGate (%s)", strings.Title(action))
		}
		return
	}

	// 3. Cisco IOS / NX-OS / ASA Detection (NetVault Synergy)
	if strings.Contains(event.RawMessage, "%ASA-") || strings.Contains(event.RawMessage, "%FTD-") || strings.Contains(event.RawMessage, "%IOS-") ||
		strings.Contains(event.RawMessage, "%SYS-") || strings.Contains(event.RawMessage, "%LINK-") || strings.Contains(event.RawMessage, "%SEC-") ||
		strings.Contains(event.RawMessage, "%LINEPROTO-") || strings.Contains(event.RawMessage, "%CDP-") || strings.Contains(event.RawMessage, "%OSPF-") ||
		strings.Contains(event.RawMessage, "%BGP-") {
		if event.Vendor == "" || event.Vendor == "Generic" {
			event.Vendor = "Cisco"
		}
		if event.Product == "" || event.Product == "Unknown" {
			if strings.Contains(event.RawMessage, "%ASA-") || strings.Contains(event.RawMessage, "%FTD-") {
				event.Product = "Cisco ASA/FTD"
			} else {
				event.Product = "Cisco IOS/NX-OS"
			}
		}
		if idx := strings.Index(event.RawMessage, "%"); idx != -1 {
			sub := event.RawMessage[idx+1:]
			end := strings.IndexAny(sub, ": ")
			if end != -1 {
				mnemonicPart := sub[:end]
				parts := strings.Split(mnemonicPart, "-")
				if len(parts) >= 3 {
					event.ApplicationName = "Cisco " + parts[0]
					event.MessageID = parts[2]
				}
			}
		}
		return
	}

	// 4. HPE Aruba OS / OS-CX Detection (NetVault Synergy)
	if strings.Contains(lowerRaw, "arubaos-cx") || strings.Contains(lowerRaw, "aruba") || strings.Contains(lowerHost, "aruba") ||
		strings.Contains(event.RawMessage, "%MODULE-") || strings.Contains(event.RawMessage, "%SYSTEM-") {
		if event.Vendor == "" || event.Vendor == "Generic" {
			event.Vendor = "HPE Aruba"
		}
		if event.Product == "" || event.Product == "Unknown" {
			event.Product = "ArubaOS-CX"
		}
		if event.ApplicationName == "" {
			event.ApplicationName = "Aruba Network"
		}
		return
	}

	// 5. Juniper Junos Detection (NetVault Synergy)
	if strings.Contains(lowerRaw, "junos") || strings.Contains(event.RawMessage, "RT_FLOW:") || strings.Contains(event.RawMessage, "RT_IDP:") ||
		strings.Contains(lowerHost, "juniper") || strings.Contains(lowerHost, "srx") || strings.Contains(lowerHost, "qfx") {
		if event.Vendor == "" || event.Vendor == "Generic" {
			event.Vendor = "Juniper"
		}
		if event.Product == "" || event.Product == "Unknown" {
			event.Product = "Junos OS"
		}
		if event.ApplicationName == "" {
			event.ApplicationName = "Junos RT"
		}
		return
	}

	// 6. Palo Alto Networks Detection
	if strings.Contains(event.RawMessage, "TRAFFIC,") || strings.Contains(lowerHost, "pa-") {
		if event.Vendor == "" || event.Vendor == "Generic" {
			event.Vendor = "Palo Alto"
		}
		if event.Product == "" || event.Product == "Unknown" {
			event.Product = "PAN-OS"
		}
		return
	}
}

// extractKV retrieves value for key= or key="value" from a string
func extractKV(s, key string) string {
	target := key + "="
	idx := strings.Index(s, target)
	if idx == -1 {
		return ""
	}
	sub := s[idx+len(target):]
	if len(sub) == 0 {
		return ""
	}
	if sub[0] == '"' {
		sub = sub[1:]
		if end := strings.IndexByte(sub, '"'); end != -1 {
			return sub[:end]
		}
		return sub
	}
	if end := strings.IndexAny(sub, " ,;\t\r\n"); end != -1 {
		return sub[:end]
	}
	return sub
}

// RFC 5424: TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
func (p *UniversalSyslogParser) parseRFC5424(s string, event *models.LogEvent) bool {
	fields := strings.SplitN(s, " ", 6)
	if len(fields) < 5 {
		return false
	}

	// Timestamp
	if fields[0] != "-" {
		if t, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			event.EventTimestamp = t.UTC()
		} else if t, err := time.Parse(time.RFC3339, fields[0]); err == nil {
			event.EventTimestamp = t.UTC()
		}
	}

	// Hostname
	if fields[1] != "-" {
		event.Hostname = fields[1]
	} else {
		event.Hostname = event.SourceIP.String()
	}

	// App-name
	if fields[2] != "-" {
		event.ApplicationName = fields[2]
	}

	// ProcID
	if fields[3] != "-" {
		event.ProcessID = fields[3]
	}

	// MsgID
	if fields[4] != "-" {
		event.MessageID = fields[4]
	}

	if len(fields) == 6 {
		msgPart := fields[5]
		// Structured Data check
		if strings.HasPrefix(msgPart, "[") {
			endSD := strings.Index(msgPart, "] ")
			if endSD != -1 {
				event.StructuredData = msgPart[:endSD+1]
				event.Message = strings.TrimSpace(msgPart[endSD+2:])
				return true
			}
		}
		event.Message = msgPart
	}

	return true
}

// RFC 3164: "Oct 04 22:24:16 myhost app[1234]: Something happened"
func (p *UniversalSyslogParser) parseRFC3164(s string, event *models.LogEvent) bool {
	if len(s) < 16 {
		return false
	}

	hasValidTimestamp := false

	// Try standard BSD timestamp: "Mmm dd hh:mm:ss"
	// Example: "Oct  4 22:24:16" or "Oct 04 22:24:16"
	tsStr := s[:15]
	currentYear := time.Now().Year()
	parsedTime, err := time.Parse("Jan _2 15:04:05", tsStr)
	if err == nil {
		event.EventTimestamp = time.Date(
			currentYear, parsedTime.Month(), parsedTime.Day(),
			parsedTime.Hour(), parsedTime.Minute(), parsedTime.Second(),
			0, time.UTC,
		)
		s = strings.TrimSpace(s[15:])
		hasValidTimestamp = true
	} else {
		// Alternative ISO timestamp prefix check
		firstSpace := strings.IndexByte(s, ' ')
		if firstSpace != -1 {
			if t, err := time.Parse(time.RFC3339, s[:firstSpace]); err == nil {
				event.EventTimestamp = t.UTC()
				s = strings.TrimSpace(s[firstSpace+1:])
				hasValidTimestamp = true
			}
		}
	}

	if !hasValidTimestamp {
		return false
	}

	// Next token: Hostname
	nextSpace := strings.IndexByte(s, ' ')
	if nextSpace != -1 {
		event.Hostname = s[:nextSpace]
		s = strings.TrimSpace(s[nextSpace+1:])
	} else {
		event.Hostname = event.SourceIP.String()
		event.Message = s
		return true
	}

	// Next token: Tag / AppName [PID]:
	colonIdx := strings.Index(s, ": ")
	if colonIdx != -1 {
		tag := s[:colonIdx]
		event.Message = s[colonIdx+2:]

		// Check for PID in brackets: "myapp[1234]"
		if openBracket := strings.IndexByte(tag, '['); openBracket != -1 {
			if closeBracket := strings.IndexByte(tag, ']'); closeBracket > openBracket {
				event.ApplicationName = tag[:openBracket]
				event.ProcessID = tag[openBracket+1 : closeBracket]
				return true
			}
		}
		event.ApplicationName = tag
		return true
	}

	event.Message = s
	return true
}
