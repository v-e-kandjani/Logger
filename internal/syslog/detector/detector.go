package detector

import (
	"fmt"
	"regexp"
	"strings"
)

// DetectionResult represents the outcome of an automated device type discovery
type DetectionResult struct {
	Vendor         string `json:"vendor"`
	DeviceType     string `json:"device_type"`
	Hostname       string `json:"hostname,omitempty"`
	Confidence     string `json:"confidence"` // HIGH, MEDIUM, LOW
	SuggestedGroup string `json:"suggested_group"`
	SuggestedName  string `json:"suggested_name"`
}

var (
	ciscoCodeRegex    = regexp.MustCompile(`%([A-Z0-9_]+)-[0-7]-([A-Z0-9_]+)`)
	fortiDevNameRegex = regexp.MustCompile(`devname="?([^"\s,]+)"?`)
	wgMsgIDRegex      = regexp.MustCompile(`msg_id="?([^"\s,]+)"?`)
	winEventIDRegex   = regexp.MustCompile(`(?i)(?:EventID|Event ID)[:=\s]+([0-9]{3,5})`)
	hostRegex         = regexp.MustCompile(`(?i)(?:host|hostname)="?([^"\s,]+)"?`)
)

// Detect analyzes raw syslog message bodies, hostnames, and application headers to fingerprint device type and vendor
func Detect(rawMessage, hostname, appName string) DetectionResult {
	lowerRaw := strings.ToLower(rawMessage)
	lowerHost := strings.ToLower(hostname)
	lowerApp := strings.ToLower(appName)

	res := DetectionResult{
		Vendor:         "Generic",
		DeviceType:     "Generic Syslog",
		Confidence:     "LOW",
		SuggestedGroup: "Default Assets",
	}

	// Extract potential embedded hostname
	detectedHost := ""
	if hostname != "" && !isIPAddress(hostname) {
		detectedHost = hostname
	} else if m := fortiDevNameRegex.FindStringSubmatch(rawMessage); len(m) > 1 {
		detectedHost = m[1]
	} else if m := hostRegex.FindStringSubmatch(rawMessage); len(m) > 1 && !isIPAddress(m[1]) {
		detectedHost = m[1]
	}
	res.Hostname = detectedHost

	// 1. FORTINET (FortiGate / FortiAnalyzer / FortiSwitch / FortiMail)
	if strings.Contains(lowerRaw, "devname=") ||
		strings.Contains(lowerRaw, "fortigate") ||
		strings.Contains(lowerHost, "fortigate") ||
		strings.Contains(lowerRaw, "type=\"traffic\"") ||
		strings.Contains(lowerRaw, "type=\"utm\"") ||
		strings.Contains(lowerRaw, "type=\"event\"") && strings.Contains(lowerRaw, "forti") {

		res.Vendor = "Fortinet"
		res.Confidence = "HIGH"

		if strings.Contains(lowerRaw, "fortiswitch") || strings.Contains(lowerHost, "fsw") {
			res.DeviceType = "Switch"
			res.SuggestedGroup = "Core Switches & Routers"
		} else if strings.Contains(lowerRaw, "fortianalyzer") || strings.Contains(lowerHost, "faz") {
			res.DeviceType = "Server"
			res.SuggestedGroup = "Datacenter Servers"
		} else if strings.Contains(lowerRaw, "fortimail") {
			res.DeviceType = "Server"
			res.SuggestedGroup = "Datacenter Servers"
		} else {
			res.DeviceType = "Firewall"
			res.SuggestedGroup = "Perimeter Firewalls"
		}
		return res
	}

	// 2. WATCHGUARD (Firebox / Fireware FW)
	if strings.Contains(lowerHost, "watchguard") ||
		strings.Contains(lowerHost, "firebox") ||
		strings.Contains(lowerHost, "xtm") ||
		strings.Contains(lowerRaw, "watchguard") ||
		strings.Contains(lowerRaw, "firebox") ||
		strings.Contains(lowerRaw, "fireware") ||
		strings.Contains(lowerRaw, "disp=\"deny\"") ||
		strings.Contains(lowerRaw, "disp=\"allow\"") ||
		strings.Contains(lowerRaw, "disp=\"drop\"") ||
		wgMsgIDRegex.MatchString(rawMessage) {

		res.Vendor = "WatchGuard"
		res.DeviceType = "Firewall"
		res.Confidence = "HIGH"
		res.SuggestedGroup = "Perimeter Firewalls"
		return res
	}

	// 3. CISCO SYSTEMS (ASA, FTD, Catalyst, Nexus, IOS-XE, WLC)
	if ciscoCode := ciscoCodeRegex.FindStringSubmatch(rawMessage); len(ciscoCode) > 1 ||
		strings.Contains(rawMessage, "%ASA-") ||
		strings.Contains(rawMessage, "%FTD-") ||
		strings.Contains(rawMessage, "%IOS-") ||
		strings.Contains(rawMessage, "%LINK-") ||
		strings.Contains(rawMessage, "%SYS-") ||
		strings.Contains(rawMessage, "%LINEPROTO-") ||
		strings.Contains(rawMessage, "%DOT11-") ||
		strings.Contains(lowerRaw, "cisco") ||
		strings.Contains(lowerHost, "cisco") {

		res.Vendor = "Cisco"
		code := ""
		if len(ciscoCode) > 1 {
			code = ciscoCode[1]
		}

		if strings.Contains(rawMessage, "%ASA-") || strings.Contains(rawMessage, "%FTD-") || code == "ASA" || code == "FTD" {
			res.DeviceType = "Firewall"
			res.Confidence = "HIGH"
			res.SuggestedGroup = "Perimeter Firewalls"
		} else if strings.Contains(rawMessage, "%LINK-") || strings.Contains(rawMessage, "%LINEPROTO-") ||
			strings.Contains(rawMessage, "%SPANTREE-") || strings.Contains(rawMessage, "%ETHPORT-") ||
			code == "ETHPORT" || code == "SW_DAI" || code == "PORT_SECURITY" ||
			strings.Contains(lowerRaw, "catalyst") || strings.Contains(lowerRaw, "nexus") ||
			strings.Contains(lowerHost, "cat") || strings.Contains(lowerHost, "sw-") {
			res.DeviceType = "Switch"
			res.Confidence = "HIGH"
			res.SuggestedGroup = "Core Switches & Routers"
		} else if strings.Contains(rawMessage, "%DOT11-") || strings.Contains(rawMessage, "%WLAN-") ||
			strings.Contains(lowerRaw, "aironet") || strings.Contains(lowerHost, "wlc") {
			res.DeviceType = "Wireless Controller"
			res.Confidence = "HIGH"
			res.SuggestedGroup = "Edge / Branch Office"
		} else if strings.Contains(rawMessage, "%BGP-") || strings.Contains(rawMessage, "%OSPF-") ||
			strings.Contains(rawMessage, "%IP_ROUTING-") || strings.Contains(lowerHost, "rtr") || strings.Contains(lowerHost, "router") {
			res.DeviceType = "Router"
			res.Confidence = "HIGH"
			res.SuggestedGroup = "Core Switches & Routers"
		} else {
			res.DeviceType = "Router"
			res.Confidence = "MEDIUM"
			res.SuggestedGroup = "Core Switches & Routers"
		}
		return res
	}

	// 4. PALO ALTO NETWORKS (PAN-OS / Next-Gen Firewall)
	if strings.Contains(rawMessage, ",TRAFFIC,") ||
		strings.Contains(rawMessage, ",THREAT,") ||
		strings.Contains(rawMessage, ",SYSTEM,") && strings.Contains(lowerRaw, "pan-os") ||
		strings.Contains(lowerHost, "pa-") ||
		strings.Contains(lowerRaw, "palo alto") {

		res.Vendor = "Palo Alto"
		res.DeviceType = "Firewall"
		res.Confidence = "HIGH"
		res.SuggestedGroup = "Perimeter Firewalls"
		return res
	}

	// 5. MIKROTIK (RouterOS / Cloud Router Switch)
	if strings.Contains(lowerRaw, "mikrotik") ||
		strings.Contains(lowerHost, "mikrotik") ||
		strings.Contains(lowerRaw, "system,info") ||
		strings.Contains(lowerRaw, "system,error") ||
		strings.Contains(lowerRaw, "firewall,info") ||
		strings.Contains(lowerRaw, "dhcp,info") ||
		strings.Contains(lowerRaw, "ip,route") {

		res.Vendor = "MikroTik"
		res.Confidence = "HIGH"
		if strings.Contains(lowerRaw, "crs") || strings.Contains(lowerHost, "switch") {
			res.DeviceType = "Switch"
			res.SuggestedGroup = "Core Switches & Routers"
		} else if strings.Contains(lowerRaw, "firewall") {
			res.DeviceType = "Firewall"
			res.SuggestedGroup = "Perimeter Firewalls"
		} else {
			res.DeviceType = "Router"
			res.SuggestedGroup = "Core Switches & Routers"
		}
		return res
	}

	// 6. PFSENSE / OPNSENSE (FreeBSD Packet Filter Firewalls)
	if strings.Contains(lowerRaw, "filterlog:") ||
		strings.Contains(lowerRaw, "pfsense") ||
		strings.Contains(lowerHost, "pfsense") ||
		strings.Contains(lowerRaw, "opnsense") ||
		strings.Contains(lowerHost, "opnsense") {

		if strings.Contains(lowerRaw, "opnsense") || strings.Contains(lowerHost, "opnsense") {
			res.Vendor = "OPNsense"
		} else {
			res.Vendor = "pfSense"
		}
		res.DeviceType = "Firewall"
		res.Confidence = "HIGH"
		res.SuggestedGroup = "Perimeter Firewalls"
		return res
	}

	// 7. HPE ARUBA (ProCurve / ArubaOS / Instant AP)
	if strings.Contains(lowerRaw, "aruba") ||
		strings.Contains(lowerHost, "aruba") ||
		strings.Contains(lowerRaw, "procurve") ||
		strings.Contains(lowerRaw, "arubaos") ||
		strings.Contains(lowerRaw, "authmgr[") ||
		strings.Contains(lowerRaw, "wms[") {

		res.Vendor = "HPE Aruba"
		res.Confidence = "HIGH"
		if strings.Contains(lowerRaw, "authmgr") || strings.Contains(lowerRaw, "wms") || strings.Contains(lowerRaw, "iap") {
			res.DeviceType = "Wireless Controller"
			res.SuggestedGroup = "Edge / Branch Office"
		} else {
			res.DeviceType = "Switch"
			res.SuggestedGroup = "Core Switches & Routers"
		}
		return res
	}

	// 8. JUNIPER NETWORKS (Junos / SRX / EX / MX)
	if strings.Contains(lowerRaw, "junos") ||
		strings.Contains(lowerHost, "junos") ||
		strings.Contains(lowerRaw, "rpd[") ||
		strings.Contains(lowerRaw, "chassisd[") ||
		strings.Contains(lowerRaw, "eswd[") ||
		strings.Contains(lowerHost, "srx") ||
		strings.Contains(lowerHost, "juniper") {

		res.Vendor = "Juniper"
		res.Confidence = "HIGH"
		if strings.Contains(lowerHost, "srx") || strings.Contains(lowerRaw, "rt_flow") {
			res.DeviceType = "Firewall"
			res.SuggestedGroup = "Perimeter Firewalls"
		} else if strings.Contains(lowerHost, "ex") || strings.Contains(lowerRaw, "eswd") {
			res.DeviceType = "Switch"
			res.SuggestedGroup = "Core Switches & Routers"
		} else {
			res.DeviceType = "Router"
			res.SuggestedGroup = "Core Switches & Routers"
		}
		return res
	}

	// 9. SOPHOS (SFOS / XG / UTM)
	if strings.Contains(lowerRaw, "device_name=\"sfos\"") ||
		strings.Contains(lowerRaw, "sophos") ||
		strings.Contains(lowerHost, "sophos") ||
		strings.Contains(lowerHost, "xg-") {

		res.Vendor = "Sophos"
		res.DeviceType = "Firewall"
		res.Confidence = "HIGH"
		res.SuggestedGroup = "Perimeter Firewalls"
		return res
	}

	// 10. CHECK POINT
	if strings.Contains(lowerRaw, "fw_subrule") ||
		strings.Contains(lowerRaw, "product=vpn-1") ||
		strings.Contains(lowerRaw, "checkpoint") ||
		strings.Contains(lowerHost, "cp-") {

		res.Vendor = "Check Point"
		res.DeviceType = "Firewall"
		res.Confidence = "HIGH"
		res.SuggestedGroup = "Perimeter Firewalls"
		return res
	}

	// 11. UBIQUITI (UniFi / EdgeMAX)
	if strings.Contains(lowerRaw, "unifi") ||
		strings.Contains(lowerHost, "unifi") ||
		strings.Contains(lowerRaw, "edgerouter") ||
		strings.Contains(lowerRaw, "edgeswitch") ||
		strings.Contains(lowerRaw, "hostapd:") && strings.Contains(lowerRaw, "u6") {

		res.Vendor = "Ubiquiti"
		res.Confidence = "HIGH"
		if strings.Contains(lowerRaw, "edgerouter") || strings.Contains(lowerRaw, "usg") {
			res.DeviceType = "Router"
			res.SuggestedGroup = "Core Switches & Routers"
		} else if strings.Contains(lowerRaw, "edgeswitch") || strings.Contains(lowerRaw, "usw") {
			res.DeviceType = "Switch"
			res.SuggestedGroup = "Core Switches & Routers"
		} else {
			res.DeviceType = "Wireless Controller"
			res.SuggestedGroup = "Edge / Branch Office"
		}
		return res
	}

	// 12. LINUX SERVERS & WORKSTATIONS
	if strings.Contains(lowerRaw, "sshd[") ||
		strings.Contains(lowerRaw, "systemd[") ||
		strings.Contains(lowerRaw, "sudo:") ||
		strings.Contains(lowerRaw, "kernel:") ||
		strings.Contains(lowerRaw, "crond[") ||
		strings.Contains(lowerRaw, "dockerd[") ||
		strings.Contains(lowerRaw, "pam_unix") ||
		strings.Contains(lowerApp, "systemd") ||
		strings.Contains(lowerApp, "sshd") ||
		strings.Contains(lowerApp, "dockerd") {

		res.Vendor = "Linux"
		res.DeviceType = "Server"
		res.Confidence = "HIGH"
		res.SuggestedGroup = "Datacenter Servers"
		return res
	}

	// 13. MICROSOFT WINDOWS (Active Directory / Windows Server)
	if strings.Contains(rawMessage, "Microsoft-Windows-Security-Auditing") ||
		strings.Contains(lowerRaw, "mswineventlog") ||
		strings.Contains(lowerRaw, "security-auditing") ||
		winEventIDRegex.MatchString(rawMessage) {

		res.Vendor = "Microsoft"
		res.DeviceType = "Server"
		res.Confidence = "HIGH"
		res.SuggestedGroup = "Datacenter Servers"
		return res
	}

	// 14. VMWARE ESXi (Hypervisor)
	if strings.Contains(lowerRaw, "vmkernel:") ||
		strings.Contains(lowerRaw, "hostd[") ||
		strings.Contains(lowerRaw, "vobd:") {

		res.Vendor = "VMware"
		res.DeviceType = "Server"
		res.Confidence = "HIGH"
		res.SuggestedGroup = "Datacenter Servers"
		return res
	}

	// 15. HEURISTICS & FACILITY FALLBACKS
	if strings.Contains(lowerApp, "firewall") || strings.Contains(lowerRaw, "iptables") || strings.Contains(lowerRaw, "nftables") || strings.Contains(lowerRaw, "ufw") {
		res.Vendor = "Linux"
		res.DeviceType = "Firewall"
		res.Confidence = "MEDIUM"
		res.SuggestedGroup = "Perimeter Firewalls"
		return res
	}

	if strings.Contains(lowerApp, "switch") || strings.Contains(lowerHost, "switch") {
		res.DeviceType = "Switch"
		res.Confidence = "LOW"
		res.SuggestedGroup = "Core Switches & Routers"
		return res
	}

	if strings.Contains(lowerApp, "router") || strings.Contains(lowerHost, "router") {
		res.DeviceType = "Router"
		res.Confidence = "LOW"
		res.SuggestedGroup = "Core Switches & Routers"
		return res
	}

	return res
}

// GenerateSuggestedName creates a descriptive, formatted asset name
func GenerateSuggestedName(ip string, res DetectionResult) string {
	cleanIP := strings.ReplaceAll(ip, ".", "-")
	cleanIP = strings.ReplaceAll(cleanIP, ":", "-")

	if res.Hostname != "" {
		return fmt.Sprintf("%s (%s)", res.Hostname, ip)
	}

	prefix := res.Vendor
	if prefix == "Generic" {
		prefix = "Device"
	}

	typeSuffix := "DEV"
	switch res.DeviceType {
	case "Firewall":
		typeSuffix = "FW"
	case "Switch":
		typeSuffix = "SW"
	case "Router":
		typeSuffix = "RTR"
	case "Server":
		typeSuffix = "SRV"
	case "Wireless Controller", "Access Point":
		typeSuffix = "WIFI"
	}

	return fmt.Sprintf("%s-%s-%s", prefix, typeSuffix, cleanIP)
}

func isIPAddress(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '.' && c != ':' {
			return false
		}
	}
	return true
}
