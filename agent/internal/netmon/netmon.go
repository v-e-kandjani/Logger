package netmon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// SocketConnection holds normalized local/remote socket info before threat scoring
type SocketConnection struct {
	PID         int
	ProcessName string
	Protocol    string
	LocalIP     string
	LocalPort   int
	RemoteIP    string
	RemotePort  int
	State       string
	Direction   string
}

// BeaconTracker records timestamp history of outbound flows to detect C2 heartbeats
type BeaconTracker struct {
	RemoteIP      string
	RemotePort    int
	PID           int
	LastLocalPort int
	Timestamps    []time.Time
}

// Scanner performs socket enumeration, DNS inspection, DGA detection, and firewall enforcement
type Scanner struct {
	mu            sync.Mutex
	beaconHistory map[string]*BeaconTracker // key: "pid:ip:port"
	seenConns     map[string]time.Time     // deduplication cache
	seenDNS       map[string]time.Time     // deduplication cache
	blockedIPs    map[string]bool          // local firewall enforced cache
}

// NewScanner creates a new cross-platform network & DNS EDR collector
func NewScanner() *Scanner {
	return &Scanner{
		beaconHistory: make(map[string]*BeaconTracker),
		seenConns:     make(map[string]time.Time),
		seenDNS:       make(map[string]time.Time),
		blockedIPs:    make(map[string]bool),
	}
}

// CalculateShannonEntropy calculates information entropy of a string (excluding standard TLDs)
func CalculateShannonEntropy(domain string) float64 {
	domain = strings.TrimSpace(strings.ToLower(domain))
	parts := strings.Split(domain, ".")
	target := parts[0]
	if len(parts) > 1 && len(parts[0]) <= 3 {
		target = strings.Join(parts[:len(parts)-1], "")
	}
	if len(target) == 0 {
		return 0.0
	}

	charCounts := make(map[rune]int)
	for _, r := range target {
		charCounts[r]++
	}

	total := float64(len(target))
	var entropy float64
	for _, count := range charCounts {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return math.Round(entropy*100) / 100
}

// IsDGA evaluates if a domain name exhibits algorithmic generation characteristics
func IsDGA(domain string) (bool, float64) {
	entropy := CalculateShannonEntropy(domain)
	parts := strings.Split(strings.ToLower(domain), ".")
	name := parts[0]

	// High entropy (> 3.75) and sufficient length (> 11 chars)
	if len(name) >= 12 && entropy >= 3.75 {
		return true, entropy
	}

	// Consonant or digit density check for random hex/alphanumeric strings
	consonantsAndDigits := 0
	for _, c := range name {
		if (c >= '0' && c <= '9') || (c >= 'b' && c <= 'z' && !strings.ContainsRune("aeiou", c)) {
			consonantsAndDigits++
		}
	}
	if len(name) >= 12 && float64(consonantsAndDigits)/float64(len(name)) > 0.80 && entropy >= 3.2 {
		return true, entropy
	}

	return false, entropy
}

// IsPrivateIP checks if an IP belongs to RFC 1918 or loopback addresses
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// RFC 1918
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return false
}

// Scan collects active sockets, audits DNS activity, detects C2 beaconing, and enforces policies
func (s *Scanner) Scan(policy *models.EndpointPolicyConfig) ([]models.EndpointNetworkConnection, []models.EndpointDNSQuery) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	// 1. Purge expired cache entries (older than 15 minutes)
	for k, t := range s.seenConns {
		if now.Sub(t) > 15*time.Minute {
			delete(s.seenConns, k)
		}
	}
	for k, t := range s.seenDNS {
		if now.Sub(t) > 15*time.Minute {
			delete(s.seenDNS, k)
		}
	}
	for k, b := range s.beaconHistory {
		if len(b.Timestamps) > 0 && now.Sub(b.Timestamps[len(b.Timestamps)-1]) > 30*time.Minute {
			delete(s.beaconHistory, k)
		}
	}

	var connResults []models.EndpointNetworkConnection
	var dnsResults []models.EndpointDNSQuery

	// 2. Enumerate sockets if NetMon is enabled
	if policy == nil || policy.EDRNetMonEnabled {
		rawSockets := s.enumerateSockets()
		for _, sock := range rawSockets {
			conn := s.evaluateSocketThreat(sock, policy, now)
			if conn != nil {
				connResults = append(connResults, *conn)
			}
		}
	}

	// 3. Inspect DNS cache / queries if DNS audit is enabled
	if policy == nil || policy.EDRDNSAuditEnabled {
		rawDNS := s.enumerateDNS()
		for _, q := range rawDNS {
			evaluated := s.evaluateDNSThreat(q, policy, now)
			if evaluated != nil {
				dnsResults = append(dnsResults, *evaluated)
			}
		}
	}

	return connResults, dnsResults
}

// evaluateSocketThreat inspects connection metadata, blocked ports/IPs, LOLBin processes, and C2 beaconing
func (s *Scanner) evaluateSocketThreat(sock SocketConnection, policy *models.EndpointPolicyConfig, now time.Time) *models.EndpointNetworkConnection {
	isPrivate := IsPrivateIP(sock.RemoteIP)
	isOutbound := sock.Direction == "outbound" && !isPrivate && sock.RemoteIP != ""

	severity := "info"
	reason := ""
	actionTaken := "allowed"

	// 1. Check prohibited ports (e.g. 4444, 1337, 6667, 8888, 31337)
	suspiciousPorts := map[int]bool{
		4444: true, 1337: true, 6667: true, 8888: true, 31337: true, 5555: true, 9999: true,
	}
	if policy != nil && len(policy.EDRBlockedPorts) > 0 {
		for _, p := range policy.EDRBlockedPorts {
			suspiciousPorts[p] = true
		}
	}
	if isOutbound && suspiciousPorts[sock.RemotePort] {
		severity = "critical"
		reason = fmt.Sprintf("Outbound connection to prohibited / suspicious C2 port %d", sock.RemotePort)
	}

	// 2. Check explicit blocked IPs from policy
	if isOutbound && policy != nil && len(policy.EDRBlockedIPs) > 0 {
		for _, bIP := range policy.EDRBlockedIPs {
			if strings.TrimSpace(bIP) == sock.RemoteIP {
				severity = "critical"
				reason = fmt.Sprintf("Outbound connection to policy-blocked malicious IP %s", sock.RemoteIP)
				if policy.EDRBlockMaliciousIPs {
					actionTaken = "blocked"
					s.enforceBlockIP(sock.RemoteIP, reason)
				}
				break
			}
		}
	}

	// 3. Check LOLBins or Script Engines initiating outbound direct external TCP connections
	procLower := strings.ToLower(sock.ProcessName)
	scriptEngines := map[string]bool{
		"powershell.exe": true, "cmd.exe": true, "cscript.exe": true, "wscript.exe": true,
		"mshta.exe": true, "certutil.exe": true, "bitsadmin.exe": true, "rundll32.exe": true,
		"regsvr32.exe": true, "bash": true, "sh": true, "python": true, "python3": true,
		"perl": true, "ruby": true, "nc": true, "netcat": true,
	}
	if isOutbound && scriptEngines[procLower] && severity != "critical" {
		if sock.RemotePort != 80 && sock.RemotePort != 443 {
			severity = "high"
			reason = fmt.Sprintf("Script engine / LOLBin '%s' connecting to external non-web port %s:%d", sock.ProcessName, sock.RemoteIP, sock.RemotePort)
		} else {
			severity = "medium"
			reason = fmt.Sprintf("Script engine '%s' connecting to external IP %s:%d", sock.ProcessName, sock.RemoteIP, sock.RemotePort)
		}
	}

	// 4. C2 Beaconing Detection (periodic regular intervals)
	if isOutbound && (policy == nil || policy.EDRDetectC2Beaconing) {
		// Ignore standard web browsers and OS system push notification services on standard web/push ports (443, 80, 5228, 8443)
		standardWebProcs := map[string]bool{
			"chrome.exe": true, "msedge.exe": true, "firefox.exe": true, "brave.exe": true,
			"opera.exe": true, "svchost.exe": true, "system": true, "chrome": true, "msedge": true, "firefox": true,
		}
		isStandardWebPort := (sock.RemotePort == 443 || sock.RemotePort == 80 || sock.RemotePort == 5228 || sock.RemotePort == 8443)
		isBrowserOrSystem := standardWebProcs[procLower]

		if !(isBrowserOrSystem && isStandardWebPort) {
			beaconKey := fmt.Sprintf("%d:%s:%d", sock.PID, sock.RemoteIP, sock.RemotePort)
			tracker, exists := s.beaconHistory[beaconKey]
			if !exists {
				tracker = &BeaconTracker{
					RemoteIP:   sock.RemoteIP,
					RemotePort: sock.RemotePort,
					PID:        sock.PID,
					Timestamps: []time.Time{now},
				}
				s.beaconHistory[beaconKey] = tracker
			} else {
				tracker.Timestamps = append(tracker.Timestamps, now)
				if len(tracker.Timestamps) > 10 {
					tracker.Timestamps = tracker.Timestamps[len(tracker.Timestamps)-10:]
				}

				// If at least 3 intervals exist, calculate delta variance
				if len(tracker.Timestamps) >= 3 {
					intervals := make([]float64, len(tracker.Timestamps)-1)
					for i := 0; i < len(intervals); i++ {
						intervals[i] = tracker.Timestamps[i+1].Sub(tracker.Timestamps[i]).Seconds()
					}
					// Compute average & standard deviation
					var sum float64
					for _, v := range intervals {
						sum += v
					}
					avg := sum / float64(len(intervals))

					var varianceSum float64
					for _, v := range intervals {
						varianceSum += math.Pow(v-avg, 2)
					}
					stdDev := math.Sqrt(varianceSum / float64(len(intervals)))

					// If regular beaconing pattern detected (low std deviation relative to avg interval)
					if avg >= 5.0 && avg <= 300.0 && stdDev <= 3.5 {
						severity = "critical"
						reason = fmt.Sprintf("Periodic C2 Beaconing pattern detected to %s:%d (avg interval: %.1fs, jitter variance: %.2fs)", sock.RemoteIP, sock.RemotePort, avg, stdDev)
						if policy != nil && policy.EDRBlockMaliciousIPs {
							actionTaken = "blocked"
							s.enforceBlockIP(sock.RemoteIP, reason)
						}
					}
				}
			}
		}
	}

	// Deduplication: Only report if new or severity elevated
	dedupKey := fmt.Sprintf("%s:%d:%s:%d:%s", sock.ProcessName, sock.PID, sock.RemoteIP, sock.RemotePort, severity)
	if last, ok := s.seenConns[dedupKey]; ok && now.Sub(last) < 5*time.Minute && severity == "info" {
		return nil
	}
	s.seenConns[dedupKey] = now

	return &models.EndpointNetworkConnection{
		ID:             uuid.New(),
		PID:            sock.PID,
		ProcessName:    sock.ProcessName,
		Protocol:       sock.Protocol,
		LocalIP:        sock.LocalIP,
		LocalPort:      sock.LocalPort,
		RemoteIP:       sock.RemoteIP,
		RemotePort:     sock.RemotePort,
		State:          sock.State,
		Direction:      sock.Direction,
		ThreatSeverity: severity,
		ThreatReason:   reason,
		ActionTaken:    actionTaken,
		Timestamp:      now,
		CreatedAt:      now,
	}
}

// evaluateDNSThreat evaluates DNS requests against DGA entropy, blocked domains, and blacklists
func (s *Scanner) evaluateDNSThreat(q models.EndpointDNSQuery, policy *models.EndpointPolicyConfig, now time.Time) *models.EndpointDNSQuery {
	domain := strings.TrimSpace(strings.ToLower(q.QueryDomain))
	if domain == "" || domain == "." || strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".arpa") {
		return nil
	}

	isDGA, entropy := IsDGA(domain)
	q.EntropyScore = entropy
	q.IsDGA = isDGA

	// 1. Check explicit blocked domains
	if policy != nil && len(policy.EDRBlockedDomains) > 0 {
		for _, bDomain := range policy.EDRBlockedDomains {
			bd := strings.TrimSpace(strings.ToLower(bDomain))
			if bd != "" && (domain == bd || strings.HasSuffix(domain, "."+bd)) {
				q.IsMalicious = true
				q.ThreatReason = fmt.Sprintf("Domain matches policy blocklist: %s", bd)
				q.ActionTaken = "blocked"
				break
			}
		}
	}

	// 2. DGA anomaly
	if q.IsDGA && (policy == nil || policy.EDRDetectDGA) {
		q.IsMalicious = true
		if q.ThreatReason == "" {
			q.ThreatReason = fmt.Sprintf("Algorithmic DGA domain characteristics detected (Shannon entropy: %.2f)", entropy)
		}
		if policy != nil && policy.EDRBlockMaliciousIPs {
			q.ActionTaken = "blocked"
		}
	}

	dedupKey := fmt.Sprintf("%s:%s:%t", q.ProcessName, domain, q.IsMalicious)
	if last, ok := s.seenDNS[dedupKey]; ok && now.Sub(last) < 5*time.Minute && !q.IsMalicious {
		return nil
	}
	s.seenDNS[dedupKey] = now

	if q.ID == uuid.Nil {
		q.ID = uuid.New()
	}
	if q.Timestamp.IsZero() {
		q.Timestamp = now
	}
	if q.CreatedAt.IsZero() {
		q.CreatedAt = now
	}
	if q.ActionTaken == "" {
		q.ActionTaken = "resolved"
	}

	return &q
}

// enforceBlockIP triggers the OS firewall to drop traffic to/from a malicious IP address
func (s *Scanner) enforceBlockIP(ip string, reason string) {
	if ip == "" || IsPrivateIP(ip) {
		return
	}
	if s.blockedIPs[ip] {
		return
	}
	s.blockedIPs[ip] = true

	go func(targetIP, r string) {
		log.Printf("[LOGGER NetMon] Micro-Isolation: Enforcing host firewall block on IP %s (%s)", targetIP, r)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		switch runtime.GOOS {
		case "windows":
			ruleName := fmt.Sprintf("LogSeal-EDR-Block-%s", targetIP)
			cmdOut := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s", ruleName), "dir=out", "action=block", fmt.Sprintf("remoteip=%s", targetIP))
			_ = cmdOut.Run()
			cmdIn := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s", ruleName), "dir=in", "action=block", fmt.Sprintf("remoteip=%s", targetIP))
			_ = cmdIn.Run()

		case "linux":
			// Try iptables block
			_ = exec.CommandContext(ctx, "iptables", "-I", "OUTPUT", "-d", targetIP, "-j", "DROP").Run()
			_ = exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-s", targetIP, "-j", "DROP").Run()

		case "darwin":
			// macOS pfctl packet filter rule can be applied or logged
			log.Printf("[LOGGER NetMon] macOS PF rule simulated block for %s", targetIP)
		}
	}(ip, reason)
}

// enumerateSockets parses open TCP/UDP sockets cross-platform
func (s *Scanner) enumerateSockets() []SocketConnection {
	var results []SocketConnection

	switch runtime.GOOS {
	case "windows":
		results = s.enumerateSocketsWindows()
	case "linux":
		results = s.enumerateSocketsLinux()
	case "darwin":
		results = s.enumerateSocketsDarwin()
	default:
		results = s.enumerateSocketsDarwin()
	}

	return results
}

// enumerateSocketsWindows parses Windows `netstat -ano -p tcp` and `-p udp`
func (s *Scanner) enumerateSocketsWindows() []SocketConnection {
	var list []SocketConnection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netstat", "-ano", "-p", "tcp")
	out, err := cmd.Output()
	if err != nil {
		return list
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) >= 5 && (fields[0] == "TCP" || fields[0] == "tcp") {
			localParts := splitHostPort(fields[1])
			remoteParts := splitHostPort(fields[2])
			state := fields[3]
			pid, _ := strconv.Atoi(fields[4])

			direction := "outbound"
			if state == "LISTENING" || remoteParts.Host == "0.0.0.0" || remoteParts.Port == 0 {
				direction = "listening"
			}

			list = append(list, SocketConnection{
				PID:         pid,
				ProcessName: resolveProcessName(pid),
				Protocol:    "tcp",
				LocalIP:     localParts.Host,
				LocalPort:   localParts.Port,
				RemoteIP:    remoteParts.Host,
				RemotePort:  remoteParts.Port,
				State:       state,
				Direction:   direction,
			})
		}
	}
	return list
}

// enumerateSocketsLinux parses Linux `ss -tuanp` or `netstat -tuanp`
func (s *Scanner) enumerateSocketsLinux() []SocketConnection {
	var list []SocketConnection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try ss first
	cmd := exec.CommandContext(ctx, "ss", "-tuanp")
	out, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		cmd = exec.CommandContext(ctx, "netstat", "-tuanp")
		out, err = cmd.Output()
	}
	if err != nil {
		return list
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}

		var localIdx, remoteIdx, procIdx int
		if fields[1] == "LISTEN" || fields[1] == "ESTAB" || fields[1] == "TIME-WAIT" {
			// ss style: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
			localIdx = 4
			remoteIdx = 5
			procIdx = 6
		} else {
			// netstat style: Proto Recv-Q Send-Q Local Foreign State PID/Program
			localIdx = 3
			remoteIdx = 4
			procIdx = 6
		}

		if len(fields) <= remoteIdx {
			continue
		}

		localParts := splitHostPort(fields[localIdx])
		remoteParts := splitHostPort(fields[remoteIdx])

		pid := 0
		procName := "system"
		if len(fields) > procIdx {
			procField := fields[procIdx]
			// e.g. users:(("curl",pid=1234,fd=3))
			if idx := strings.Index(procField, "pid="); idx != -1 {
				numStr := ""
				for _, ch := range procField[idx+4:] {
					if ch >= '0' && ch <= '9' {
						numStr += string(ch)
					} else {
						break
					}
				}
				pid, _ = strconv.Atoi(numStr)
			}
			if idxName := strings.Index(procField, `("`); idxName != -1 {
				end := strings.Index(procField[idxName+2:], `"`)
				if end != -1 {
					procName = procField[idxName+2 : idxName+2+end]
				}
			}
		}

		direction := "outbound"
		if remoteParts.Port == 0 || remoteParts.Host == "*" || remoteParts.Host == "0.0.0.0" {
			direction = "listening"
		}

		list = append(list, SocketConnection{
			PID:         pid,
			ProcessName: procName,
			Protocol:    proto,
			LocalIP:     localParts.Host,
			LocalPort:   localParts.Port,
			RemoteIP:    remoteParts.Host,
			RemotePort:  remoteParts.Port,
			State:       "ESTABLISHED",
			Direction:   direction,
		})
	}
	return list
}

// enumerateSocketsDarwin parses macOS `lsof -i -P -n`
func (s *Scanner) enumerateSocketsDarwin() []SocketConnection {
	var list []SocketConnection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lsof", "-i", "-P", "-n")
	out, err := cmd.Output()
	if err != nil {
		return list
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		// Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (STATE)
		if len(fields) >= 9 && (fields[4] == "IPv4" || fields[4] == "IPv6") {
			procName := fields[0]
			pid, _ := strconv.Atoi(fields[1])
			proto := strings.ToLower(fields[7])
			nameField := fields[8]

			state := "CONNECTED"
			if len(fields) >= 10 {
				state = strings.Trim(fields[9], "()")
			}

			// nameField is e.g. "192.168.1.100:54321->93.184.216.34:443" or "*:8080"
			if strings.Contains(nameField, "->") {
				parts := strings.Split(nameField, "->")
				loc := splitHostPort(parts[0])
				rem := splitHostPort(parts[1])
				list = append(list, SocketConnection{
					PID:         pid,
					ProcessName: procName,
					Protocol:    proto,
					LocalIP:     loc.Host,
					LocalPort:   loc.Port,
					RemoteIP:    rem.Host,
					RemotePort:  rem.Port,
					State:       state,
					Direction:   "outbound",
				})
			} else {
				loc := splitHostPort(nameField)
				list = append(list, SocketConnection{
					PID:         pid,
					ProcessName: procName,
					Protocol:    proto,
					LocalIP:     loc.Host,
					LocalPort:   loc.Port,
					RemoteIP:    "",
					RemotePort:  0,
					State:       state,
					Direction:   "listening",
				})
			}
		}
	}
	return list
}

// enumerateDNS collects recent DNS queries from system caches
func (s *Scanner) enumerateDNS() []models.EndpointDNSQuery {
	var list []models.EndpointDNSQuery
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch runtime.GOOS {
	case "windows":
		// Windows: Get-DnsClientCache via powershell
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-DnsClientCache | Select-Object -Property Entry,Data,Status -First 50 | ConvertTo-Json -Compress")
		out, err := cmd.Output()
		if err == nil && len(out) > 5 {
			// Basic domain extraction
			str := string(out)
			re := regexp.MustCompile(`"Entry":"([^"]+)"`)
			matches := re.FindAllStringSubmatch(str, -1)
			for _, m := range matches {
				if len(m) > 1 {
					list = append(list, models.EndpointDNSQuery{
						ID:          uuid.New(),
						ProcessName: "svchost.exe",
						QueryDomain: m[1],
						QueryType:   "A",
					})
				}
			}
		}

	case "darwin":
		// macOS: query local resolver cache via dscacheutil
		cmd := exec.CommandContext(ctx, "dscacheutil", "-cachedump", "-entries", "host")
		out, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "name:") {
					domain := strings.TrimSpace(strings.TrimPrefix(line, "name:"))
					if domain != "" && !strings.Contains(domain, "localhost") {
						list = append(list, models.EndpointDNSQuery{
							ID:          uuid.New(),
							ProcessName: "mDNSResponder",
							QueryDomain: domain,
							QueryType:   "A",
						})
					}
				}
			}
		}
	}

	return list
}

type hostPort struct {
	Host string
	Port int
}

func splitHostPort(addr string) hostPort {
	addr = strings.TrimSpace(addr)
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return hostPort{Host: addr, Port: 0}
	}
	host := addr[:lastColon]
	host = strings.Trim(host, "[]")
	port, _ := strconv.Atoi(addr[lastColon+1:])
	return hostPort{Host: host, Port: port}
}

func resolveProcessName(pid int) string {
	if pid <= 0 {
		return "system"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
		out, err := cmd.Output()
		if err == nil {
			fields := strings.Split(string(out), ",")
			if len(fields) > 0 {
				return strings.Trim(fields[0], `"`)
			}
		}
	}
	return "process"
}
