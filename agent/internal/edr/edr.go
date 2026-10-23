package edr

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

// ProcessInfo holds normalized process metadata and parent relationships
type ProcessInfo struct {
	PID               int
	PPID              int
	Name              string
	CommandLine       string
	ParentName        string
	ParentCommandLine string
	Username          string
}

// Scanner performs behavioral analysis and detects Living-off-the-Land (LOLBin) abuse
type Scanner struct {
	mu            sync.Mutex
	seenAnomalies map[string]time.Time // key: pid:rule_id, val: last seen time
}

// NewScanner creates a new cross-platform EDR scanner
func NewScanner() *Scanner {
	return &Scanner{
		seenAnomalies: make(map[string]time.Time),
	}
}

// Scan inspects running processes against behavioral rules, enforces policy, and yields anomalies
func (s *Scanner) Scan(policy *models.EndpointPolicyConfig) []models.EndpointProcessAnomaly {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Cleanup expired seen anomalies (older than 10 minutes)
	now := time.Now().UTC()
	for k, t := range s.seenAnomalies {
		if now.Sub(t) > 10*time.Minute {
			delete(s.seenAnomalies, k)
		}
	}

	// 2. Enumerate processes and build process tree
	procs := s.collectProcesses()
	if len(procs) == 0 {
		return nil
	}

	// Build map for parent metadata resolution
	procMap := make(map[int]*ProcessInfo, len(procs))
	for i := range procs {
		procMap[procs[i].PID] = &procs[i]
	}
	for i := range procs {
		if parent, ok := procMap[procs[i].PPID]; ok {
			procs[i].ParentName = parent.Name
			procs[i].ParentCommandLine = parent.CommandLine
			if procs[i].Username == "" && parent.Username != "" {
				procs[i].Username = parent.Username
			}
		}
	}

	// 3. Evaluate heuristic and behavioral rules
	var anomalies []models.EndpointProcessAnomaly
	for _, p := range procs {
		matches := s.evaluateRules(p, policy)
		for _, m := range matches {
			dedupKey := fmt.Sprintf("%d:%s:%s", p.PID, p.Name, m.RuleID)
			if last, ok := s.seenAnomalies[dedupKey]; ok && now.Sub(last) < 10*time.Minute {
				continue
			}
			s.seenAnomalies[dedupKey] = now

			actionTaken := "audited"
			// Check if automated process termination should be executed
			if policy != nil && policy.EDRKillOnCritical && strings.EqualFold(m.Severity, "critical") {
				if s.killProcess(p.PID) {
					actionTaken = "terminated"
					log.Printf("[LOGGER EDR] Autonomous Threat Neutralization: Successfully terminated anomalous PID %d (%s) triggered by rule %s", p.PID, p.Name, m.RuleID)
				} else {
					actionTaken = "kill_failed"
					log.Printf("[LOGGER EDR] Warning: Failed to autonomously terminate anomalous PID %d (%s)", p.PID, p.Name)
				}
			}

			anomalies = append(anomalies, models.EndpointProcessAnomaly{
				ID:                uuid.New(),
				PID:               p.PID,
				ProcessName:       p.Name,
				CommandLine:       p.CommandLine,
				ParentPID:         p.PPID,
				ParentName:        p.ParentName,
				ParentCommandLine: p.ParentCommandLine,
				Username:          p.Username,
				Severity:          m.Severity,
				RuleID:            m.RuleID,
				RuleName:          m.RuleName,
				MitreTactic:       m.MitreTactic,
				MitreTechnique:    m.MitreTechnique,
				ActionTaken:       actionTaken,
				Details:           m.Details,
				Timestamp:         now,
				CreatedAt:         now,
			})
		}
	}

	return anomalies
}

type ruleMatch struct {
	RuleID         string
	RuleName       string
	Severity       string
	MitreTactic    string
	MitreTechnique string
	Details        string
}

// evaluateRules inspects a process against behavioral and script attack heuristics
func (s *Scanner) evaluateRules(p ProcessInfo, policy *models.EndpointPolicyConfig) []ruleMatch {
	var matches []ruleMatch

	pNameLower := strings.ToLower(p.Name)
	cmdLower := strings.ToLower(p.CommandLine)
	parentLower := strings.ToLower(p.ParentName)

	monitorScripts := true
	blockLOLBins := true
	if policy != nil {
		if !policy.EDRMonitorScriptEngines {
			monitorScripts = false
		}
		if !policy.EDRBlockLOLBins {
			blockLOLBins = false
		}
	}

	// -------------------------------------------------------------------------
	// RULE 1: Office/Productivity Application Spawning Shell or Script Engine
	// MITRE: T1204.002, T1059.001
	// -------------------------------------------------------------------------
	officeApps := []string{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "eqnedt32.exe", "msaccess.exe", "visio.exe"}
	scriptEngines := []string{"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash", "sh", "python.exe", "certutil.exe", "bitsadmin.exe"}

	isOfficeParent := false
	for _, off := range officeApps {
		if parentLower == off || strings.HasSuffix(parentLower, off) {
			isOfficeParent = true
			break
		}
	}
	if isOfficeParent {
		isScriptChild := false
		for _, se := range scriptEngines {
			if pNameLower == se || strings.HasSuffix(pNameLower, se) {
				isScriptChild = true
				break
			}
		}
		if isScriptChild {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-OFFICE-SPAWN",
				RuleName:       "Office Application Spawned Shell or Script Interpreter",
				Severity:       "critical",
				MitreTactic:    "Execution",
				MitreTechnique: "T1204.002",
				Details:        fmt.Sprintf("Productivity process '%s' spawned script interpreter '%s'. Common weaponized macro or exploit payload vector.", p.ParentName, p.Name),
			})
		}
	}

	// -------------------------------------------------------------------------
	// RULE 2: Web Server or Database Spawning Interactive Shell (Webshell Detection)
	// MITRE: T1059.004, T1505.003
	// -------------------------------------------------------------------------
	webServers := []string{
		"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "httpd", "nginx", "apache2",
		"lighttpd", "caddy", "sqlservr.exe", "mysqld.exe", "postgres", "php-fpm", "php",
	}
	interactiveShells := []string{
		"cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "dash", "zsh", "whoami", "whoami.exe", "net.exe", "net1.exe",
	}

	isWebServerParent := false
	for _, ws := range webServers {
		if parentLower == ws || strings.HasSuffix(parentLower, ws) {
			isWebServerParent = true
			break
		}
	}
	if isWebServerParent {
		isShellChild := false
		for _, sh := range interactiveShells {
			if pNameLower == sh || strings.HasSuffix(pNameLower, sh) {
				isShellChild = true
				break
			}
		}
		if isShellChild {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-WEBSHELL",
				RuleName:       "Web or Database Server Spawned Interactive Shell",
				Severity:       "critical",
				MitreTactic:    "Persistence",
				MitreTechnique: "T1505.003",
				Details:        fmt.Sprintf("Web server process '%s' spawned interactive shell or reconnaissance utility '%s'. Highly indicative of an active web shell backdoor.", p.ParentName, p.Name),
			})
		}
	}

	// -------------------------------------------------------------------------
	// RULE 3: Living-off-the-Land Binary (LOLBin) Weaponization
	// MITRE: T1105, T1218, T1197
	// -------------------------------------------------------------------------
	if blockLOLBins {
		// CertUtil download cradle
		if strings.Contains(pNameLower, "certutil") && (strings.Contains(cmdLower, "-urlcache") || strings.Contains(cmdLower, "-split") || strings.Contains(cmdLower, "http://") || strings.Contains(cmdLower, "https://")) {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-LOLBIN-CERTUTIL",
				RuleName:       "CertUtil Remote Ingress Tool Download",
				Severity:       "high",
				MitreTactic:    "Command and Control",
				MitreTechnique: "T1105",
				Details:        "certutil.exe invoked with -urlcache or remote HTTP(S) address to download external payload.",
			})
		}

		// Mshta executing inline script or remote HTA
		if strings.Contains(pNameLower, "mshta") && (strings.Contains(cmdLower, "javascript:") || strings.Contains(cmdLower, "vbscript:") || strings.Contains(cmdLower, "http://") || strings.Contains(cmdLower, "https://")) {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-LOLBIN-MSHTA",
				RuleName:       "Mshta Inline Script or Remote HTA Execution",
				Severity:       "high",
				MitreTactic:    "Defense Evasion",
				MitreTechnique: "T1218.005",
				Details:        "mshta.exe invoked with inline script protocol or remote URL download.",
			})
		}

		// Regsvr32 /s /u /i:http (Squiblydoo)
		if strings.Contains(pNameLower, "regsvr32") && (strings.Contains(cmdLower, "/i:http") || strings.Contains(cmdLower, "/i:https") || strings.Contains(cmdLower, ".sct")) {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-LOLBIN-REGSVR32",
				RuleName:       "Regsvr32 Remote Scriptlet Execution (Squiblydoo)",
				Severity:       "critical",
				MitreTactic:    "Defense Evasion",
				MitreTechnique: "T1218.010",
				Details:        "regsvr32.exe executed with remote scriptlet or SCT reference bypassing application allowlists.",
			})
		}

		// Rundll32 with javascript or suspicious protocol
		if strings.Contains(pNameLower, "rundll32") && (strings.Contains(cmdLower, "javascript:") || strings.Contains(cmdLower, "vbscript:") || strings.Contains(cmdLower, "http://") || strings.Contains(cmdLower, "https://")) {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-LOLBIN-RUNDLL32",
				RuleName:       "Rundll32 Arbitrary Script or Remote DLL Ingestion",
				Severity:       "high",
				MitreTactic:    "Defense Evasion",
				MitreTechnique: "T1218.011",
				Details:        "rundll32.exe invoked with inline script or remote web protocol.",
			})
		}

		// Bitsadmin download
		if strings.Contains(pNameLower, "bitsadmin") && (strings.Contains(cmdLower, "/transfer") || strings.Contains(cmdLower, "/download")) {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-LOLBIN-BITSADMIN",
				RuleName:       "Bitsadmin Asynchronous Background File Download",
				Severity:       "medium",
				MitreTactic:    "Persistence",
				MitreTechnique: "T1197",
				Details:        "bitsadmin.exe utilized to transfer files asynchronously from remote server.",
			})
		}
	}

	// -------------------------------------------------------------------------
	// RULE 4: Ransomware Volume Shadow Copy Invalidation & Recovery Inhibition
	// MITRE: T1490
	// -------------------------------------------------------------------------
	if (strings.Contains(pNameLower, "vssadmin") && strings.Contains(cmdLower, "delete") && strings.Contains(cmdLower, "shadows")) ||
		(strings.Contains(pNameLower, "wbadmin") && strings.Contains(cmdLower, "delete") && strings.Contains(cmdLower, "catalog")) ||
		(strings.Contains(pNameLower, "bcdedit") && (strings.Contains(cmdLower, "ignoreallfailures") || strings.Contains(cmdLower, "recoveryenabled no"))) ||
		(strings.Contains(pNameLower, "wmic") && strings.Contains(cmdLower, "shadowcopy") && strings.Contains(cmdLower, "delete")) {
		matches = append(matches, ruleMatch{
			RuleID:         "EDR-RULE-RANSOMWARE-INHIBIT",
			RuleName:       "Ransomware Volume Shadow Copy & Recovery Invalidation",
			Severity:       "critical",
			MitreTactic:    "Impact",
			MitreTechnique: "T1490",
			Details:        "Process executed commands to systematically delete volume shadow copies or disable boot recovery options.",
		})
	}

	// -------------------------------------------------------------------------
	// RULE 5: Obfuscated & Stealth Script Execution
	// MITRE: T1027, T1059.001
	// -------------------------------------------------------------------------
	if monitorScripts {
		isPowerShell := strings.Contains(pNameLower, "powershell") || strings.Contains(pNameLower, "pwsh")
		if isPowerShell {
			hasEnc := strings.Contains(cmdLower, "-encodedcommand") || strings.Contains(cmdLower, "-enc ") || strings.Contains(cmdLower, "frombase64string")
			hasBypass := strings.Contains(cmdLower, "-executionpolicy bypass") || strings.Contains(cmdLower, "-ep bypass")
			hasHidden := strings.Contains(cmdLower, "-windowstyle hidden") || strings.Contains(cmdLower, "-w hidden")

			if hasEnc {
				matches = append(matches, ruleMatch{
					RuleID:         "EDR-RULE-SCRIPT-OBFUSCATION",
					RuleName:       "Base64 Encoded PowerShell Execution",
					Severity:       "high",
					MitreTactic:    "Defense Evasion",
					MitreTechnique: "T1027",
					Details:        "PowerShell process started with base64 encoded command arguments (-enc / -EncodedCommand) to obscure execution intent.",
				})
			} else if hasBypass && hasHidden {
				matches = append(matches, ruleMatch{
					RuleID:         "EDR-RULE-SCRIPT-STEALTH",
					RuleName:       "Stealth Hidden PowerShell Execution Policy Bypass",
					Severity:       "medium",
					MitreTactic:    "Defense Evasion",
					MitreTechnique: "T1059.001",
					Details:        "PowerShell executed with combined -WindowStyle Hidden and -ExecutionPolicy Bypass flags.",
				})
			}
		}
	}

	// -------------------------------------------------------------------------
	// RULE 6: In-Memory Download Cradle / Direct Shell Pipe
	// MITRE: T1059.001, T1059.004
	// -------------------------------------------------------------------------
	if monitorScripts {
		// PowerShell IEX download cradle
		if (strings.Contains(cmdLower, "invoke-expression") || strings.Contains(cmdLower, "iex")) &&
			(strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "net.webclient") || strings.Contains(cmdLower, "curl") || strings.Contains(cmdLower, "irm ")) {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-DOWNLOAD-CRADLE",
				RuleName:       "In-Memory Download Cradle Execution",
				Severity:       "critical",
				MitreTactic:    "Execution",
				MitreTechnique: "T1059.001",
				Details:        "PowerShell invoked memory-only script download cradle using WebClient.DownloadString piped directly to Invoke-Expression (IEX).",
			})
		}

		// Linux / macOS curl | bash pipe
		if (strings.Contains(cmdLower, "curl ") || strings.Contains(cmdLower, "wget ")) &&
			(strings.Contains(cmdLower, "| bash") || strings.Contains(cmdLower, "| sh") || strings.Contains(cmdLower, "| /bin/sh") || strings.Contains(cmdLower, "| /bin/bash")) {
			matches = append(matches, ruleMatch{
				RuleID:         "EDR-RULE-PIPE-TO-SHELL",
				RuleName:       "Remote Web Content Piped Directly to Shell",
				Severity:       "high",
				MitreTactic:    "Execution",
				MitreTechnique: "T1059.004",
				Details:        "curl or wget process piping unverified remote script directly into bash/sh shell execution.",
			})
		}
	}

	return matches
}

// killProcess terminates an anomalous process given its PID
func (s *Scanner) killProcess(pid int) bool {
	if pid <= 1 {
		return false // Never kill init or system idle process
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid))
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Kill()
	return err == nil
}

// collectProcesses acquires the process list according to current operating system
func (s *Scanner) collectProcesses() []ProcessInfo {
	switch runtime.GOOS {
	case "linux":
		return s.collectLinuxProcesses()
	case "darwin":
		return s.collectDarwinProcesses()
	case "windows":
		return s.collectWindowsProcesses()
	default:
		return s.collectPosixProcesses()
	}
}

// collectLinuxProcesses parses /proc filesystem directly for maximum speed and zero child forks
func (s *Scanner) collectLinuxProcesses() []ProcessInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return s.collectPosixProcesses()
	}

	var procs []ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		pidPath := filepath.Join("/proc", entry.Name())

		// 1. Read comm & ppid from /proc/<pid>/stat
		statBytes, err := os.ReadFile(filepath.Join(pidPath, "stat"))
		if err != nil {
			continue
		}
		statStr := string(statBytes)
		openParen := strings.Index(statStr, "(")
		closeParen := strings.LastIndex(statStr, ")")
		if openParen == -1 || closeParen == -1 || closeParen < openParen {
			continue
		}
		name := statStr[openParen+1 : closeParen]
		fields := strings.Fields(statStr[closeParen+1:])
		ppid := 0
		if len(fields) >= 2 {
			ppid, _ = strconv.Atoi(fields[1])
		}

		// 2. Read full command line from /proc/<pid>/cmdline
		cmdlineBytes, _ := os.ReadFile(filepath.Join(pidPath, "cmdline"))
		cmdline := string(bytes.ReplaceAll(cmdlineBytes, []byte{0}, []byte{' '}))
		cmdline = strings.TrimSpace(cmdline)
		if cmdline == "" {
			cmdline = name
		}

		// 3. Read username from /proc/<pid>/status
		username := ""
		if statusBytes, err := os.ReadFile(filepath.Join(pidPath, "status")); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(statusBytes))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Uid:") {
					uidFields := strings.Fields(line)
					if len(uidFields) >= 2 {
						username = "uid:" + uidFields[1]
					}
					break
				}
			}
		}

		procs = append(procs, ProcessInfo{
			PID:         pid,
			PPID:        ppid,
			Name:        name,
			CommandLine: cmdline,
			Username:    username,
		})
	}

	return procs
}

// collectDarwinProcesses utilizes ps -A -o pid,ppid,user,comm,args
func (s *Scanner) collectDarwinProcesses() []ProcessInfo {
	return s.collectPosixProcesses()
}

// collectPosixProcesses executes ps utility with consistent column format
func (s *Scanner) collectPosixProcesses() []ProcessInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ps", "-A", "-o", "pid=,ppid=,user=,comm=,args=")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var procs []ProcessInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		user := fields[2]
		comm := fields[3]
		// The remainder of the line is args
		cmdline := strings.Join(fields[4:], " ")

		procs = append(procs, ProcessInfo{
			PID:         pid,
			PPID:        ppid,
			Name:        filepath.Base(comm),
			CommandLine: cmdline,
			Username:    user,
		})
	}

	return procs
}

// collectWindowsProcesses executes wmic or powershell CIM process enumeration
func (s *Scanner) collectWindowsProcesses() []ProcessInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// 1. Try wmic process get ProcessId,ParentProcessId,Name,CommandLine /FORMAT:CSV
	cmd := exec.CommandContext(ctx, "wmic", "process", "get", "ProcessId,ParentProcessId,Name,CommandLine", "/FORMAT:CSV")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		return parseWmicProcessCSV(out)
	}

	// 2. Fallback to PowerShell Get-CimInstance
	psScript := `Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId),$($_.ParentProcessId),$($_.Name),$($_.CommandLine)" }`
	psCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	psOut, psErr := psCmd.Output()
	if psErr == nil && len(psOut) > 0 {
		return parsePowershellProcesses(psOut)
	}

	return nil
}

func parseWmicProcessCSV(data []byte) []ProcessInfo {
	var procs []ProcessInfo
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Node,") {
			continue
		}
		// Node,CommandLine,Name,ParentProcessId,ProcessId
		parts := strings.Split(line, ",")
		if len(parts) < 5 {
			continue
		}
		// CSV format from wmic puts columns alphabetically after Node:
		// CommandLine (parts[1]), Name (parts[2]), ParentProcessId (parts[3]), ProcessId (parts[4])
		pid, _ := strconv.Atoi(parts[len(parts)-1])
		ppid, _ := strconv.Atoi(parts[len(parts)-2])
		name := parts[len(parts)-3]
		cmdline := strings.Join(parts[1:len(parts)-3], ",")

		if pid > 0 {
			procs = append(procs, ProcessInfo{
				PID:         pid,
				PPID:        ppid,
				Name:        name,
				CommandLine: cmdline,
			})
		}
	}
	return procs
}

func parsePowershellProcesses(data []byte) []ProcessInfo {
	var procs []ProcessInfo
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 4)
		if len(parts) < 3 {
			continue
		}
		pid, _ := strconv.Atoi(parts[0])
		ppid, _ := strconv.Atoi(parts[1])
		name := parts[2]
		cmdline := ""
		if len(parts) == 4 {
			cmdline = parts[3]
		}
		if pid > 0 {
			procs = append(procs, ProcessInfo{
				PID:         pid,
				PPID:        ppid,
				Name:        name,
				CommandLine: cmdline,
			})
		}
	}
	return procs
}

// Regex helpers to test against common patterns
var reCurlPipe = regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(ba)?sh`)
