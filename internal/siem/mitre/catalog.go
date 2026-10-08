package mitre

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// Tactic represents a MITRE ATT&CK tactical objective (e.g. Credential Access)
type Tactic struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ShortName   string `json:"short_name,omitempty"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// Technique represents a MITRE ATT&CK technique or sub-technique (e.g. T1110)
type Technique struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	TacticID       string   `json:"tactic_id"`
	TacticName     string   `json:"tactic_name"`
	TacticIDs      []string `json:"tactic_ids,omitempty"` // every tactic the technique belongs to (ATT&CK is many-to-many)
	Description    string   `json:"description"`
	URL            string   `json:"url"`
	SubTechniqueOf string   `json:"sub_technique_of,omitempty"`
	Platforms      []string `json:"platforms,omitempty"`
}

// tactics returns every tactic ID the technique is mapped to
func (t Technique) tactics() []string {
	if len(t.TacticIDs) > 0 {
		return t.TacticIDs
	}
	if t.TacticID != "" {
		return []string{t.TacticID}
	}
	return nil
}

// CoverageTechnique reports detection capability status for a specific technique
type CoverageTechnique struct {
	Technique
	Covered       bool       `json:"covered"`
	RuleIDs       []string   `json:"rule_ids"`
	RuleNames     []string   `json:"rule_names"`
	AlertCount    int64      `json:"alert_count"`
	LastSeenAlert *time.Time `json:"last_seen_alert,omitempty"`
	IsNew         bool       `json:"is_new"`             // introduced by the most recent ATT&CK release
	Inferred      bool       `json:"inferred,omitempty"` // referenced by a rule but absent from the loaded catalog
}

// CoverageTactic reports tactical coverage metrics
type CoverageTactic struct {
	Tactic
	TotalTechniques   int                 `json:"total_techniques"`
	CoveredTechniques int                 `json:"covered_techniques"`
	CoveragePercent   float64             `json:"coverage_percent"`
	Techniques        []CoverageTechnique `json:"techniques"`
}

// AutoSyncStatus exposes the state of the background ATT&CK release watcher
type AutoSyncStatus struct {
	Enabled       bool       `json:"enabled"`
	FeedURL       string     `json:"feed_url"`
	IntervalHours int        `json:"interval_hours"`
	LastCheck     *time.Time `json:"last_check,omitempty"`
	LastSuccess   *time.Time `json:"last_success,omitempty"`
	LastResult    string     `json:"last_result,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	NextCheck     *time.Time `json:"next_check,omitempty"`
	Persisted     bool       `json:"persisted"`
}

// MatrixReport encapsulates the full ATT&CK matrix coverage state
type MatrixReport struct {
	Version           string           `json:"version"`
	AttackVersion     string           `json:"attack_version,omitempty"`
	PreviousVersion   string           `json:"previous_version,omitempty"`
	LastUpdated       time.Time        `json:"last_updated"`
	Source            string           `json:"source"`
	IsBaseline        bool             `json:"is_baseline"`
	TotalTactics      int              `json:"total_tactics"`
	TotalTechniques   int              `json:"total_techniques"`
	TotalParent       int              `json:"total_parent_techniques"`
	TotalSub          int              `json:"total_sub_techniques"`
	CoveredTechniques int              `json:"covered_techniques"`
	TotalAlertsMapped int64            `json:"total_alerts_mapped"`
	NewTechniques     int              `json:"new_techniques"`
	NewTechniqueIDs   []string         `json:"new_technique_ids,omitempty"`
	AutoSync          AutoSyncStatus   `json:"auto_sync"`
	Tactics           []CoverageTactic `json:"tactics"`
}

// AlertStat is an aggregated per-technique alert counter
type AlertStat struct {
	Count    int64
	LastSeen time.Time
}

// Catalog maintains the in-memory registry of MITRE ATT&CK tactics & techniques
type Catalog struct {
	mu              sync.RWMutex
	tactics         []Tactic
	techniques      map[string]Technique // keyed by Technique ID (e.g. "T1110")
	version         string
	attackVersion   string
	previousVersion string
	lastUpdated     time.Time
	source          string
	isBaseline      bool
	etag            string
	newTechIDs      map[string]bool

	store    Store
	autoSync AutoSyncStatus
}

// Official MITRE Enterprise ATT&CK STIX 2.1 JSON endpoint
const DefaultMITRESTIXURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

// NewCatalog initializes a pre-loaded MITRE ATT&CK Enterprise Matrix catalog
func NewCatalog() *Catalog {
	c := &Catalog{
		techniques:  make(map[string]Technique),
		newTechIDs:  make(map[string]bool),
		version:     "v15.1 Enterprise Matrix",
		lastUpdated: time.Now().UTC(),
		source:      "Embedded Enterprise ATT&CK Baseline",
		isBaseline:  true,
	}
	c.loadDefaultBaseline()
	return c
}

func (c *Catalog) loadDefaultBaseline() {
	c.tactics = defaultTactics()

	baselineTechs := []Technique{
		// Initial Access
		{ID: "T1190", Name: "Exploit Public-Facing Application", TacticID: "TA0001", TacticName: "Initial Access", Description: "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.", URL: "https://attack.mitre.org/techniques/T1190/"},
		{ID: "T1566", Name: "Phishing", TacticID: "TA0001", TacticName: "Initial Access", Description: "Adversaries may send phishing messages to gain access to victim systems.", URL: "https://attack.mitre.org/techniques/T1566/"},
		{ID: "T1133", Name: "External Remote Services", TacticID: "TA0001", TacticName: "Initial Access", Description: "Adversaries may leverage external-facing remote services such as VPNs or Citrix.", URL: "https://attack.mitre.org/techniques/T1133/"},
		// Execution
		{ID: "T1059", Name: "Command and Scripting Interpreter", TacticID: "TA0002", TacticName: "Execution", Description: "Adversaries may abuse command and script interpreters to execute commands.", URL: "https://attack.mitre.org/techniques/T1059/"},
		{ID: "T1204", Name: "User Execution", TacticID: "TA0002", TacticName: "Execution", Description: "Adversaries may rely on the actions of an ordinary user to gain execution.", URL: "https://attack.mitre.org/techniques/T1204/"},
		// Persistence
		{ID: "T1136", Name: "Create Account", TacticID: "TA0003", TacticName: "Persistence", Description: "Adversaries may create an account to maintain access to victim systems.", URL: "https://attack.mitre.org/techniques/T1136/"},
		{ID: "T1136.001", Name: "Create Account: Local Account", TacticID: "TA0003", TacticName: "Persistence", Description: "Adversaries may create a local account to maintain access to victim systems.", URL: "https://attack.mitre.org/techniques/T1136/001/", SubTechniqueOf: "T1136"},
		{ID: "T1078", Name: "Valid Accounts", TacticID: "TA0003", TacticName: "Persistence", Description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Persistence.", URL: "https://attack.mitre.org/techniques/T1078/"},
		// Privilege Escalation
		{ID: "T1548", Name: "Abuse Elevation Control Mechanism", TacticID: "TA0004", TacticName: "Privilege Escalation", Description: "Adversaries may circumvent mechanisms designed to control elevate privileges.", URL: "https://attack.mitre.org/techniques/T1548/"},
		{ID: "T1548.003", Name: "Sudo and Sudoers", TacticID: "TA0004", TacticName: "Privilege Escalation", Description: "Adversaries may abuse sudo and sudoers configuration to perform unauthorized elevation.", URL: "https://attack.mitre.org/techniques/T1548/003/", SubTechniqueOf: "T1548"},
		{ID: "T1068", Name: "Exploitation for Privilege Escalation", TacticID: "TA0004", TacticName: "Privilege Escalation", Description: "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.", URL: "https://attack.mitre.org/techniques/T1068/"},
		// Defense Evasion
		{ID: "T1070", Name: "Indicator Removal", TacticID: "TA0005", TacticName: "Defense Evasion", Description: "Adversaries may delete or alter generated artifacts on a host system, including event logs.", URL: "https://attack.mitre.org/techniques/T1070/"},
		{ID: "T1562", Name: "Impair Defenses", TacticID: "TA0005", TacticName: "Defense Evasion", Description: "Adversaries may maliciously disable or modify security tools and defensive capabilities.", URL: "https://attack.mitre.org/techniques/T1562/"},
		// Credential Access
		{ID: "T1110", Name: "Brute Force", TacticID: "TA0006", TacticName: "Credential Access", Description: "Adversaries may use brute force techniques to attempt credential access through trial and error.", URL: "https://attack.mitre.org/techniques/T1110/"},
		{ID: "T1110.001", Name: "Password Guessing", TacticID: "TA0006", TacticName: "Credential Access", Description: "Adversaries may systematically guess passwords to authenticate accounts.", URL: "https://attack.mitre.org/techniques/T1110/001/", SubTechniqueOf: "T1110"},
		{ID: "T1110.003", Name: "Password Spraying", TacticID: "TA0006", TacticName: "Credential Access", Description: "Adversaries may use a single or small list of commonly used passwords against many accounts.", URL: "https://attack.mitre.org/techniques/T1110/003/", SubTechniqueOf: "T1110"},
		{ID: "T1003", Name: "OS Credential Dumping", TacticID: "TA0006", TacticName: "Credential Access", Description: "Adversaries may dump credentials from the operating system to obtain account logon information.", URL: "https://attack.mitre.org/techniques/T1003/"},
		// Discovery
		{ID: "T1046", Name: "Network Service Discovery", TacticID: "TA0007", TacticName: "Discovery", Description: "Adversaries may attempt to get a listing of services running on remote hosts (port scanning).", URL: "https://attack.mitre.org/techniques/T1046/"},
		{ID: "T1082", Name: "System Information Discovery", TacticID: "TA0007", TacticName: "Discovery", Description: "Adversaries may attempt to get detailed information about the operating system and hardware.", URL: "https://attack.mitre.org/techniques/T1082/"},
		{ID: "T1087", Name: "Account Discovery", TacticID: "TA0007", TacticName: "Discovery", Description: "Adversaries may attempt to get a listing of valid accounts on a system or network.", URL: "https://attack.mitre.org/techniques/T1087/"},
		// Lateral Movement
		{ID: "T1021", Name: "Remote Services", TacticID: "TA0008", TacticName: "Lateral Movement", Description: "Adversaries may use valid accounts to log into a service specifically designed for remote terminal access.", URL: "https://attack.mitre.org/techniques/T1021/"},
		// Command and Control
		{ID: "T1071", Name: "Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control", Description: "Adversaries may communicate using application layer protocols to avoid detection.", URL: "https://attack.mitre.org/techniques/T1071/"},
		// Impact
		{ID: "T1499", Name: "Endpoint Denial of Service", TacticID: "TA0040", TacticName: "Impact", Description: "Adversaries may perform Endpoint Denial of Service attacks to degrade or block availability of services.", URL: "https://attack.mitre.org/techniques/T1499/"},
		{ID: "T1486", Name: "Data Encrypted for Impact", TacticID: "TA0040", TacticName: "Impact", Description: "Adversaries may encrypt data on target systems to interrupt availability (Ransomware).", URL: "https://attack.mitre.org/techniques/T1486/"},
	}

	for _, t := range baselineTechs {
		c.techniques[t.ID] = t
	}
}

func defaultTactics() []Tactic {
	return []Tactic{
		{ID: "TA0043", ShortName: "reconnaissance", Name: "Reconnaissance", Description: "Gather information to plan future adversary operations", URL: "https://attack.mitre.org/tactics/TA0043/"},
		{ID: "TA0042", ShortName: "resource-development", Name: "Resource Development", Description: "Establish resources to support adversary operations", URL: "https://attack.mitre.org/tactics/TA0042/"},
		{ID: "TA0001", ShortName: "initial-access", Name: "Initial Access", Description: "Gain entry to your network", URL: "https://attack.mitre.org/tactics/TA0001/"},
		{ID: "TA0002", ShortName: "execution", Name: "Execution", Description: "Run malicious code", URL: "https://attack.mitre.org/tactics/TA0002/"},
		{ID: "TA0003", ShortName: "persistence", Name: "Persistence", Description: "Maintain their foothold across restarts", URL: "https://attack.mitre.org/tactics/TA0003/"},
		{ID: "TA0004", ShortName: "privilege-escalation", Name: "Privilege Escalation", Description: "Gain higher-level permissions", URL: "https://attack.mitre.org/tactics/TA0004/"},
		{ID: "TA0005", ShortName: "defense-evasion", Name: "Defense Evasion", Description: "Avoid being detected by security tools", URL: "https://attack.mitre.org/tactics/TA0005/"},
		{ID: "TA0006", ShortName: "credential-access", Name: "Credential Access", Description: "Steal account names and passwords", URL: "https://attack.mitre.org/tactics/TA0006/"},
		{ID: "TA0007", ShortName: "discovery", Name: "Discovery", Description: "Explore and observe the target environment", URL: "https://attack.mitre.org/tactics/TA0007/"},
		{ID: "TA0008", ShortName: "lateral-movement", Name: "Lateral Movement", Description: "Move through your network to other systems", URL: "https://attack.mitre.org/tactics/TA0008/"},
		{ID: "TA0009", ShortName: "collection", Name: "Collection", Description: "Gather data of interest to the adversary goal", URL: "https://attack.mitre.org/tactics/TA0009/"},
		{ID: "TA0011", ShortName: "command-and-control", Name: "Command and Control", Description: "Communicate with compromised systems to control them", URL: "https://attack.mitre.org/tactics/TA0011/"},
		{ID: "TA0010", ShortName: "exfiltration", Name: "Exfiltration", Description: "Steal and remove sensitive data from your network", URL: "https://attack.mitre.org/tactics/TA0010/"},
		{ID: "TA0040", ShortName: "impact", Name: "Impact", Description: "Manipulate, interrupt, or destroy systems and data", URL: "https://attack.mitre.org/tactics/TA0040/"},
	}
}

// GetTechnique looks up a technique by ID (e.g. "T1110" or "T1110.003")
func (c *Catalog) GetTechnique(id string) (Technique, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.techniques[id]
	return t, ok
}

// TechniqueCount returns the number of loaded techniques (incl. sub-techniques)
func (c *Catalog) TechniqueCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.techniques)
}

// GenerateCoverageReport compares active SIEM rules and alerts against the ATT&CK matrix
func (c *Catalog) GenerateCoverageReport(rules []models.SIEMRule, alerts []models.SIEMAlert) MatrixReport {
	stats := make(map[string]AlertStat)
	for _, a := range alerts {
		if a.MitreTechnique == "" {
			continue
		}
		s := stats[a.MitreTechnique]
		s.Count++
		if a.LastSeen.After(s.LastSeen) {
			s.LastSeen = a.LastSeen
		}
		stats[a.MitreTechnique] = s
	}
	return c.GenerateCoverageReportWithStats(rules, stats)
}

// GenerateCoverageReportWithStats builds the matrix using pre-aggregated per-technique alert counters
func (c *Catalog) GenerateCoverageReportWithStats(rules []models.SIEMRule, alertStats map[string]AlertStat) MatrixReport {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Local working copy: rule-only techniques are added here, never into the shared map (avoids writes under RLock)
	techs := make(map[string]Technique, len(c.techniques)+8)
	for id, t := range c.techniques {
		techs[id] = t
	}
	inferred := make(map[string]bool)

	tacticByName := make(map[string]string, len(c.tactics))
	for _, tac := range c.tactics {
		tacticByName[strings.ToLower(tac.Name)] = tac.ID
	}

	rulesByTech := make(map[string][]models.SIEMRule)
	for _, r := range rules {
		if r.MitreTechnique == "" || !r.IsEnabled {
			continue
		}
		rulesByTech[r.MitreTechnique] = append(rulesByTech[r.MitreTechnique], r)
		if _, exists := techs[r.MitreTechnique]; exists {
			continue
		}
		tacticID := tacticByName[strings.ToLower(r.MitreTactic)]
		parent := ""
		if i := strings.Index(r.MitreTechnique, "."); i > 0 {
			parent = r.MitreTechnique[:i]
			if p, ok := techs[parent]; ok && tacticID == "" {
				tacticID = p.TacticID
			}
		}
		if tacticID == "" {
			tacticID = "TA0001"
		}
		techs[r.MitreTechnique] = Technique{
			ID:             r.MitreTechnique,
			Name:           r.Name,
			TacticID:       tacticID,
			TacticName:     r.MitreTactic,
			Description:    r.Description,
			SubTechniqueOf: parent,
			URL:            fmt.Sprintf("https://attack.mitre.org/techniques/%s/", strings.ReplaceAll(r.MitreTechnique, ".", "/")),
		}
		inferred[r.MitreTechnique] = true
	}

	var totalAlertsMapped int64
	for _, s := range alertStats {
		totalAlertsMapped += s.Count
	}

	// A technique is covered when a rule targets it directly or any of its sub-techniques
	coverageRules := func(id string) []models.SIEMRule {
		matching := append([]models.SIEMRule(nil), rulesByTech[id]...)
		if !strings.Contains(id, ".") {
			for techID, rList := range rulesByTech {
				if strings.HasPrefix(techID, id+".") {
					matching = append(matching, rList...)
				}
			}
		}
		return matching
	}

	byTactic := make(map[string][]Technique)
	for _, t := range techs {
		for _, tacID := range t.tactics() {
			byTactic[tacID] = append(byTactic[tacID], t)
		}
	}

	coveredSet := make(map[string]bool)
	shownSet := make(map[string]bool)
	tacticsList := make([]CoverageTactic, 0, len(c.tactics))

	for _, tac := range c.tactics {
		list := byTactic[tac.ID]
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })

		covTac := CoverageTactic{Tactic: tac, Techniques: make([]CoverageTechnique, 0, len(list))}
		for _, tech := range list {
			matching := coverageRules(tech.ID)
			ruleIDs := make([]string, 0, len(matching))
			ruleNames := make([]string, 0, len(matching))
			seen := make(map[string]bool)
			for _, r := range matching {
				if seen[r.ID] {
					continue
				}
				seen[r.ID] = true
				ruleIDs = append(ruleIDs, r.ID)
				ruleNames = append(ruleNames, r.Name)
			}
			isCovered := len(ruleIDs) > 0
			if isCovered {
				covTac.CoveredTechniques++
				coveredSet[tech.ID] = true
			}
			shownSet[tech.ID] = true

			covTech := CoverageTechnique{
				Technique: tech,
				Covered:   isCovered,
				RuleIDs:   ruleIDs,
				RuleNames: ruleNames,
				IsNew:     c.newTechIDs[tech.ID],
				Inferred:  inferred[tech.ID],
			}
			if s, ok := alertStats[tech.ID]; ok {
				covTech.AlertCount = s.Count
				if !s.LastSeen.IsZero() {
					ls := s.LastSeen
					covTech.LastSeenAlert = &ls
				}
			}
			covTac.Techniques = append(covTac.Techniques, covTech)
		}

		covTac.TotalTechniques = len(covTac.Techniques)
		if covTac.TotalTechniques > 0 {
			covTac.CoveragePercent = float64(covTac.CoveredTechniques) / float64(covTac.TotalTechniques) * 100.0
		}
		tacticsList = append(tacticsList, covTac)
	}

	parents, subs := 0, 0
	for id := range shownSet {
		if strings.Contains(id, ".") {
			subs++
		} else {
			parents++
		}
	}

	newIDs := make([]string, 0, len(c.newTechIDs))
	for id := range c.newTechIDs {
		newIDs = append(newIDs, id)
	}
	sort.Strings(newIDs)

	return MatrixReport{
		Version:           c.version,
		AttackVersion:     c.attackVersion,
		PreviousVersion:   c.previousVersion,
		LastUpdated:       c.lastUpdated,
		Source:            c.source,
		IsBaseline:        c.isBaseline,
		TotalTactics:      len(c.tactics),
		TotalTechniques:   len(shownSet),
		TotalParent:       parents,
		TotalSub:          subs,
		CoveredTechniques: len(coveredSet),
		TotalAlertsMapped: totalAlertsMapped,
		NewTechniques:     len(newIDs),
		NewTechniqueIDs:   newIDs,
		AutoSync:          c.autoSync,
		Tactics:           tacticsList,
	}
}
