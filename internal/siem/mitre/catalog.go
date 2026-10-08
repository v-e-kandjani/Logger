package mitre

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// Tactic represents a MITRE ATT&CK tactical objective (e.g. Credential Access)
type Tactic struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// Technique represents a MITRE ATT&CK technique or sub-technique (e.g. T1110)
type Technique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TacticID    string   `json:"tactic_id"`
	TacticName  string   `json:"tactic_name"`
	Description string   `json:"description"`
	URL         string   `json:"url"`
	SubTechniqueOf string `json:"sub_technique_of,omitempty"`
}

// CoverageTechnique reports detection capability status for a specific technique
type CoverageTechnique struct {
	Technique
	Covered      bool     `json:"covered"`
	RuleIDs      []string `json:"rule_ids"`
	RuleNames    []string `json:"rule_names"`
	AlertCount   int64    `json:"alert_count"`
	LastSeenAlert *time.Time `json:"last_seen_alert,omitempty"`
}

// CoverageTactic reports tactical coverage metrics
type CoverageTactic struct {
	Tactic
	TotalTechniques   int                 `json:"total_techniques"`
	CoveredTechniques int                 `json:"covered_techniques"`
	CoveragePercent   float64             `json:"coverage_percent"`
	Techniques        []CoverageTechnique `json:"techniques"`
}

// MatrixReport encapsulates the full ATT&CK matrix coverage state
type MatrixReport struct {
	Version            string           `json:"version"`
	LastUpdated        time.Time        `json:"last_updated"`
	Source             string           `json:"source"`
	TotalTactics       int              `json:"total_tactics"`
	TotalTechniques    int              `json:"total_techniques"`
	CoveredTechniques  int              `json:"covered_techniques"`
	TotalAlertsMapped  int64            `json:"total_alerts_mapped"`
	Tactics            []CoverageTactic `json:"tactics"`
}

// Catalog maintains the in-memory registry of MITRE ATT&CK tactics & techniques
type Catalog struct {
	mu          sync.RWMutex
	tactics     []Tactic
	techniques  map[string]Technique // keyed by Technique ID (e.g. "T1110")
	version     string
	lastUpdated time.Time
	source      string
}

// Official MITRE Enterprise ATT&CK STIX 2.1 JSON endpoint
const DefaultMITRESTIXURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

// NewCatalog initializes a pre-loaded MITRE ATT&CK Enterprise Matrix catalog
func NewCatalog() *Catalog {
	c := &Catalog{
		techniques:  make(map[string]Technique),
		version:     "v15.1 Enterprise Matrix",
		lastUpdated: time.Now().UTC(),
		source:      "Embedded Enterprise ATT&CK Baseline",
	}
	c.loadDefaultBaseline()
	return c
}

func (c *Catalog) loadDefaultBaseline() {
	c.tactics = []Tactic{
		{ID: "TA0043", Name: "Reconnaissance", Description: "Gather information to plan future adversary operations", URL: "https://attack.mitre.org/tactics/TA0043/"},
		{ID: "TA0042", Name: "Resource Development", Description: "Establish resources to support adversary operations", URL: "https://attack.mitre.org/tactics/TA0042/"},
		{ID: "TA0001", Name: "Initial Access", Description: "Gain entry to your network", URL: "https://attack.mitre.org/tactics/TA0001/"},
		{ID: "TA0002", Name: "Execution", Description: "Run malicious code", URL: "https://attack.mitre.org/tactics/TA0002/"},
		{ID: "TA0003", Name: "Persistence", Description: "Maintain their foothold across restarts", URL: "https://attack.mitre.org/tactics/TA0003/"},
		{ID: "TA0004", Name: "Privilege Escalation", Description: "Gain higher-level permissions", URL: "https://attack.mitre.org/tactics/TA0004/"},
		{ID: "TA0005", Name: "Defense Evasion", Description: "Avoid being detected by security tools", URL: "https://attack.mitre.org/tactics/TA0005/"},
		{ID: "TA0006", Name: "Credential Access", Description: "Steal account names and passwords", URL: "https://attack.mitre.org/tactics/TA0006/"},
		{ID: "TA0007", Name: "Discovery", Description: "Explore and observe the target environment", URL: "https://attack.mitre.org/tactics/TA0007/"},
		{ID: "TA0008", Name: "Lateral Movement", Description: "Move through your network to other systems", URL: "https://attack.mitre.org/tactics/TA0008/"},
		{ID: "TA0009", Name: "Collection", Description: "Gather data of interest to the adversary goal", URL: "https://attack.mitre.org/tactics/TA0009/"},
		{ID: "TA0011", Name: "Command and Control", Description: "Communicate with compromised systems to control them", URL: "https://attack.mitre.org/tactics/TA0011/"},
		{ID: "TA0010", Name: "Exfiltration", Description: "Steal and remove sensitive data from your network", URL: "https://attack.mitre.org/tactics/TA0010/"},
		{ID: "TA0040", Name: "Impact", Description: "Manipulate, interrupt, or destroy systems and data", URL: "https://attack.mitre.org/tactics/TA0040/"},
	}

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

// GetTechnique looks up a technique by ID (e.g. "T1110" or "T1110.003")
func (c *Catalog) GetTechnique(id string) (Technique, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.techniques[id]
	return t, ok
}

// GenerateCoverageReport compares active SIEM rules and alerts against the ATT&CK matrix
func (c *Catalog) GenerateCoverageReport(rules []models.SIEMRule, alerts []models.SIEMAlert) MatrixReport {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Map rules by MITRE technique
	rulesByTech := make(map[string][]models.SIEMRule)
	for _, r := range rules {
		if r.MitreTechnique != "" && r.IsEnabled {
			rulesByTech[r.MitreTechnique] = append(rulesByTech[r.MitreTechnique], r)
			if _, exists := c.techniques[r.MitreTechnique]; !exists {
				tacticID := "TA0001"
				for _, tac := range c.tactics {
					if strings.EqualFold(tac.Name, r.MitreTactic) {
						tacticID = tac.ID
						break
					}
				}
				c.techniques[r.MitreTechnique] = Technique{
					ID:          r.MitreTechnique,
					Name:        r.Name,
					TacticID:    tacticID,
					TacticName:  r.MitreTactic,
					Description: r.Description,
					URL:         fmt.Sprintf("https://attack.mitre.org/techniques/%s/", strings.ReplaceAll(r.MitreTechnique, ".", "/")),
				}
			}
		}
	}

	// Map alerts by MITRE technique
	alertsByTech := make(map[string]int64)
	lastSeenByTech := make(map[string]time.Time)
	var totalAlertsMapped int64

	for _, a := range alerts {
		if a.MitreTechnique != "" {
			alertsByTech[a.MitreTechnique]++
			totalAlertsMapped++
			if last, ok := lastSeenByTech[a.MitreTechnique]; !ok || a.LastSeen.After(last) {
				lastSeenByTech[a.MitreTechnique] = a.LastSeen
			}
		}
	}

	var totalCovered int
	tacticsList := make([]CoverageTactic, 0, len(c.tactics))

	for _, tac := range c.tactics {
		covTac := CoverageTactic{
			Tactic:     tac,
			Techniques: make([]CoverageTechnique, 0),
		}

		for _, tech := range c.techniques {
			if tech.TacticID != tac.ID {
				continue
			}

			matchingRules := rulesByTech[tech.ID]
			if len(matchingRules) == 0 {
				for techID, rList := range rulesByTech {
					if strings.HasPrefix(techID, tech.ID+".") {
						matchingRules = append(matchingRules, rList...)
					}
				}
			}
			isCovered := len(matchingRules) > 0
			if isCovered {
				covTac.CoveredTechniques++
				totalCovered++
			}

			ruleIDs := make([]string, 0, len(matchingRules))
			ruleNames := make([]string, 0, len(matchingRules))
			for _, r := range matchingRules {
				ruleIDs = append(ruleIDs, r.ID)
				ruleNames = append(ruleNames, r.Name)
			}

			covTech := CoverageTechnique{
				Technique:  tech,
				Covered:    isCovered,
				RuleIDs:    ruleIDs,
				RuleNames:  ruleNames,
				AlertCount: alertsByTech[tech.ID],
			}
			if ls, ok := lastSeenByTech[tech.ID]; ok {
				covTech.LastSeenAlert = &ls
			}

			covTac.Techniques = append(covTac.Techniques, covTech)
		}

		covTac.TotalTechniques = len(covTac.Techniques)
		if covTac.TotalTechniques > 0 {
			covTac.CoveragePercent = float64(covTac.CoveredTechniques) / float64(covTac.TotalTechniques) * 100.0
		}
		tacticsList = append(tacticsList, covTac)
	}

	return MatrixReport{
		Version:           c.version,
		LastUpdated:       c.lastUpdated,
		Source:            c.source,
		TotalTactics:      len(c.tactics),
		TotalTechniques:   len(c.techniques),
		CoveredTechniques: totalCovered,
		TotalAlertsMapped: totalAlertsMapped,
		Tactics:           tacticsList,
	}
}

// SyncFromURL fetches the latest enterprise ATT&CK STIX bundle or JSON matrix definitions
func (c *Catalog) SyncFromURL(ctx context.Context, rawURL string) (int, error) {
	if rawURL == "" {
		rawURL = DefaultMITRESTIXURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "Valtrivo-LogSeal-SIEM/1.0")

	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch MITRE STIX JSON: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("MITRE source returned HTTP status %d", resp.StatusCode)
	}

	return c.ParseSTIXStream(resp.Body, rawURL)
}

// SyncFromFile loads updated ATT&CK STIX / JSON from a local filepath (e.g. for air-gapped systems)
func (c *Catalog) SyncFromFile(filePath string) (int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("open MITRE file: %w", err)
	}
	defer f.Close()

	return c.ParseSTIXStream(f, filePath)
}

// ParseSTIXStream parses STIX 2.1 JSON or lightweight JSON matrix definition
func (c *Catalog) ParseSTIXStream(r io.Reader, sourceName string) (int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("read stream: %w", err)
	}

	// First try lightweight catalog schema
	type SimpleFormat struct {
		Version    string      `json:"version"`
		Techniques []Technique `json:"techniques"`
	}

	var sf SimpleFormat
	if jsonErr := json.Unmarshal(data, &sf); jsonErr == nil && len(sf.Techniques) > 0 {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, t := range sf.Techniques {
			if t.ID != "" {
				c.techniques[t.ID] = t
			}
		}
		if sf.Version != "" {
			c.version = sf.Version
		}
		c.lastUpdated = time.Now().UTC()
		c.source = sourceName
		return len(sf.Techniques), nil
	}

	// Try STIX 2.1 bundle
	type STIXExternalRef struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
		URL        string `json:"url"`
	}
	type STIXKillChainPhase struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	}
	type STIXObject struct {
		Type             string               `json:"type"`
		Name             string               `json:"name"`
		Description      string               `json:"description"`
		ExternalRefs     []STIXExternalRef    `json:"external_references"`
		KillChainPhases  []STIXKillChainPhase `json:"kill_chain_phases"`
		Revoked          bool                 `json:"revoked"`
		XMitreDeprecated bool                 `json:"x_mitre_deprecated"`
	}
	type STIXBundle struct {
		Objects []STIXObject `json:"objects"`
	}

	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return 0, fmt.Errorf("unmarshal JSON: %w", err)
	}

	parsedCount := 0
	c.mu.Lock()
	defer c.mu.Unlock()

	// Mapping of kill chain phase names to Tactic IDs
	phaseToTactic := map[string]struct {
		id   string
		name string
	}{
		"reconnaissance":        {"TA0043", "Reconnaissance"},
		"resource-development":  {"TA0042", "Resource Development"},
		"initial-access":        {"TA0001", "Initial Access"},
		"execution":             {"TA0002", "Execution"},
		"persistence":           {"TA0003", "Persistence"},
		"privilege-escalation":  {"TA0004", "Privilege Escalation"},
		"defense-evasion":       {"TA0005", "Defense Evasion"},
		"credential-access":     {"TA0006", "Credential Access"},
		"discovery":             {"TA0007", "Discovery"},
		"lateral-movement":      {"TA0008", "Lateral Movement"},
		"collection":            {"TA0009", "Collection"},
		"command-and-control":   {"TA0011", "Command and Control"},
		"exfiltration":          {"TA0010", "Exfiltration"},
		"impact":                {"TA0040", "Impact"},
	}

	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" || obj.Revoked || obj.XMitreDeprecated {
			continue
		}

		var techID, techURL string
		for _, ref := range obj.ExternalRefs {
			if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
				techID = ref.ExternalID
				techURL = ref.URL
				break
			}
		}

		if techID == "" {
			continue
		}

		var tacID, tacName string
		for _, phase := range obj.KillChainPhases {
			if phase.KillChainName == "mitre-attack" {
				if mapping, ok := phaseToTactic[phase.PhaseName]; ok {
					tacID = mapping.id
					tacName = mapping.name
					break
				}
			}
		}

		c.techniques[techID] = Technique{
			ID:          techID,
			Name:        obj.Name,
			TacticID:    tacID,
			TacticName:  tacName,
			Description: obj.Description,
			URL:         techURL,
		}
		parsedCount++
	}

	c.version = fmt.Sprintf("MITRE ATT&CK STIX 2.1 (%d techniques)", len(c.techniques))
	c.lastUpdated = time.Now().UTC()
	c.source = sourceName

	return parsedCount, nil
}
