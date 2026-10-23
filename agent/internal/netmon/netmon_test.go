package netmon

import (
	"testing"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

func TestShannonEntropy(t *testing.T) {
	// Normal domains have low to moderate entropy (predictable words)
	normalDomains := []string{
		"google.com",
		"microsoft.com",
		"apple.com",
		"github.com",
		"cloudflare.com",
	}

	for _, d := range normalDomains {
		entropy := CalculateShannonEntropy(d)
		if entropy > 3.7 {
			t.Errorf("Expected normal domain %s to have lower entropy, got %.2f", d, entropy)
		}
	}

	// Random algorithmic DGA domains have high entropy
	dgaDomains := []string{
		"x9k2m8q4v1z7p3j6.biz",
		"kj8a9d7fz12bq98c.info",
		"pqwmxzntkrvwqz.com",
	}

	for _, d := range dgaDomains {
		isDGA, entropy := IsDGA(d)
		if !isDGA {
			t.Errorf("Expected %s to be flagged as DGA (entropy: %.2f)", d, entropy)
		}
	}
}

func TestEvaluateSocketThreat(t *testing.T) {
	scanner := NewScanner()
	now := time.Now().UTC()

	policy := &models.EndpointPolicyConfig{
		EDRNetMonEnabled:     true,
		EDRBlockMaliciousIPs: true,
		EDRDetectC2Beaconing: true,
		EDRBlockedPorts:      []int{4444, 1337},
		EDRBlockedIPs:        []string{"198.51.100.23"},
	}

	// Test 1: Connection to blocked port 4444
	sock1 := SocketConnection{
		PID:         1001,
		ProcessName: "svchost.exe",
		Protocol:    "tcp",
		LocalIP:     "10.0.0.5",
		LocalPort:   50100,
		RemoteIP:    "192.0.2.1",
		RemotePort:  4444,
		State:       "ESTABLISHED",
		Direction:   "outbound",
	}
	res1 := scanner.evaluateSocketThreat(sock1, policy, now)
	if res1 == nil || res1.ThreatSeverity != "critical" {
		t.Fatalf("Expected port 4444 to be flagged as critical threat, got: %+v", res1)
	}

	// Test 2: Script engine (powershell) connecting to external non-web port
	sock2 := SocketConnection{
		PID:         2002,
		ProcessName: "powershell.exe",
		Protocol:    "tcp",
		LocalIP:     "10.0.0.5",
		LocalPort:   50200,
		RemoteIP:    "203.0.113.55",
		RemotePort:  8080,
		State:       "ESTABLISHED",
		Direction:   "outbound",
	}
	res2 := scanner.evaluateSocketThreat(sock2, policy, now)
	if res2 == nil || res2.ThreatSeverity != "high" {
		t.Fatalf("Expected powershell outbound to be flagged high, got: %+v", res2)
	}

	// Test 3: Blocked IP from policy
	sock3 := SocketConnection{
		PID:         3003,
		ProcessName: "curl",
		Protocol:    "tcp",
		LocalIP:     "10.0.0.5",
		LocalPort:   50300,
		RemoteIP:    "198.51.100.23",
		RemotePort:  443,
		State:       "ESTABLISHED",
		Direction:   "outbound",
	}
	res3 := scanner.evaluateSocketThreat(sock3, policy, now)
	if res3 == nil || res3.ThreatSeverity != "critical" || res3.ActionTaken != "blocked" {
		t.Fatalf("Expected blocked IP to be blocked, got: %+v", res3)
	}
}

func TestC2BeaconingDetection(t *testing.T) {
	scanner := NewScanner()
	baseTime := time.Now().UTC()

	policy := &models.EndpointPolicyConfig{
		EDRNetMonEnabled:     true,
		EDRDetectC2Beaconing: true,
	}

	// Simulate periodic beaconing every 10 seconds (with +/- 0.5s jitter)
	sock := SocketConnection{
		PID:         5555,
		ProcessName: "beacon.exe",
		Protocol:    "tcp",
		LocalIP:     "10.0.0.5",
		LocalPort:   50000,
		RemoteIP:    "198.51.100.99",
		RemotePort:  8443,
		State:       "ESTABLISHED",
		Direction:   "outbound",
	}

	// 1st tick
	_ = scanner.evaluateSocketThreat(sock, policy, baseTime)
	// 2nd tick at +10s
	_ = scanner.evaluateSocketThreat(sock, policy, baseTime.Add(10*time.Second))
	// 3rd tick at +20s
	res := scanner.evaluateSocketThreat(sock, policy, baseTime.Add(20*time.Second))

	if res == nil || res.ThreatSeverity != "critical" {
		t.Fatalf("Expected 3rd regular periodic beacon to trigger critical alert, got: %+v", res)
	}
}
