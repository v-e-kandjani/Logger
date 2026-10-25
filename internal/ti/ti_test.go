package ti

import (
	"strings"
	"testing"

	"github.com/syslog-platform/logger/internal/models"
)

func TestMatcherLookups(t *testing.T) {
	m := NewMatcher()

	indicators := []models.TIIndicator{
		{
			ID:             1,
			IndicatorType:  "ip",
			IndicatorValue: "198.51.100.77",
			ThreatCategory: "c2_server",
			Severity:       "critical",
			Confidence:     95,
			Source:         "AlienVault OTX",
			IsActive:       true,
		},
		{
			ID:             2,
			IndicatorType:  "domain",
			IndicatorValue: "evil-malware.com",
			ThreatCategory: "phishing",
			Severity:       "high",
			Confidence:     90,
			Source:         "URLhaus",
			IsActive:       true,
		},
		{
			ID:             3,
			IndicatorType:  "sha256",
			IndicatorValue: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			ThreatCategory: "ransomware",
			Severity:       "critical",
			Confidence:     100,
			Source:         "CISA KEV",
			IsActive:       true,
		},
	}

	m.BuildSnapshot(indicators)

	// 1. IP Lookup
	hit := m.MatchIP("198.51.100.77")
	if hit == nil {
		t.Fatalf("expected IP hit, got nil")
	}
	if hit.IndicatorValue != "198.51.100.77" || hit.Severity != "critical" {
		t.Errorf("unexpected IP hit data: %+v", hit)
	}

	// Clean/Non-existent IP
	if m.MatchIP("8.8.8.8") != nil {
		t.Errorf("expected clean IP to return nil")
	}

	// 2. Domain Exact & Subdomain Lookup
	if m.MatchDomain("evil-malware.com") == nil {
		t.Errorf("expected exact domain hit")
	}
	if hitSub := m.MatchDomain("c2.sub.evil-malware.com"); hitSub == nil {
		t.Errorf("expected subdomain match on parent domain evil-malware.com")
	}

	// Clean Domain
	if m.MatchDomain("google.com") != nil {
		t.Errorf("expected clean domain to return nil")
	}

	// 3. Hash Lookup
	if m.MatchHash("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855") == nil {
		t.Errorf("expected case-insensitive hash hit")
	}
	if m.MatchHash("0000000000000000000000000000000000000000000000000000000000000000") != nil {
		t.Errorf("expected clean hash to return nil")
	}

	// 4. Syslog Match Helper
	syslogHit := m.MatchSyslog("10.0.0.1", "198.51.100.77", "safe.internal", "Connection established")
	if syslogHit == nil || syslogHit.IndicatorType != "ip" {
		t.Errorf("expected syslog destination IP match")
	}
}

func TestHarvesterParsers(t *testing.T) {
	h := NewHarvester()
	feed := &models.TIFeed{
		ID:                10,
		Name:              "Test Feed",
		IndicatorType:     "ip",
		ThreatCategory:    "botnet",
		DefaultConfidence: 85,
	}

	// 1. Plain List
	plainData := `# Comment
192.0.2.1
192.0.2.2 # inline comment
; another comment
192.0.2.3
`
	inds, err := h.parsePlainList(strings.NewReader(plainData), feed)
	if err != nil {
		t.Fatalf("parsePlainList failed: %v", err)
	}
	if len(inds) != 3 {
		t.Errorf("expected 3 indicators, got %d", len(inds))
	}

	// 2. CSV Parser
	csvData := `# URLhaus Database
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
1,2026-10-25,"http://malicious-drop.net/payload.exe",online,2026-10-25,malware_download,exe,https://urlhaus.abuse.ch,reporter1
`
	csvInds, err := h.parseCSV(strings.NewReader(csvData), feed)
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}
	if len(csvInds) < 1 {
		t.Errorf("expected at least 1 indicator from CSV, got %d", len(csvInds))
	}
}
