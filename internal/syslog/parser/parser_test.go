package parser

import (
	"net"
	"testing"
)

func TestParseRFC5424(t *testing.T) {
	p := NewUniversalParser("test-node")
	msg := []byte("<34>1 2026-10-04T22:24:16.003Z myrouter.corp myapp 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] An event occurred")
	ip := net.ParseIP("192.168.1.1")

	event, err := p.Parse(msg, ip, 514, "UDP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.FacilityCode != 4 || event.Facility != "auth" {
		t.Errorf("expected facility auth (4), got %d (%s)", event.FacilityCode, event.Facility)
	}
	if event.SeverityCode != 2 || event.Severity != "CRITICAL" {
		t.Errorf("expected severity CRITICAL (2), got %d (%s)", event.SeverityCode, event.Severity)
	}
	if event.Hostname != "myrouter.corp" {
		t.Errorf("expected hostname myrouter.corp, got %s", event.Hostname)
	}
	if event.ApplicationName != "myapp" {
		t.Errorf("expected app myapp, got %s", event.ApplicationName)
	}
	if event.ProcessID != "1234" {
		t.Errorf("expected PID 1234, got %s", event.ProcessID)
	}
	if event.MessageID != "ID47" {
		t.Errorf("expected MsgID ID47, got %s", event.MessageID)
	}
	if event.Message != "An event occurred" {
		t.Errorf("expected message 'An event occurred', got '%s'", event.Message)
	}
	if event.ParserStatus != "SUCCESS" {
		t.Errorf("expected parser status SUCCESS, got %s", event.ParserStatus)
	}
	if event.RawMessage != string(msg) {
		t.Errorf("raw message integrity mismatch")
	}
}

func TestParseRFC3164(t *testing.T) {
	p := NewUniversalParser("test-node")
	msg := []byte("<13>Oct  4 22:24:16 firewall-gw kernel[55]: IP packet dropped on eth0")
	ip := net.ParseIP("10.0.0.1")

	event, err := p.Parse(msg, ip, 514, "UDP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.FacilityCode != 1 || event.Facility != "user" {
		t.Errorf("expected facility user (1), got %d (%s)", event.FacilityCode, event.Facility)
	}
	if event.SeverityCode != 5 || event.Severity != "NOTICE" {
		t.Errorf("expected severity NOTICE (5), got %d (%s)", event.SeverityCode, event.Severity)
	}
	if event.Hostname != "firewall-gw" {
		t.Errorf("expected hostname firewall-gw, got %s", event.Hostname)
	}
	if event.ApplicationName != "kernel" {
		t.Errorf("expected app kernel, got %s", event.ApplicationName)
	}
	if event.ProcessID != "55" {
		t.Errorf("expected PID 55, got %s", event.ProcessID)
	}
	if event.Message != "IP packet dropped on eth0" {
		t.Errorf("expected message 'IP packet dropped on eth0', got '%s'", event.Message)
	}
	if event.ParserStatus != "SUCCESS" {
		t.Errorf("expected status SUCCESS, got %s", event.ParserStatus)
	}
}

func TestParseMalformedFallback(t *testing.T) {
	p := NewUniversalParser("test-node")
	msg := []byte("DEVICE-XYZ arbitrary plain-text diagnostic trace without standard header")
	ip := net.ParseIP("172.16.10.50")

	event, err := p.Parse(msg, ip, 514, "UDP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.ParserStatus != "PARTIAL" {
		t.Errorf("expected PARTIAL status, got %s", event.ParserStatus)
	}
	if event.RawMessage != string(msg) {
		t.Errorf("raw message must be strictly preserved")
	}
	if event.FacilityCode != 1 || event.SeverityCode != 6 {
		t.Errorf("expected default fallback facility/severity")
	}
	if event.EventTimestamp.IsZero() {
		t.Errorf("event timestamp should be set to reception time")
	}
}

func TestParseWatchGuard_ISO(t *testing.T) {
	p := NewUniversalParser("test-node")
	msg := []byte("<134>2026-10-04T22:49:47 WatchGuard-Firebox-M370 firewall: msg_id=\"3000-0148\" disp=\"Allow\" policy=\"HTTPS-Proxy-00\" src=\"10.0.1.25\" dst=\"198.51.100.4\" pr=\"tcp\"")
	ip := net.ParseIP("192.168.1.254")

	event, err := p.Parse(msg, ip, 514, "UDP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.ParserStatus != "SUCCESS" {
		t.Errorf("expected SUCCESS status for WatchGuard log, got %s", event.ParserStatus)
	}
	if event.Vendor != "WatchGuard" {
		t.Errorf("expected vendor WatchGuard, got %s", event.Vendor)
	}
	if event.Product != "Firebox" {
		t.Errorf("expected product Firebox, got %s", event.Product)
	}
	if event.Hostname != "WatchGuard-Firebox-M370" {
		t.Errorf("expected hostname WatchGuard-Firebox-M370, got %s", event.Hostname)
	}
	if event.MessageID != "3000-0148" {
		t.Errorf("expected MessageID 3000-0148, got %s", event.MessageID)
	}
}

func TestParseWatchGuard_BSDFormat(t *testing.T) {
	p := NewUniversalParser("test-node")
	msg := []byte("<30>Oct  4 22:15:30 Firebox-Core firewall: msg_id=\"3000-0173\" Deny 203.0.113.5 198.51.100.20 80/tcp 54321 80 1-Trusted 0-External Firewall-Rule 48 127 (HTTP-proxy-00)")
	ip := net.ParseIP("10.0.1.1")

	event, err := p.Parse(msg, ip, 514, "UDP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.ParserStatus != "SUCCESS" {
		t.Errorf("expected SUCCESS status for WatchGuard BSD log, got %s", event.ParserStatus)
	}
	if event.Vendor != "WatchGuard" {
		t.Errorf("expected vendor WatchGuard, got %s", event.Vendor)
	}
	if event.Product != "Firebox" {
		t.Errorf("expected product Firebox, got %s", event.Product)
	}
	if event.MessageID != "3000-0173" {
		t.Errorf("expected MessageID 3000-0173, got %s", event.MessageID)
	}
	if event.ApplicationName != "Firewall (Deny)" {
		t.Errorf("expected ApplicationName 'Firewall (Deny)', got %s", event.ApplicationName)
	}
}

func TestParseWatchGuard_EventLog(t *testing.T) {
	p := NewUniversalParser("test-node")
	msg := []byte("<30>Oct  4 22:15:30 WatchGuard sessiond: msg_id=\"3E00-0004\" User authentication succeeded for admin from 10.0.1.100")
	ip := net.ParseIP("10.0.1.1")

	event, err := p.Parse(msg, ip, 514, "UDP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Vendor != "WatchGuard" {
		t.Errorf("expected vendor WatchGuard, got %s", event.Vendor)
	}
	if event.Product != "Firebox" {
		t.Errorf("expected product Firebox, got %s", event.Product)
	}
	if event.MessageID != "3E00-0004" {
		t.Errorf("expected MessageID 3E00-0004, got %s", event.MessageID)
	}
}

