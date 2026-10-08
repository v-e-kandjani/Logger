package normalizer

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

func TestNormalizer(t *testing.T) {
	n := NewNormalizer()

	t.Run("Linux SSH Failed Login", func(t *testing.T) {
		event := &models.LogEvent{
			EventTimestamp: time.Now(),
			SourceIP:       net.ParseIP("192.168.1.10"),
			RawMessage:     "Failed password for invalid user admin from 185.220.101.5 port 42312 ssh2",
		}
		norm := n.Normalize(event)

		if norm.EventCategory != "authentication" {
			t.Errorf("expected authentication, got %s", norm.EventCategory)
		}
		if norm.EventAction != "login-failed" {
			t.Errorf("expected login-failed, got %s", norm.EventAction)
		}
		if norm.EventOutcome != "failure" {
			t.Errorf("expected failure, got %s", norm.EventOutcome)
		}
		if norm.Username != "admin" {
			t.Errorf("expected admin, got %s", norm.Username)
		}
		if norm.SourceIP != "185.220.101.5" {
			t.Errorf("expected 185.220.101.5, got %s", norm.SourceIP)
		}
		if norm.MitreTechnique != "T1110" {
			t.Errorf("expected T1110, got %s", norm.MitreTechnique)
		}
	})

	t.Run("Fortinet FortiGate Denied Connection", func(t *testing.T) {
		event := &models.LogEvent{
			EventTimestamp: time.Now(),
			Vendor:         "Fortinet",
			RawMessage:     `date=2026-10-08 time=20:10:00 devname="FGT60E" type=traffic subtype=forward action=deny srcip=203.0.113.195 dstip=10.0.0.15 srcport=51234 dstport=443`,
		}
		norm := n.Normalize(event)

		if norm.EventCategory != "network" {
			t.Errorf("expected network, got %s", norm.EventCategory)
		}
		if norm.EventAction != "connection-denied" {
			t.Errorf("expected connection-denied, got %s", norm.EventAction)
		}
		if norm.SourceIP != "203.0.113.195" {
			t.Errorf("expected 203.0.113.195, got %s", norm.SourceIP)
		}
		if norm.DestinationIP != "10.0.0.15" {
			t.Errorf("expected 10.0.0.15, got %s", norm.DestinationIP)
		}
	})

	t.Run("WatchGuard Firebox Denied Connection", func(t *testing.T) {
		event := &models.LogEvent{
			InternalID:     uuid.New(),
			EventTimestamp: time.Now(),
			Vendor:         "WatchGuard",
			RawMessage:     `2026-10-04T22:49:47 WatchGuard-Firebox firewall: disp="Deny" src="198.51.100.22" dst="10.0.0.1" src_port="44321" dst_port="80"`,
		}
		norm := n.Normalize(event)

		if norm.EventCategory != "network" {
			t.Errorf("expected network, got %s", norm.EventCategory)
		}
		if norm.EventAction != "connection-denied" {
			t.Errorf("expected connection-denied, got %s", norm.EventAction)
		}
		if norm.SourceIP != "198.51.100.22" {
			t.Errorf("expected 198.51.100.22, got %s", norm.SourceIP)
		}
	})

	t.Run("Fortinet FortiGate client-rst and accept traffic", func(t *testing.T) {
		logClientRst := `date=2026-10-08 time=22:22:13 devname="FGT-1" devid="FG200ETK20907839" eventtime=1791487333663103688 tz="+0300" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="1WARE" srcip=10.34.25.30 srcport=17898 srcintf="DEVOPS" srcintfrole="lan" dstip=172.16.65.10 dstport=443 dstintf="port4" dstintfrole="lan" srccountry="Reserved" dstcountry="Reserved" sessionid=1152113349 proto=6 action="client-rst" policyid=284 policytype="policy" poluuid="54bf16e6-c301-51f1-ea5f-d3a28de28f21" policyname="DevOps_to_Prod_" service="HTTPS" trandisp="noop" appcat="unscanned" duration=10 sentbyte=960775 rcvdbyte=4251583 sentpkt=1256 rcvdpkt=3573 srchwvendor="VMware"`
		event := &models.LogEvent{
			EventTimestamp: time.Now(),
			Vendor:         "Fortinet",
			RawMessage:     logClientRst,
		}
		norm := n.Normalize(event)

		if norm.EventCategory != "network" {
			t.Errorf("expected network, got %s", norm.EventCategory)
		}
		if norm.EventAction != "connection-allowed" {
			t.Errorf("expected connection-allowed, got %s", norm.EventAction)
		}
		if norm.SourceIP != "10.34.25.30" {
			t.Errorf("expected 10.34.25.30, got %s", norm.SourceIP)
		}
		if norm.DestinationIP != "172.16.65.10" {
			t.Errorf("expected 172.16.65.10, got %s", norm.DestinationIP)
		}
		if norm.DeviceName != "FGT-1" {
			t.Errorf("expected FGT-1, got %s", norm.DeviceName)
		}
		if norm.SourcePort != 17898 {
			t.Errorf("expected 17898, got %d", norm.SourcePort)
		}
		if norm.DestinationPort != 443 {
			t.Errorf("expected 443, got %d", norm.DestinationPort)
		}
	})

	t.Run("Fortinet UTM App-Ctrl Allowed (User False Positive Sample)", func(t *testing.T) {
		raw := `<190>date=2026-10-09 time=00:07:20 devname="FGT-1" devid="FG200ETK20907839" eventtime=1791493640783911952 tz="+0300" logid="1059028704" type="utm" subtype="app-ctrl" eventtype="signature" level="information" vd="TEKMAR" appid=15895 srcip=10.21.91.222 srccountry="Reserved" dstip=185.121.124.195 dstcountry="Turkey" srcport=57670 dstport=443 srcintf="Medmar-Vlan-915" srcintfrole="lan" dstintf="port5" dstintfrole="wan" proto=6 service="HTTPS" direction="outgoing" policyid=47 poluuid="e4c783b2-4df5-51f1-cddd-7b50e2139216" policytype="policy" sessionid=1153775136 applist="Medmar-Application-Control" action="pass" appcat="Network.Service" app="SSL" incidentserialno=297439689 msg="Network.Service: SSL" apprisk="elevated"`
		event := &models.LogEvent{
			EventTimestamp: time.Now(),
			Vendor:         "Fortinet",
			RawMessage:     raw,
		}
		norm := n.Normalize(event)

		if norm.EventCategory != "network" {
			t.Errorf("expected network, got %s", norm.EventCategory)
		}
		if norm.EventAction != "app-control-allowed" {
			t.Errorf("expected app-control-allowed, got %s", norm.EventAction)
		}
		if norm.EventOutcome != "allowed" {
			t.Errorf("expected allowed, got %s", norm.EventOutcome)
		}
		if norm.Severity != "INFORMATIONAL" {
			t.Errorf("expected INFORMATIONAL, got %s", norm.Severity)
		}
		if norm.RiskScore != 5 {
			t.Errorf("expected RiskScore 5, got %d", norm.RiskScore)
		}
		if norm.MitreTactic != "" || norm.MitreTechnique != "" {
			t.Errorf("expected empty MITRE tactic/technique on benign app flow, got %s / %s", norm.MitreTactic, norm.MitreTechnique)
		}
	})

	t.Run("Fortinet UTM WebFilter Allowed", func(t *testing.T) {
		raw := `<189>date=2026-10-09 time=00:39:03 devname="FGT-1" devid="FG200ETK20907839" eventtime=1791495542756106249 tz="+0300" logid="0317013312" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="notice" vd="1WARE" policyid=32 poluuid="2ba79f32-fdf3-51ea-e34e-3827612db846" policytype="policy" sessionid=1154263185 srcip=10.10.200.123 srcport=53765 srccountry="Reserved" srcintf="port4" srcintfrole="lan" srcuuid="51c8ac44-478d-51ec-09c0-5db5ff7c50eb" dstip=20.190.151.37 dstport=443 dstcountry="United States" dstintf="port3" dstintfrole="undefined" dstuuid="bc052d00-7c8b-51e9-2cf1-805c3c127fd2" proto=6 service="HTTPS" hostname="graph.microsoft.com" profile="g-default" action="passthrough" reqtype="direct" url="https://graph.microsoft.com/" sentbyte=207 rcvdbyte=0 direction="outgoing" msg="URL belongs to an allowed category in policy"`
		event := &models.LogEvent{
			EventTimestamp: time.Now(),
			Vendor:         "Fortinet",
			RawMessage:     raw,
		}
		norm := n.Normalize(event)

		if norm.EventCategory != "network" {
			t.Errorf("expected network, got %s", norm.EventCategory)
		}
		if norm.EventAction != "web-filter-allowed" {
			t.Errorf("expected web-filter-allowed, got %s", norm.EventAction)
		}
		if norm.EventOutcome != "allowed" {
			t.Errorf("expected allowed, got %s", norm.EventOutcome)
		}
		if norm.Severity != "INFORMATIONAL" {
			t.Errorf("expected INFORMATIONAL, got %s", norm.Severity)
		}
	})

	t.Run("Fortinet UTM IPS True Threat", func(t *testing.T) {
		raw := `date=2026-10-09 time=00:10:00 devname="FGT-1" type="utm" subtype="ips" action="dropped" attack="SQL.Injection" srcip=198.51.100.5 dstip=10.10.1.20 srcport=44211 dstport=80`
		event := &models.LogEvent{
			EventTimestamp: time.Now(),
			Vendor:         "Fortinet",
			RawMessage:     raw,
		}
		norm := n.Normalize(event)

		if norm.EventCategory != "threat" {
			t.Errorf("expected threat, got %s", norm.EventCategory)
		}
		if norm.EventAction != "intrusion-high-priority" {
			t.Errorf("expected intrusion-high-priority, got %s", norm.EventAction)
		}
		if norm.Severity != "CRITICAL" {
			t.Errorf("expected CRITICAL, got %s", norm.Severity)
		}
	})

	t.Run("Fortinet IPS Low-Severity Scanner Dropped (ZGrab user sample)", func(t *testing.T) {
		raw := `<185>date=2026-10-09 time=00:57:17 devname="FGT-1" devid="FG200ETK20907839" eventtime=1791496637490672551 tz="+0300" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="1WARE" severity="low" srcip=138.68.153.47 srccountry="United Kingdom" dstip=10.10.200.133 dstcountry="Reserved" srcintf="port3" srcintfrole="undefined" dstintf="port4" dstintfrole="lan" sessionid=1154541640 action="dropped" proto=6 service="HTTP" policyid=6 poluuid="ce3dfde8-84ca-51e9-4d22-981302c8abc3" policytype="policy" attack="ZGrab.Scanner" srcport=55050 dstport=80 hostname="185.121.124.16" url="/" agent="Mozilla/5.0 zgrab/0.x" httpmethod="GET" direction="outgoing" attackid=48805 profile="g-default" ref="http://www.fortinet.com/ids/VID48805" incidentserialno=297467798 msg="applications3: ZGrab.Scanner" crscore=5 craction=32768 crlevel="low"`
		norm := n.Normalize(&models.LogEvent{EventTimestamp: time.Now(), Vendor: "Fortinet", RawMessage: raw})

		if norm.EventCategory != "threat" || norm.EventAction != "ips-recon-blocked" || norm.EventOutcome != "blocked" {
			t.Errorf("expected threat/ips-recon-blocked/blocked, got %s/%s/%s", norm.EventCategory, norm.EventAction, norm.EventOutcome)
		}
		if norm.Severity != "LOW" || norm.RiskScore != 15 {
			t.Errorf("expected LOW/15, got %s/%d", norm.Severity, norm.RiskScore)
		}
		if norm.MitreTechnique != "T1595" {
			t.Errorf("expected T1595, got %s", norm.MitreTechnique)
		}
		if norm.SourceIP != "138.68.153.47" || norm.Extra["attack"] != "ZGrab.Scanner" {
			t.Errorf("unexpected src/attack: %s / %s", norm.SourceIP, norm.Extra["attack"])
		}
	})

	t.Run("Fortinet IPS High-Severity Allowed Escalates", func(t *testing.T) {
		raw := `date=2026-10-09 time=00:10:00 devname="FGT-1" type="utm" subtype="ips" severity="critical" action="detected" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" srcip=198.51.100.9 dstip=10.10.1.20 srcport=40000 dstport=443`
		norm := n.Normalize(&models.LogEvent{EventTimestamp: time.Now(), Vendor: "Fortinet", RawMessage: raw})

		if norm.EventAction != "intrusion-high-priority" || norm.EventOutcome != "detected" || norm.Severity != "CRITICAL" {
			t.Errorf("expected intrusion-high-priority/detected/CRITICAL, got %s/%s/%s", norm.EventAction, norm.EventOutcome, norm.Severity)
		}
	})
}
