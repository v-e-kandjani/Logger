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
}
