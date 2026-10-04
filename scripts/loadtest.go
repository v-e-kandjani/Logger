package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"time"
)

var sampleHosts = []string{"WatchGuard-Firebox-M370", "core-fw-01", "edge-router-02", "dist-sw-03", "linux-srv-10", "k8s-worker-05"}
var sampleApps = []string{"firewall", "sshd", "kernel", "nginx", "sudo", "systemd", "dockerd"}
var sampleMessages = []string{
	"msg_id=\"3000-0148\" disp=\"Allow\" policy=\"HTTPS-Proxy-00\" src=\"10.0.1.25\" dst=\"198.51.100.4\" pr=\"tcp\" duration=12 sent=1420 rcvd=6520",
	"msg_id=\"3000-0173\" disp=\"Deny\" policy=\"Unhandled-Internal-Packet\" src=\"192.168.10.45\" dst=\"8.8.8.8\" pr=\"udp\"",
	"Accepted publickey for admin from 10.0.4.22 port 54222 ssh2",
	"Connection reset by peer: 192.168.10.45",
	"TLS handshake failed: certificate expired",
	"Out of memory: Kill process 8912 (java) score 852 or sacrifice child",
	"BGP neighbor 172.16.0.1 Up (hold timer 180s)",
	"User 'valp' executed '/bin/systemctl restart syslog-platform' as root via sudo",
	"Packet dropped by firewall rule 104: SRC=198.51.100.22 DST=10.0.1.5 PROTO=TCP DPT=445",
}

var sampleWatchGuardMessages = []string{
	"firewall: msg_id=\"3000-0148\" Deny 203.0.113.5 198.51.100.20 80/tcp 54321 80 1-Trusted 0-External Firewall-Rule 48 127 (HTTP-proxy-00)",
	"firewall: msg_id=\"3000-0173\" Allow 10.0.1.50 172.16.1.10 443/tcp 51234 443 1-Trusted 0-External HTTPS-out 52 128 (HTTPS-proxy-00)",
	"firewall: msg_id=\"3000-0151\" Allow 192.168.1.105 8.8.8.8 53/udp 61245 53 1-Trusted 0-External DNS 65 64 (DNS-00)",
	"sessiond: msg_id=\"3E00-0004\" User authentication succeeded for admin from 10.0.1.100",
	"iked: msg_id=\"0204-0001\" IKE Phase 1 negotiation succeeded with peer 198.51.100.1",
	"firewall: msg_id=\"3000-0148\" disp=\"Allow\" policy=\"HTTPS-Proxy-00\" src=\"10.0.1.25\" dst=\"198.51.100.4\" pr=\"tcp\" duration=12 sent=1420 rcvd=6520",
	"firewall: msg_id=\"3000-0173\" disp=\"Deny\" policy=\"Unhandled-Internal-Packet\" src=\"192.168.10.45\" dst=\"8.8.8.8\" pr=\"udp\"",
}

func main() {
	target := flag.String("target", "127.0.0.1:514", "Target Syslog UDP host:port")
	eps := flag.Int("eps", 1000, "Events per second")
	duration := flag.Duration("duration", 10*time.Second, "Test run duration")
	vendor := flag.String("vendor", "all", "Traffic vendor profile: 'all' or 'watchguard'")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		panic(err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Printf("Generating synthetic syslog (%s) to %s at %d EPS for %v...\n", *vendor, *target, *eps, *duration)

	ticker := time.NewTicker(time.Second / time.Duration(*eps))
	defer ticker.Stop()

	timeout := time.After(*duration)
	count := 0
	startTime := time.Now()

	for {
		select {
		case <-timeout:
			actualEPS := float64(count) / time.Since(startTime).Seconds()
			fmt.Printf("Finished load test: Sent %d syslog packets (Average: %.1f EPS)\n", count, actualEPS)
			return
		case <-ticker.C:
			var payload string
			pri := rand.Intn(191)
			nowStr := time.Now().Format("Jan _2 15:04:05")

			if *vendor == "watchguard" {
				host := "WatchGuard-Firebox-M370"
				msg := sampleWatchGuardMessages[rand.Intn(len(sampleWatchGuardMessages))]
				payload = fmt.Sprintf("<%d>%s %s %s", pri, nowStr, host, msg)
			} else {
				host := sampleHosts[rand.Intn(len(sampleHosts))]
				app := sampleApps[rand.Intn(len(sampleApps))]
				msg := sampleMessages[rand.Intn(len(sampleMessages))]
				payload = fmt.Sprintf("<%d>%s %s %s[%d]: %s", pri, nowStr, host, app, rand.Intn(30000)+1000, msg)
			}

			_, _ = conn.Write([]byte(payload))
			count++
		}
	}
}
