package generator

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Options configuration for synthetic syslog generation
type Options struct {
	Target   string        // "127.0.0.1:514"
	Protocol string        // "udp" or "tcp"
	Vendor   string        // "all", "watchguard", "fortinet", "cisco", "linux"
	Count    int           // e.g. 25
	Delay    time.Duration // e.g. 50ms
}

var watchGuardTemplates = []string{
	`firewall: msg_id="3000-0148" disp="Allow" policy="HTTPS-Proxy-00" src="192.168.1.%d" dst="198.51.100.4" pr="tcp" duration=12 sent=1420 rcvd=6520`,
	`firewall: msg_id="3000-0173" disp="Deny" policy="Unhandled-Internal-Packet" src="192.168.1.%d" dst="8.8.8.8" pr="udp"`,
	`firewall: msg_id="3000-0151" Allow 192.168.1.%d 8.8.8.8 53/udp 61245 53 1-Trusted 0-External DNS 65 64 (DNS-00)`,
	`sessiond: msg_id="3E00-0004" User authentication succeeded for admin from 10.0.1.%d`,
	`iked: msg_id="0204-0001" IKE Phase 1 negotiation succeeded with peer 198.51.100.%d`,
	`firewall: msg_id="3000-0148" Deny 203.0.113.%d 198.51.100.20 80/tcp 54321 80 1-Trusted 0-External Firewall-Rule 48 127 (HTTP-proxy-00)`,
}

var fortinetTemplates = []string{
	`date=%s time=%s devname="FG100E-HQ" devid="FG100ETK18000123" type="traffic" subtype="forward" level="notice" vd="root" srcip="192.168.10.%d" dstip="1.1.1.1" action="accept" policyid=1 proto=6 service="HTTPS"`,
	`date=%s time=%s devname="FG100E-HQ" devid="FG100ETK18000123" type="utm" subtype="virus" level="warning" vd="root" srcip="192.168.10.%d" action="blocked" virus="EICAR_TEST_FILE"`,
}

var ciscoTemplates = []string{
	`%%ASA-6-302013: Built outbound TCP connection 492021 for outside:198.51.100.1/443 (198.51.100.1/443) to inside:10.0.2.%d/52114 (10.0.2.%d/52114)`,
	`%%ASA-4-106023: Deny udp src outside:203.0.113.%d/53412 dst inside:10.0.2.1/53 by access-group "outside_access_in" [0x0, 0x0]`,
}

var linuxTemplates = []string{
	`sshd[%d]: Accepted publickey for admin from 192.168.1.%d port 54222 ssh2: RSA SHA256:abc123xyz`,
	`sudo[%d]: pam_unix(sudo:session): session opened for user root(uid=0) by admin(uid=1000)`,
	`kernel: [ 1042.859211] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=198.51.100.%d DST=172.16.0.1 LEN=40 TOS=0x00 PROTO=TCP DPT=445`,
}

// ProduceLogs sends realistic syslog messages to target socket
func ProduceLogs(opts Options) (int, error) {
	if opts.Target == "" {
		opts.Target = "127.0.0.1:514"
	}
	if opts.Protocol == "" {
		opts.Protocol = "udp"
	}
	if opts.Count <= 0 {
		opts.Count = 25
	}
	if opts.Delay <= 0 {
		opts.Delay = 40 * time.Millisecond
	}

	proto := strings.ToLower(opts.Protocol)
	var conn net.Conn
	var err error

	if proto == "tcp" {
		conn, err = net.DialTimeout("tcp", opts.Target, 3*time.Second)
	} else {
		conn, err = net.Dial("udp", opts.Target)
	}
	if err != nil {
		return 0, fmt.Errorf("connect to %s (%s): %w", opts.Target, proto, err)
	}
	defer conn.Close()

	vendor := strings.ToLower(opts.Vendor)
	sent := 0

	for i := 0; i < opts.Count; i++ {
		now := time.Now()
		bsdTime := now.Format("Jan _2 15:04:05")
		isoDate := now.Format("2006-01-02")
		isoTime := now.Format("15:04:05")
		ipSuffix := (i % 250) + 2
		pri := 134 // Local0.Info default

		var payload string
		selectedVendor := vendor
		if selectedVendor == "all" || selectedVendor == "" {
			switch i % 4 {
			case 0:
				selectedVendor = "watchguard"
			case 1:
				selectedVendor = "fortinet"
			case 2:
				selectedVendor = "cisco"
			default:
				selectedVendor = "linux"
			}
		}

		switch selectedVendor {
		case "watchguard":
			pri = 134 // local0
			tmpl := watchGuardTemplates[rand.Intn(len(watchGuardTemplates))]
			msg := fmt.Sprintf(tmpl, ipSuffix)
			// Format RFC3164 with WatchGuard host
			payload = fmt.Sprintf("<%d>%s WatchGuard-Firebox-M370 %s", pri, bsdTime, msg)

		case "fortinet":
			pri = 189 // local7
			tmpl := fortinetTemplates[rand.Intn(len(fortinetTemplates))]
			msg := fmt.Sprintf(tmpl, isoDate, isoTime, ipSuffix)
			payload = fmt.Sprintf("<%d>%s FortiGate-Cluster %s", pri, bsdTime, msg)

		case "cisco":
			pri = 186 // local7.Info
			tmpl := ciscoTemplates[rand.Intn(len(ciscoTemplates))]
			msg := fmt.Sprintf(tmpl, ipSuffix, ipSuffix)
			payload = fmt.Sprintf("<%d>%s cisco-core-asa %s", pri, bsdTime, msg)

		default: // linux
			pri = 86 // authpriv.Info
			tmpl := linuxTemplates[rand.Intn(len(linuxTemplates))]
			pid := rand.Intn(30000) + 1000
			msg := fmt.Sprintf(tmpl, pid, ipSuffix)
			payload = fmt.Sprintf("<%d>%s srv-app-01 %s", pri, bsdTime, msg)
		}

		packetBytes := []byte(payload)
		if proto == "tcp" {
			packetBytes = append(packetBytes, '\n')
		}

		if _, err := conn.Write(packetBytes); err != nil {
			return sent, fmt.Errorf("send error at packet %d: %w", i+1, err)
		}
		sent++

		if opts.Delay > 0 && i < opts.Count-1 {
			time.Sleep(opts.Delay)
		}
	}

	return sent, nil
}
