package detector

import (
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		hostname   string
		app        string
		wantVendor string
		wantType   string
	}{
		{
			name:       "Fortinet FortiGate traffic log",
			raw:        `date=2026-10-08 time=14:22:01 devname="FG100D-CORP" devid="FG100D12345" type="traffic" srcip=192.168.1.50 dstip=8.8.8.8`,
			hostname:   "FG100D-CORP",
			app:        "",
			wantVendor: "Fortinet",
			wantType:   "Firewall",
		},
		{
			name:       "WatchGuard Firebox deny log",
			raw:        `Oct 08 14:25:31 Firebox firewall: msg_id="3000-0148" disp="Deny" src=10.0.0.5 dst=1.1.1.1 pr=tcp/443`,
			hostname:   "Firebox",
			app:        "firewall",
			wantVendor: "WatchGuard",
			wantType:   "Firewall",
		},
		{
			name:       "Cisco ASA connection teardown",
			raw:        `<166>Oct 08 2026 14:25:32: %ASA-6-302014: Teardown TCP connection 4521 for inside:192.168.1.10/443 to outside:203.0.113.5/54321`,
			hostname:   "192.168.1.1",
			app:        "",
			wantVendor: "Cisco",
			wantType:   "Firewall",
		},
		{
			name:       "Cisco Catalyst Switch port up/down",
			raw:        `<189>Oct 08 14:26:00 core-sw-01: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/24, changed state to up`,
			hostname:   "core-sw-01",
			app:        "",
			wantVendor: "Cisco",
			wantType:   "Switch",
		},
		{
			name:       "MikroTik RouterOS route announcement",
			raw:        `oct/08/2026 14:26:15 system,info,account user admin logged in from 192.168.88.10 via winbox`,
			hostname:   "MikroTik-Main",
			app:        "",
			wantVendor: "MikroTik",
			wantType:   "Router",
		},
		{
			name:       "Linux Server failed ssh auth",
			raw:        `Oct 08 14:27:01 srv-app-01 sshd[12345]: Failed password for invalid user admin from 192.168.1.99 port 54122 ssh2`,
			hostname:   "srv-app-01",
			app:        "sshd",
			wantVendor: "Linux",
			wantType:   "Server",
		},
		{
			name:       "Windows Active Directory EventID 4625",
			raw:        `Microsoft-Windows-Security-Auditing: An account failed to log on. EventID: 4625 Account Name: Administrator`,
			hostname:   "DC01",
			app:        "Microsoft-Windows-Security-Auditing",
			wantVendor: "Microsoft",
			wantType:   "Server",
		},
		{
			name:       "Palo Alto PAN-OS traffic",
			raw:        `1,2026/10/08 14:28:00,001801000000,TRAFFIC,drop,2304,2026/10/08 14:28:00,192.168.1.10,8.8.8.8`,
			hostname:   "pa-vm-50",
			app:        "",
			wantVendor: "Palo Alto",
			wantType:   "Firewall",
		},
		{
			name:       "pfSense packet filter log",
			raw:        `Oct 08 14:28:30 pfSense filterlog: 4,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.2,192.168.1.1`,
			hostname:   "pfSense",
			app:        "filterlog",
			wantVendor: "pfSense",
			wantType:   "Firewall",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Detect(tc.raw, tc.hostname, tc.app)
			if res.Vendor != tc.wantVendor {
				t.Errorf("Vendor got %s, want %s", res.Vendor, tc.wantVendor)
			}
			if res.DeviceType != tc.wantType {
				t.Errorf("DeviceType got %s, want %s", res.DeviceType, tc.wantType)
			}
		})
	}
}
