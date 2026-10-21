package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
)

// Info holds local agent identity and host fingerprint
type Info struct {
	AgentUUID         string `json:"agent_uuid"`
	AuthToken         string `json:"auth_token,omitempty"`
	TenantSlug        string `json:"tenant_slug,omitempty"`
	Hostname          string `json:"hostname"`
	FQDN              string `json:"fqdn"`
	OSType            string `json:"os_type"`
	OSFamily          string `json:"os_family"`
	OSName            string `json:"os_name"`
	OSVersion         string `json:"os_version"`
	OSBuild           string `json:"os_build"`
	KernelVersion     string `json:"kernel_version"`
	Architecture      string `json:"architecture"`
	IPAddress         string `json:"ip_address"`
	MACAddress        string `json:"mac_address"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

// LoadOrGenerate loads existing identity from file, or creates a new stable UUID
func LoadOrGenerate(identityFilePath string) (*Info, error) {
	var info Info

	if identityFilePath != "" {
		if data, err := os.ReadFile(identityFilePath); err == nil {
			if err := json.Unmarshal(data, &info); err == nil && info.AgentUUID != "" {
				// Refresh runtime host telemetry while preserving UUID and AuthToken
				refreshHostTelemetry(&info)
				return &info, nil
			}
		}
	}

	// Generate new UUID
	info.AgentUUID = uuid.New().String()
	refreshHostTelemetry(&info)

	// Save identity if path provided
	if identityFilePath != "" {
		_ = SaveIdentity(identityFilePath, &info)
	}

	return &info, nil
}

// SaveIdentity writes identity data to persistent disk
func SaveIdentity(path string, info *Info) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func refreshHostTelemetry(info *Info) {
	hostname, _ := os.Hostname()
	info.Hostname = hostname
	info.FQDN = hostname
	info.OSType = runtime.GOOS
	info.Architecture = runtime.GOARCH

	// Resolve local IP and MAC
	ip, mac := getPrimaryNetwork()
	info.IPAddress = ip
	info.MACAddress = mac

	// Determine OS details
	detectOSDetails(info)

	// Fingerprint
	fpRaw := info.Hostname + ":" + info.OSType + ":" + info.Architecture + ":" + info.MACAddress
	hash := sha256.Sum256([]byte(fpRaw))
	info.DeviceFingerprint = hex.EncodeToString(hash[:16])
}

func getPrimaryNetwork() (string, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1", ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					return ipNet.IP.String(), iface.HardwareAddr.String()
				}
			}
		}
	}
	return "127.0.0.1", ""
}

func detectOSDetails(info *Info) {
	switch runtime.GOOS {
	case "windows":
		info.OSFamily = "windows"
		info.OSName = "Microsoft Windows"
	case "darwin":
		info.OSFamily = "darwin"
		info.OSName = "macOS"
	case "linux":
		info.OSFamily = "linux"
		info.OSName = "Linux"
		// Parse /etc/os-release if present
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					info.OSName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				} else if strings.HasPrefix(line, "ID=") {
					info.OSFamily = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
				} else if strings.HasPrefix(line, "VERSION_ID=") {
					info.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
				}
			}
		}
	default:
		info.OSFamily = runtime.GOOS
		info.OSName = runtime.GOOS
	}
}
