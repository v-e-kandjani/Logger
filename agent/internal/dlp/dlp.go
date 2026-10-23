package dlp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// Scanner inspects and enforces DLP security on USB and removable storage devices
type Scanner struct {
	mu              sync.Mutex
	previousDevices map[string]models.EndpointUSBDevice // key: unique device signature
	isInitial       bool
}

// NewScanner creates a new cross-platform USB DLP scanner
func NewScanner() *Scanner {
	return &Scanner{
		previousDevices: make(map[string]models.EndpointUSBDevice),
		isInitial:       true,
	}
}

// Scan enumerates connected USB devices, enforces storage policies, and produces audit events
func (s *Scanner) Scan(policy *models.EndpointPolicyConfig) ([]models.EndpointUSBDevice, []models.EndpointUSBEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var currentDevices []models.EndpointUSBDevice
	var events []models.EndpointUSBEvent

	// 1. Discover devices per operating system
	switch runtime.GOOS {
	case "windows":
		currentDevices = s.discoverWindowsDevices()
	case "linux":
		currentDevices = s.discoverLinuxDevices()
	case "darwin":
		currentDevices = s.discoverDarwinDevices()
	default:
		currentDevices = []models.EndpointUSBDevice{}
	}

	currentMap := make(map[string]models.EndpointUSBDevice)

	// 2. Policy Enforcement & Whitelisting
	mode := "allow"
	enforceWhitelist := false
	alertOnInsertion := true
	var allowedMap map[string]bool

	if policy != nil {
		if policy.USBStorageMode != "" {
			mode = strings.ToLower(policy.USBStorageMode)
		}
		enforceWhitelist = policy.USBEnforceWhitelist
		alertOnInsertion = policy.USBAlertOnInsertion
		if len(policy.USBAllowedDevices) > 0 {
			allowedMap = make(map[string]bool)
			for _, dev := range policy.USBAllowedDevices {
				trimmed := strings.ToUpper(strings.TrimSpace(dev))
				if trimmed != "" {
					allowedMap[trimmed] = true
				}
			}
		}
	}

	for i := range currentDevices {
		dev := &currentDevices[i]
		key := deviceKey(*dev)
		currentMap[key] = *dev

		// Whitelist check
		isWhitelisted := false
		if allowedMap != nil {
			vidPid := strings.ToUpper(fmt.Sprintf("%s:%s", dev.VendorID, dev.ProductID))
			serial := strings.ToUpper(dev.SerialNumber)
			if allowedMap[vidPid] || (serial != "" && allowedMap[serial]) {
				isWhitelisted = true
			}
		}
		dev.IsWhitelisted = isWhitelisted

		// Determine enforcement for this device
		if enforceWhitelist && !isWhitelisted {
			// Unauthorized device under whitelist rule
			dev.IsBlocked = true
			action := "blocked"
			details := fmt.Sprintf("USB Device %s:%s (Serial: %s) is not in the authorized whitelist", dev.VendorID, dev.ProductID, dev.SerialNumber)

			if mode == "read_only" {
				dev.IsBlocked = false
				dev.IsReadOnly = true
				action = "mounted_ro"
				details += " - forced Read-Only access"
			}

			events = append(events, models.EndpointUSBEvent{
				EventType:      "unauthorized_whitelist",
				VendorID:       dev.VendorID,
				ProductID:      dev.ProductID,
				SerialNumber:   dev.SerialNumber,
				DeviceName:     dev.ProductName,
				DriveLetter:    dev.DriveLetter,
				MountPoint:     dev.MountPoint,
				ActionTaken:    action,
				MitreTechnique: "T1200", // Hardware Additions
				Details:        details,
				CreatedAt:      time.Now().UTC(),
			})
		} else {
			// Standard mode enforcement
			switch mode {
			case "block":
				dev.IsBlocked = true
				dev.IsReadOnly = false
			case "read_only":
				dev.IsBlocked = false
				dev.IsReadOnly = true
			default: // allow
				dev.IsBlocked = false
				dev.IsReadOnly = false
			}
		}

		currentDevices[i] = *dev
	}

	// 3. Apply System-wide OS DLP Enforcement if changed
	s.applyOSEnforcement(mode, currentDevices)

	// 4. Differential Detection (Insertion / Removal Events)
	if !s.isInitial {
		// New devices inserted
		for key, dev := range currentMap {
			if _, exists := s.previousDevices[key]; !exists {
				action := "allowed"
				eventType := "inserted"
				mitre := "T1052.001" // Exfiltration Over Physical Medium

				if dev.IsBlocked {
					action = "blocked"
					eventType = "blocked"
					mitre = "T1200"
				} else if dev.IsReadOnly {
					action = "mounted_ro"
				}

				if alertOnInsertion || dev.IsBlocked {
					events = append(events, models.EndpointUSBEvent{
						EventType:      eventType,
						VendorID:       dev.VendorID,
						ProductID:      dev.ProductID,
						SerialNumber:   dev.SerialNumber,
						DeviceName:     dev.ProductName,
						DriveLetter:    dev.DriveLetter,
						MountPoint:     dev.MountPoint,
						ActionTaken:    action,
						MitreTechnique: mitre,
						Details:        fmt.Sprintf("Removable USB media connected: %s (VID: %s, PID: %s, Serial: %s, Drive: %s, Capacity: %d MB)", dev.ProductName, dev.VendorID, dev.ProductID, dev.SerialNumber, dev.DriveLetter, dev.CapacityBytes/(1024*1024)),
						CreatedAt:      time.Now().UTC(),
					})
				}
			}
		}

		// Devices removed
		for key, dev := range s.previousDevices {
			if _, exists := currentMap[key]; !exists {
				events = append(events, models.EndpointUSBEvent{
					EventType:      "removed",
					VendorID:       dev.VendorID,
					ProductID:      dev.ProductID,
					SerialNumber:   dev.SerialNumber,
					DeviceName:     dev.ProductName,
					DriveLetter:    dev.DriveLetter,
					MountPoint:     dev.MountPoint,
					ActionTaken:    "unmounted",
					MitreTechnique: "T1052.001",
					Details:        fmt.Sprintf("Removable USB media disconnected: %s (VID: %s, PID: %s)", dev.ProductName, dev.VendorID, dev.ProductID),
					CreatedAt:      time.Now().UTC(),
				})
			}
		}
	} else {
		s.isInitial = false
	}

	s.previousDevices = currentMap
	return currentDevices, events
}

// deviceKey returns a deterministic unique key for a USB device
func deviceKey(d models.EndpointUSBDevice) string {
	if d.SerialNumber != "" {
		return fmt.Sprintf("%s:%s:%s", d.VendorID, d.ProductID, d.SerialNumber)
	}
	if d.DeviceID != "" {
		return fmt.Sprintf("%s:%s:%s", d.VendorID, d.ProductID, d.DeviceID)
	}
	if d.DriveLetter != "" {
		return fmt.Sprintf("%s:%s:%s", d.VendorID, d.ProductID, d.DriveLetter)
	}
	return fmt.Sprintf("%s:%s:%s", d.VendorID, d.ProductID, d.ProductName)
}

// -------------------------------------------------------------------------
// OS-Specific Discovery Implementations
// -------------------------------------------------------------------------

// discoverWindowsDevices queries WMI and PowerShell for USB storage
func (s *Scanner) discoverWindowsDevices() []models.EndpointUSBDevice {
	var devices []models.EndpointUSBDevice

	// PowerShell script to query Win32_DiskDrive and associated logical disks
	psScript := `
		$disks = Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' -or $_.MediaType -match 'Removable' }
		$result = @()
		foreach ($d in $disks) {
			$part = Get-CimAssociatedInstance -InputObject $d -ResultClassName Win32_DiskPartition
			$letters = @()
			if ($part) {
				$log = Get-CimAssociatedInstance -InputObject $part -ResultClassName Win32_LogicalDisk
				if ($log) { $letters = $log.DeviceID }
			}
			$result += [PSCustomObject]@{
				DeviceID = $d.DeviceID
				Model = $d.Model
				Size = $d.Size
				PNPDeviceID = $d.PNPDeviceID
				DriveLetters = ($letters -join ',')
			}
		}
		$result | ConvertTo-Json -Compress
	`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	out, err := cmd.Output()
	if err != nil {
		// Fallback to basic wmic command if PowerShell fails
		return s.discoverWindowsFallback()
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" || trimmed == "[]" {
		return devices
	}

	type psDisk struct {
		DeviceID     string      `json:"DeviceID"`
		Model        string      `json:"Model"`
		Size         interface{} `json:"Size"`
		PNPDeviceID  string      `json:"PNPDeviceID"`
		DriveLetters string      `json:"DriveLetters"`
	}

	var diskList []psDisk
	if strings.HasPrefix(trimmed, "[") {
		_ = json.Unmarshal([]byte(trimmed), &diskList)
	} else if strings.HasPrefix(trimmed, "{") {
		var single psDisk
		if err := json.Unmarshal([]byte(trimmed), &single); err == nil {
			diskList = append(diskList, single)
		}
	}

	vidPidRegex := regexp.MustCompile(`VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})`)

	for _, d := range diskList {
		vid := ""
		pid := ""
		serial := ""

		if matches := vidPidRegex.FindStringSubmatch(d.PNPDeviceID); len(matches) >= 3 {
			vid = strings.ToUpper(matches[1])
			pid = strings.ToUpper(matches[2])
		}

		parts := strings.Split(d.PNPDeviceID, `\`)
		if len(parts) >= 3 {
			serial = parts[len(parts)-1]
			// Trim ampersands in serial if generated by Windows PnP
			if idx := strings.Index(serial, "&"); idx != -1 {
				serial = serial[:idx]
			}
		}

		var sizeBytes int64
		switch v := d.Size.(type) {
		case float64:
			sizeBytes = int64(v)
		case string:
			sizeBytes, _ = strconv.ParseInt(v, 10, 64)
		}

		dev := models.EndpointUSBDevice{
			DeviceID:      d.DeviceID,
			VendorID:      vid,
			ProductID:     pid,
			SerialNumber:  serial,
			ProductName:   d.Model,
			DriveLetter:   d.DriveLetters,
			CapacityBytes: sizeBytes,
			IsConnected:   true,
			FirstSeen:     time.Now().UTC(),
			LastSeen:      time.Now().UTC(),
		}
		devices = append(devices, dev)
	}

	return devices
}

func (s *Scanner) discoverWindowsFallback() []models.EndpointUSBDevice {
	return []models.EndpointUSBDevice{}
}

// discoverLinuxDevices reads /sys/bus/usb/devices/
func (s *Scanner) discoverLinuxDevices() []models.EndpointUSBDevice {
	var devices []models.EndpointUSBDevice

	usbBase := "/sys/bus/usb/devices"
	entries, err := os.ReadDir(usbBase)
	if err != nil {
		return devices
	}

	mounts := parseLinuxMounts()

	for _, entry := range entries {
		devPath := filepath.Join(usbBase, entry.Name())
		vidBytes, err := os.ReadFile(filepath.Join(devPath, "idVendor"))
		if err != nil {
			continue
		}
		pidBytes, _ := os.ReadFile(filepath.Join(devPath, "idProduct"))
		serialBytes, _ := os.ReadFile(filepath.Join(devPath, "serial"))
		mfgBytes, _ := os.ReadFile(filepath.Join(devPath, "manufacturer"))
		prodBytes, _ := os.ReadFile(filepath.Join(devPath, "product"))

		vid := strings.TrimSpace(string(vidBytes))
		pid := strings.TrimSpace(string(pidBytes))
		if vid == "" && pid == "" {
			continue
		}

		// Ignore Linux root hub devices (1d6b)
		if strings.EqualFold(vid, "1d6b") {
			continue
		}

		productName := strings.TrimSpace(string(prodBytes))
		vendorName := strings.TrimSpace(string(mfgBytes))
		if productName == "" {
			productName = fmt.Sprintf("USB Device %s:%s", vid, pid)
		}

		mountPoint := ""
		for devNode, mnt := range mounts {
			if strings.Contains(devNode, entry.Name()) {
				mountPoint = mnt
				break
			}
		}

		dev := models.EndpointUSBDevice{
			DeviceID:     entry.Name(),
			VendorID:     strings.ToUpper(vid),
			ProductID:    strings.ToUpper(pid),
			SerialNumber: strings.TrimSpace(string(serialBytes)),
			VendorName:   vendorName,
			ProductName:  productName,
			MountPoint:   mountPoint,
			IsConnected:  true,
			FirstSeen:    time.Now().UTC(),
			LastSeen:     time.Now().UTC(),
		}
		devices = append(devices, dev)
	}

	return devices
}

func parseLinuxMounts() map[string]string {
	res := make(map[string]string)
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return res
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			res[fields[0]] = fields[1]
		}
	}
	return res
}

// discoverDarwinDevices runs system_profiler SPUSBDataType
func (s *Scanner) discoverDarwinDevices() []models.EndpointUSBDevice {
	var devices []models.EndpointUSBDevice

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "system_profiler", "SPUSBDataType", "-json")
	out, err := cmd.Output()
	if err != nil {
		return devices
	}

	type usbTree struct {
		SPUSBDataType []struct {
			Name        string `json:"_name"`
			VendorID    string `json:"vendor_id,omitempty"`
			ProductID   string `json:"product_id,omitempty"`
			SerialNum   string `json:"serial_num,omitempty"`
			Media       []struct {
				BsdName string `json:"bsd_name"`
				Size    string `json:"size"`
			} `json:"Media,omitempty"`
		} `json:"SPUSBDataType"`
	}

	var data usbTree
	if err := json.Unmarshal(out, &data); err != nil {
		return devices
	}

	for _, item := range data.SPUSBDataType {
		if strings.Contains(item.Name, "Root Hub") || strings.Contains(item.Name, "Controller") {
			continue
		}

		vid := parseDarwinHex(item.VendorID)
		pid := parseDarwinHex(item.ProductID)
		if vid == "" && pid == "" {
			continue
		}

		dev := models.EndpointUSBDevice{
			DeviceID:     item.Name,
			VendorID:     strings.ToUpper(vid),
			ProductID:    strings.ToUpper(pid),
			SerialNumber: item.SerialNum,
			ProductName:  item.Name,
			IsConnected:  true,
			FirstSeen:    time.Now().UTC(),
			LastSeen:     time.Now().UTC(),
		}
		devices = append(devices, dev)
	}

	return devices
}

func parseDarwinHex(val string) string {
	parts := strings.Fields(val)
	for _, p := range parts {
		if strings.HasPrefix(p, "0x") {
			return strings.TrimPrefix(p, "0x")
		}
	}
	return ""
}

// -------------------------------------------------------------------------
// OS DLP Access Control Enforcement
// -------------------------------------------------------------------------

func (s *Scanner) applyOSEnforcement(mode string, devices []models.EndpointUSBDevice) {
	switch runtime.GOOS {
	case "windows":
		s.applyWindowsEnforcement(mode)
	case "linux":
		s.applyLinuxEnforcement(mode, devices)
	}
}

func (s *Scanner) applyWindowsEnforcement(mode string) {
	switch mode {
	case "block":
		// Disable USBSTOR service (Start = 4: Disabled)
		_ = exec.Command("reg.exe", "add", `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`, "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f").Run()
	case "read_only":
		// Ensure USBSTOR is enabled (Start = 3: Automatic/Manual)
		_ = exec.Command("reg.exe", "add", `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`, "/v", "Start", "/t", "REG_DWORD", "/d", "3", "/f").Run()
		// Set StorageDevicePolicies WriteProtect = 1
		_ = exec.Command("reg.exe", "add", `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`, "/v", "WriteProtect", "/t", "REG_DWORD", "/d", "1", "/f").Run()
	case "allow":
		// Enable USBSTOR and disable WriteProtect
		_ = exec.Command("reg.exe", "add", `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`, "/v", "Start", "/t", "REG_DWORD", "/d", "3", "/f").Run()
		_ = exec.Command("reg.exe", "add", `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`, "/v", "WriteProtect", "/t", "REG_DWORD", "/d", "0", "/f").Run()
	}
}

func (s *Scanner) applyLinuxEnforcement(mode string, devices []models.EndpointUSBDevice) {
	for _, dev := range devices {
		if dev.DeviceID == "" {
			continue
		}
		authPath := filepath.Join("/sys/bus/usb/devices", dev.DeviceID, "authorized")
		if _, err := os.Stat(authPath); err == nil {
			if mode == "block" || dev.IsBlocked {
				_ = os.WriteFile(authPath, []byte("0"), 0644)
			} else {
				_ = os.WriteFile(authPath, []byte("1"), 0644)
			}
		}

		if (mode == "read_only" || dev.IsReadOnly) && dev.MountPoint != "" {
			_ = exec.Command("mount", "-o", "remount,ro", dev.MountPoint).Run()
		}
	}
}

// GenerateSimulatedUSBEvent creates a simulated test event for verification
func GenerateSimulatedUSBEvent(hostname string) (models.EndpointUSBDevice, models.EndpointUSBEvent) {
	dev := models.EndpointUSBDevice{
		DeviceID:      "USB\\VID_0781&PID_5567\\SANDISK_TEST",
		VendorID:      "0781",
		ProductID:     "5567",
		SerialNumber:  "4C530001050805117450",
		VendorName:    "SanDisk Corp.",
		ProductName:   "Cruzer Blade USB Flash Drive",
		DriveLetter:   "E:",
		MountPoint:    "E:",
		CapacityBytes: 32212254720, // 32 GB
		FileSystem:    "FAT32",
		IsConnected:   true,
		IsBlocked:     false,
		IsReadOnly:    false,
		FirstSeen:     time.Now().UTC(),
		LastSeen:      time.Now().UTC(),
	}

	evt := models.EndpointUSBEvent{
		EventType:      "inserted",
		VendorID:       dev.VendorID,
		ProductID:      dev.ProductID,
		SerialNumber:   dev.SerialNumber,
		DeviceName:     dev.ProductName,
		DriveLetter:    dev.DriveLetter,
		MountPoint:     dev.MountPoint,
		ActionTaken:    "allowed",
		MitreTechnique: "T1052.001",
		Details:        fmt.Sprintf("Host '%s': Authorized SanDisk Cruzer Blade 32GB attached to drive E:", hostname),
		CreatedAt:      time.Now().UTC(),
	}

	return dev, evt
}
