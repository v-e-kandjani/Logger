package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	DefaultConfigPath = "/etc/logseal/proxy.json"
	FallbackConfig    = "./proxy.json"
	ProxyVersion      = "1.5.12"
)

// ProxyConfig stores local forwarder settings
type ProxyConfig struct {
	Endpoint     string `json:"endpoint"`       // e.g. https://168.231.106.208:8443
	NodeName     string `json:"node_name"`      // Local identifier
	Token        string `json:"token"`          // Secret edge auth token
	ListenUDP    string `json:"listen_udp"`     // e.g. :514
	ListenTCP    string `json:"listen_tcp"`     // e.g. :514
	SpoolDir     string `json:"spool_dir"`      // /var/spool/logseal
	InsecureTLS  bool   `json:"insecure_tls"`   // Allow self-signed certificates
	MaxBatchSize int    `json:"max_batch_size"` // Max events per HTTP push
	MaxSpoolMB   int    `json:"max_spool_mb"`   // Max local disk spool storage
}

// LogPacket represents a captured local syslog message
type LogPacket struct {
	Data       string `json:"data"`
	SourceIP   string `json:"source_ip"`
	SourcePort uint16 `json:"source_port"`
	Protocol   string `json:"protocol"`
	Timestamp  string `json:"timestamp"`
}

// HeartbeatResponse from Cloud
type HeartbeatResponse struct {
	Status              string                 `json:"status"`
	Message             string                 `json:"message"`
	NodeID              string                 `json:"node_id"`
	NodeName            string                 `json:"node_name"`
	TenantName          string                 `json:"tenant_name"`
	SyncInterval        string                 `json:"sync_interval"`
	SyncIntervalSeconds int                    `json:"sync_interval_seconds"`
	LDAPConfig          map[string]interface{} `json:"ldap_config,omitempty"`
}

type IngestResponse struct {
	Status              string `json:"status"`
	Ingested            int64  `json:"ingested"`
	SyncInterval        string `json:"sync_interval"`
	SyncIntervalSeconds int    `json:"sync_interval_seconds"`
}

// ProxyDaemon encapsulates the forwarder runtime
type ProxyDaemon struct {
	cfg          ProxyConfig
	configPath   string
	httpClient   *http.Client
	queue        chan LogPacket
	spoolFile    *os.File
	spoolMu      sync.Mutex
	startTime    time.Time
	scheduleMu   sync.RWMutex
	syncInterval string // Cloud-controlled: "online", "every 60 second", etc.
	intervalSecs int
	stopCh       chan struct{}
	wg           sync.WaitGroup

	// Telemetry counters
	receivedLogs atomic.Int64
	forwardedLogs atomic.Int64
	spooledLogs  atomic.Int64
}

func main() {
	var (
		cfgFile     = flag.String("config", "", "Path to configuration file")
		endpoint    = flag.String("endpoint", "", "Cloud Logger Endpoint URL (e.g. https://168.231.106.208:8443)")
		nodeName    = flag.String("name", "", "Edge Node Name")
		token       = flag.String("token", "", "Authentication Token")
		listenUDP   = flag.String("listen-udp", ":514", "Syslog UDP listen address")
		listenTCP   = flag.String("listen-tcp", ":514", "Syslog TCP listen address")
		spoolDir    = flag.String("spool-dir", "/var/spool/logseal", "Directory for offline spool buffering")
		insecureTLS = flag.Bool("insecure", true, "Skip TLS certificate validation")
		setupFlag   = flag.Bool("setup", false, "Run interactive connection setup wizard")
		versionFlag = flag.Bool("version", false, "Display version and exit")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Valtrivo LogSeal Edge Proxy Forwarder Node v%s\n", ProxyVersion)
		os.Exit(0)
	}

	// Determine configuration file path
	targetConfig := *cfgFile
	if targetConfig == "" {
		if _, err := os.Stat(DefaultConfigPath); err == nil {
			targetConfig = DefaultConfigPath
		} else if _, err := os.Stat(FallbackConfig); err == nil {
			targetConfig = FallbackConfig
		} else {
			// Check if /etc/logseal can be written or use ./proxy.json
			if os.Geteuid() == 0 {
				targetConfig = DefaultConfigPath
			} else {
				targetConfig = FallbackConfig
			}
		}
	}

	// Run interactive setup dialog if requested or if no config exists and interactive terminal
	if *setupFlag || (*endpoint == "" && *token == "" && !fileExists(targetConfig) && isTerminal()) {
		runInteractiveSetup(targetConfig)
	}

	// Load configuration
	cfg := loadConfig(targetConfig)

	// Command-line flag overrides
	if *endpoint != "" {
		cfg.Endpoint = *endpoint
	}
	if *nodeName != "" {
		cfg.NodeName = *nodeName
	}
	if *token != "" {
		cfg.Token = *token
	}
	if *listenUDP != "" {
		cfg.ListenUDP = *listenUDP
	}
	if *listenTCP != "" {
		cfg.ListenTCP = *listenTCP
	}
	if *spoolDir != "" {
		cfg.SpoolDir = *spoolDir
	}
	if flag.Lookup("insecure") != nil {
		cfg.InsecureTLS = *insecureTLS
	}

	// Validate minimal requirements
	if cfg.Endpoint == "" || cfg.Token == "" {
		fmt.Println("\n[!] Configuration missing. Please run with -setup or provide -endpoint and -token.")
		fmt.Println("Example: logseal-proxy -setup")
		fmt.Println("Example: logseal-proxy -endpoint https://168.231.106.208:8443 -token lp_edge_xxx -name branch-1")
		os.Exit(1)
	}

	daemon := NewProxyDaemon(cfg, targetConfig)
	daemon.Start()

	// Wait for OS termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[Edge Proxy] Received signal %v, shutting down gracefully...", sig)
	daemon.Stop()
	log.Println("[Edge Proxy] Shutdown complete.")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func loadConfig(path string) ProxyConfig {
	cfg := ProxyConfig{
		ListenUDP:    ":514",
		ListenTCP:    ":514",
		SpoolDir:     "/var/spool/logseal",
		InsecureTLS:  true,
		MaxBatchSize: 500,
		MaxSpoolMB:   500,
	}

	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	if cfg.MaxBatchSize <= 0 {
		cfg.MaxBatchSize = 500
	}
	if cfg.MaxSpoolMB <= 0 {
		cfg.MaxSpoolMB = 500
	}
	return cfg
}

func saveConfig(path string, cfg ProxyConfig) error {
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// runInteractiveSetup provides an interactive terminal connection dialog
func runInteractiveSetup(configPath string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println()
	fmt.Println("==================================================================")
	fmt.Println("        VALTRIVO LOGSEAL - EDGE PROXY NODE CONNECTION DIALOG      ")
	fmt.Println("==================================================================")
	fmt.Println("Connect this Linux host to your Cloud Logger instance to forward")
	fmt.Println("syslog streams securely. The Cloud will manage the schedule.")
	fmt.Println("==================================================================")
	fmt.Println()

	existing := loadConfig(configPath)

	// 1. Cloud Endpoint
	defaultEndpoint := existing.Endpoint
	if defaultEndpoint == "" {
		defaultEndpoint = "https://168.231.106.208:8443"
	}
	fmt.Printf("[1/3] Cloud FQDN or IP Endpoint URL [%s]:\n> ", defaultEndpoint)
	epInput, _ := reader.ReadString('\n')
	epInput = strings.TrimSpace(epInput)
	if epInput != "" {
		existing.Endpoint = epInput
	} else {
		existing.Endpoint = defaultEndpoint
	}
	if !strings.HasPrefix(existing.Endpoint, "http://") && !strings.HasPrefix(existing.Endpoint, "https://") {
		existing.Endpoint = "https://" + existing.Endpoint
	}

	// 2. Node Name
	hostname, _ := os.Hostname()
	defaultName := existing.NodeName
	if defaultName == "" {
		defaultName = hostname
		if defaultName == "" {
			defaultName = "edge-proxy-node-1"
		}
	}
	fmt.Printf("\n[2/3] Edge Node Friendly Name [%s]:\n> ", defaultName)
	nameInput, _ := reader.ReadString('\n')
	nameInput = strings.TrimSpace(nameInput)
	if nameInput != "" {
		existing.NodeName = nameInput
	} else {
		existing.NodeName = defaultName
	}

	// 3. Auth Token
	defaultToken := existing.Token
	tokenPrompt := "[3/3] Authentication Token (Generated from Cloud Settings):"
	if defaultToken != "" {
		tokenPrompt = fmt.Sprintf("[3/3] Authentication Token [%s...]:", defaultToken[:min(len(defaultToken), 12)])
	}
	fmt.Println("\n" + tokenPrompt)
	fmt.Print("> ")
	tokenInput, _ := reader.ReadString('\n')
	tokenInput = strings.TrimSpace(tokenInput)
	if tokenInput != "" {
		existing.Token = tokenInput
	}

	// Insecure TLS prompt
	fmt.Print("\nAllow self-signed / untrusted TLS certificate? [Y/n]: ")
	insecureInput, _ := reader.ReadString('\n')
	insecureInput = strings.ToLower(strings.TrimSpace(insecureInput))
	existing.InsecureTLS = (insecureInput == "" || insecureInput == "y" || insecureInput == "yes")

	// Testing connection
	fmt.Println("\n[*] Verifying connection to Cloud Logger...")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: existing.InsecureTLS},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	hbReq := map[string]interface{}{
		"token":          existing.Token,
		"node_name":      existing.NodeName,
		"version":        ProxyVersion,
		"buffered_count": 0,
		"uptime_seconds": 0,
	}
	reqData, _ := json.Marshal(hbReq)
	resp, err := client.Post(strings.TrimRight(existing.Endpoint, "/")+"/api/v1/edge/heartbeat", "application/json", bytes.NewReader(reqData))
	if err != nil {
		fmt.Printf("[!] Connection failed: %v\n", err)
		fmt.Print("Save configuration anyway? [y/N]: ")
		saveAnyway, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(saveAnyway)) != "y" {
			fmt.Println("Setup aborted.")
			os.Exit(1)
		}
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var hbResp HeartbeatResponse
			_ = json.NewDecoder(resp.Body).Decode(&hbResp)
			fmt.Println("[+] CONNECTION SUCCESSFUL!")
			fmt.Printf("    Cloud Verified Name: %s (Tenant: %s)\n", hbResp.NodeName, hbResp.TenantName)
			fmt.Printf("    Active Cloud Schedule: [%s]\n", hbResp.SyncInterval)
			fmt.Println("    (Notice: All transmission schedules are controlled by the Cloud)")
		} else {
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("[!] Cloud rejected authentication (HTTP %d): %s\n", resp.StatusCode, string(body))
			fmt.Print("Save configuration anyway? [y/N]: ")
			saveAnyway, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(saveAnyway)) != "y" {
				fmt.Println("Setup aborted.")
				os.Exit(1)
			}
		}
	}

	if err := saveConfig(configPath, existing); err != nil {
		fmt.Printf("[!] Failed to write config to %s: %v\n", configPath, err)
	} else {
		fmt.Printf("\n[+] Configuration saved successfully to %s\n\n", configPath)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func NewProxyDaemon(cfg ProxyConfig, configPath string) *ProxyDaemon {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureTLS},
		MaxIdleConns:    20,
		IdleConnTimeout: 90 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	_ = os.MkdirAll(cfg.SpoolDir, 0755)

	spoolPath := filepath.Join(cfg.SpoolDir, "spool.log")
	f, err := os.OpenFile(spoolPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("[Edge Spool] Warning: unable to open spool file: %v", err)
	}

	return &ProxyDaemon{
		cfg:          cfg,
		configPath:   configPath,
		httpClient:   client,
		queue:        make(chan LogPacket, 50000),
		spoolFile:    f,
		startTime:    time.Now(),
		syncInterval: "online", // Default to online until heartbeat updates it
		intervalSecs: 0,
		stopCh:       make(chan struct{}),
	}
}

func (d *ProxyDaemon) Start() {
	log.Printf("[Edge Proxy v%s] Initializing forwarder daemon for '%s'...", ProxyVersion, d.cfg.NodeName)
	log.Printf("[Edge Proxy] Cloud Endpoint: %s", d.cfg.Endpoint)

	// 1. Initial Heartbeat Check-in to discover Cloud-configured schedule
	d.checkHeartbeat()

	// 2. Start Background Heartbeat Loop (every 15 seconds)
	d.wg.Add(1)
	go d.heartbeatLoop()

	// 3. Start Local Syslog Listeners (UDP and TCP)
	d.startSyslogListeners()

	// 4. Start Dynamic Scheduler / Log Transmitter
	d.wg.Add(1)
	go d.transmissionLoop()

	log.Printf("[Edge Proxy] Ready. Syslog active on UDP %s and TCP %s", d.cfg.ListenUDP, d.cfg.ListenTCP)
}

func (d *ProxyDaemon) Stop() {
	close(d.stopCh)
	d.wg.Wait()
	if d.spoolFile != nil {
		_ = d.spoolFile.Close()
	}
}

func (d *ProxyDaemon) startSyslogListeners() {
	// UDP Listener
	if d.cfg.ListenUDP != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", d.cfg.ListenUDP)
		if err == nil {
			conn, err := net.ListenUDP("udp", udpAddr)
			if err == nil {
				d.wg.Add(1)
				go d.udpWorker(conn)
			} else {
				log.Printf("[Edge Proxy] UDP listen error: %v", err)
			}
		}
	}

	// TCP Listener
	if d.cfg.ListenTCP != "" {
		tcpAddr, err := net.ResolveTCPAddr("tcp", d.cfg.ListenTCP)
		if err == nil {
			listener, err := net.ListenTCP("tcp", tcpAddr)
			if err == nil {
				d.wg.Add(1)
				go d.tcpWorker(listener)
			} else {
				log.Printf("[Edge Proxy] TCP listen error: %v", err)
			}
		}
	}
}

func (d *ProxyDaemon) udpWorker(conn *net.UDPConn) {
	defer d.wg.Done()
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		select {
		case <-d.stopCh:
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		d.receivedLogs.Add(1)
		pkt := LogPacket{
			Data:       string(buf[:n]),
			SourceIP:   remoteAddr.IP.String(),
			SourcePort: uint16(remoteAddr.Port),
			Protocol:   "udp",
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		}

		d.enqueueLog(pkt)
	}
}

func (d *ProxyDaemon) tcpWorker(listener *net.TCPListener) {
	defer d.wg.Done()
	defer listener.Close()

	for {
		select {
		case <-d.stopCh:
			return
		default:
		}

		_ = listener.SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := listener.AcceptTCP()
		if err != nil {
			continue
		}

		go d.handleTCPClient(conn)
	}
}

func (d *ProxyDaemon) handleTCPClient(conn *net.TCPConn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	scanner := bufio.NewScanner(conn)

	// Scan lines of syslog stream
	for scanner.Scan() {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}

		d.receivedLogs.Add(1)
		pkt := LogPacket{
			Data:       text,
			SourceIP:   remoteAddr.IP.String(),
			SourcePort: uint16(remoteAddr.Port),
			Protocol:   "tcp",
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		}
		d.enqueueLog(pkt)
	}
}

func (d *ProxyDaemon) enqueueLog(pkt LogPacket) {
	select {
	case d.queue <- pkt:
	default:
		// Queue full, write to offline disk spool
		d.spoolLogToDisk(pkt)
	}
}

func (d *ProxyDaemon) spoolLogToDisk(pkt LogPacket) {
	d.spoolMu.Lock()
	defer d.spoolMu.Unlock()
	d.spooledLogs.Add(1)

	if d.spoolFile == nil {
		return
	}
	line, err := json.Marshal(pkt)
	if err == nil {
		_, _ = d.spoolFile.Write(append(line, '\n'))
	}
}

// heartbeatLoop keeps check-in with Cloud and dynamically adjusts log transmission schedule
func (d *ProxyDaemon) heartbeatLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.checkHeartbeat()
		}
	}
}

func (d *ProxyDaemon) checkHeartbeat() {
	url := strings.TrimRight(d.cfg.Endpoint, "/") + "/api/v1/edge/heartbeat"
	reqData := map[string]interface{}{
		"token":          d.cfg.Token,
		"node_name":      d.cfg.NodeName,
		"version":        ProxyVersion,
		"buffered_count": len(d.queue),
		"uptime_seconds": int64(time.Since(d.startTime).Seconds()),
	}

	b, _ := json.Marshal(reqData)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Edge-Token", d.cfg.Token)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		log.Printf("[Heartbeat] Notice: Cloud unreachable (%v). Spooling locally.", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var hbResp HeartbeatResponse
		if err := json.NewDecoder(resp.Body).Decode(&hbResp); err == nil {
			d.updateScheduleFromCloud(hbResp.SyncInterval, hbResp.SyncIntervalSeconds)
		}
	} else if resp.StatusCode == http.StatusUnauthorized {
		log.Printf("[Heartbeat] CRITICAL: Cloud rejected token for node '%s'. Check token in settings.", d.cfg.NodeName)
	}
}

func (d *ProxyDaemon) updateScheduleFromCloud(newInterval string, secs int) {
	d.scheduleMu.Lock()
	defer d.scheduleMu.Unlock()

	if newInterval == "" {
		newInterval = "online"
	}

	if d.syncInterval != newInterval {
		log.Printf("[Edge Scheduler] Transmission schedule dynamically updated by Cloud: '%s' -> '%s' (%ds)",
			d.syncInterval, newInterval, secs)
		d.syncInterval = newInterval
		d.intervalSecs = secs
	}
}

func (d *ProxyDaemon) getSchedule() (string, int) {
	d.scheduleMu.RLock()
	defer d.scheduleMu.RUnlock()
	return d.syncInterval, d.intervalSecs
}

// transmissionLoop dynamically coordinates sending logs to Cloud according to the Cloud's interval
func (d *ProxyDaemon) transmissionLoop() {
	defer d.wg.Done()

	for {
		select {
		case <-d.stopCh:
			// Flush remaining on shutdown
			d.flushBatch(true)
			return
		default:
		}

		interval, secs := d.getSchedule()

		if interval == "online" || secs <= 0 {
			// Online mode: Stream logs as soon as available (up to 100 batch or 500ms debounce)
			d.streamOnline()
		} else {
			// Scheduled batch mode: Accumulate logs in memory/spool and flush every N seconds
			log.Printf("[Edge Scheduler] Logs accumulating locally. Next batch transmission in %ds (%s)...", secs, interval)
			select {
			case <-d.stopCh:
				d.flushBatch(true)
				return
			case <-time.After(time.Duration(secs) * time.Second):
				d.flushBatch(false)
			}
		}
	}
}

// streamOnline debounces and sends near-realtime batches to Cloud
func (d *ProxyDaemon) streamOnline() {
	var batch []LogPacket
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case <-d.stopCh:
			if len(batch) > 0 {
				d.transmitBatch(batch)
			}
			return
		case pkt := <-d.queue:
			batch = append(batch, pkt)
			if len(batch) >= d.cfg.MaxBatchSize {
				d.transmitBatch(batch)
				batch = nil
				// Also check if any disk spooled events need uploading
				d.drainDiskSpool()
				return
			}
		case <-timer.C:
			if len(batch) > 0 {
				d.transmitBatch(batch)
				batch = nil
				d.drainDiskSpool()
			}
			return
		}
	}
}

// flushBatch collects all available logs from memory queue and disk spool and transmits
func (d *ProxyDaemon) flushBatch(forceAll bool) {
	var batch []LogPacket
	max := d.cfg.MaxBatchSize * 4
	if forceAll {
		max = 50000
	}

	for len(batch) < max {
		select {
		case pkt := <-d.queue:
			batch = append(batch, pkt)
		default:
			goto Send
		}
	}

Send:
	if len(batch) > 0 {
		log.Printf("[Edge Scheduler] Scheduled flush triggering: transmitting %d queued logs to Cloud...", len(batch))
		d.transmitBatch(batch)
	}

	d.drainDiskSpool()
}

// drainDiskSpool reads previously offlined disk spooled logs and sends them to Cloud
func (d *ProxyDaemon) drainDiskSpool() {
	d.spoolMu.Lock()
	defer d.spoolMu.Unlock()

	spoolPath := filepath.Join(d.cfg.SpoolDir, "spool.log")
	fi, err := os.Stat(spoolPath)
	if err != nil || fi.Size() == 0 {
		return
	}

	// Rotate spool file
	_ = d.spoolFile.Close()
	drainPath := filepath.Join(d.cfg.SpoolDir, fmt.Sprintf("drain_%d.log", time.Now().UnixNano()))
	if err := os.Rename(spoolPath, drainPath); err != nil {
		// Re-open
		d.spoolFile, _ = os.OpenFile(spoolPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		return
	}

	// Re-open fresh spool file
	d.spoolFile, _ = os.OpenFile(spoolPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)

	// Read and send drained logs
	go func(path string) {
		defer os.Remove(path)

		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()

		var batch []LogPacket
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var pkt LogPacket
			if err := json.Unmarshal(scanner.Bytes(), &pkt); err == nil {
				batch = append(batch, pkt)
				if len(batch) >= d.cfg.MaxBatchSize {
					d.transmitBatch(batch)
					batch = nil
				}
			}
		}
		if len(batch) > 0 {
			d.transmitBatch(batch)
		}
	}(drainPath)
}

// transmitBatch sends GZIP-compressed log batch over HTTPS to /api/v1/edge/ingest
func (d *ProxyDaemon) transmitBatch(events []LogPacket) bool {
	if len(events) == 0 {
		return true
	}

	url := strings.TrimRight(d.cfg.Endpoint, "/") + "/api/v1/edge/ingest"
	payload := map[string]interface{}{
		"token":     d.cfg.Token,
		"node_name": d.cfg.NodeName,
		"events":    events,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	// GZIP compression for high bandwidth efficiency
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(jsonData)
	_ = gw.Close()

	req, err := http.NewRequest(http.MethodPost, url, &gzBuf)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Edge-Token", d.cfg.Token)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		log.Printf("[Edge Transmit] WAN send failure: %v. Spooling %d logs to disk.", err, len(events))
		for _, pkt := range events {
			d.spoolLogToDisk(pkt)
		}
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var ingResp IngestResponse
		if err := json.NewDecoder(resp.Body).Decode(&ingResp); err == nil {
			d.forwardedLogs.Add(int64(len(events)))
			if ingResp.SyncInterval != "" {
				d.updateScheduleFromCloud(ingResp.SyncInterval, ingResp.SyncIntervalSeconds)
			}
		}
		return true
	}

	body, _ := io.ReadAll(resp.Body)
	log.Printf("[Edge Transmit] Server returned HTTP %d: %s. Spooling %d logs.", resp.StatusCode, string(body), len(events))
	for _, pkt := range events {
		d.spoolLogToDisk(pkt)
	}
	return false
}
