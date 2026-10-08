package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/syslog-platform/logger/internal/api"
	"github.com/syslog-platform/logger/internal/archive"
	"github.com/syslog-platform/logger/internal/config"
	"github.com/syslog-platform/logger/internal/database/clickhouse"
	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/metrics"
	"github.com/syslog-platform/logger/internal/siem/correlation"
	"github.com/syslog-platform/logger/internal/siem/normalizer"
	"github.com/syslog-platform/logger/internal/syslog/generator"
	"github.com/syslog-platform/logger/internal/syslog/listener"
	"github.com/syslog-platform/logger/internal/syslog/pipeline"
	"github.com/syslog-platform/logger/internal/timestamp"
)

func main() {
	// CLI Subcommand: produce-logs / test-logs
	if len(os.Args) > 1 && (os.Args[1] == "produce-logs" || os.Args[1] == "test-logs") {
		runProduceLogsCLI(os.Args[2:])
		return
	}

	configPath := flag.String("config", "config/config.yaml", "Path to YAML configuration")
	flag.Parse()

	log.Println("[Syslog Platform] Booting high-throughput logging & evidence engine...")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// 1. Initialize PostgreSQL
	pgDB, err := postgres.NewDB(cfg.Postgres)
	if err != nil {
		log.Fatalf("PostgreSQL connection error: %v", err)
	}
	defer pgDB.Close()
	log.Println("[PostgreSQL] Connected and connection pool initialized")

	// Seed initial assets ONLY if explicitly enabled (SEED_DEMO_DEVICES=true)
	seedDemo := os.Getenv("SEED_DEMO_DEVICES") == "true" || cfg.Syslog.SeedDemoDevices
	if seedDemo {
		if err := pgDB.SeedDefaultDevices(context.Background()); err != nil {
			log.Printf("[PostgreSQL] Warning seeding default devices: %v", err)
		} else {
			log.Println("[PostgreSQL] Demo devices seeded")
		}
	} else {
		log.Println("[PostgreSQL] Demo device seeding disabled (Clean inventory mode)")
	}

	// Seed default administrator if users table empty
	if err := pgDB.SeedDefaultUser(context.Background(), "admin", "admin5651!"); err != nil {
		log.Printf("[PostgreSQL] Warning seeding default admin user: %v", err)
	} else {
		log.Println("[PostgreSQL] Security administrator verified (admin / admin5651!)")
	}

	// Verify & auto-migrate SIEM detection rules and alert schema
	if err := pgDB.EnsureSIEMSchema(context.Background()); err != nil {
		log.Printf("[PostgreSQL] Warning ensuring SIEM schema: %v", err)
	} else {
		log.Println("[PostgreSQL] SIEM tables and out-of-the-box detection rules verified")
	}

	// 2. Initialize in-memory Device Cache
	deviceCache := postgres.NewDeviceCache(pgDB)
	log.Println("[DeviceCache] Initialized active device lookup cache")

	// 3. Initialize ClickHouse analytical store
	chClient, err := clickhouse.NewClient(cfg.ClickHouse)
	if err != nil {
		log.Fatalf("ClickHouse connection error: %v", err)
	}
	defer chClient.Close()
	log.Println("[ClickHouse] Connected and batch inserter worker pool running")

	// 4. Initialize Adaptive Timestamp Provider (TÜBİTAK KamuSM, Internal Standalone, or Disabled)
	dbSettings, _ := pgDB.GetSettings(context.Background())
	stampingMode := timestamp.StampingMode(dbSettings["stamping_mode"])
	if stampingMode == "" {
		if cfg.Timestamp.Provider == "kamusm" {
			stampingMode = timestamp.ModeKamuSM
		} else {
			stampingMode = timestamp.ModeInternal
		}
	}
	autoFallback := true
	if val, ok := dbSettings["auto_fallback"]; ok {
		autoFallback = val == "true" || val == "1"
	}

	kamusmCfg := timestamp.KamuSMConfig{
		JavaBinary:   cfg.Timestamp.JavaBinary,
		JarPath:      cfg.Timestamp.JarPath,
		ServerURL:    cfg.Timestamp.ServerURL,
		ServerPort:   cfg.Timestamp.ServerPort,
		CustomerNo:   cfg.Timestamp.CustomerNo,
		CustomerPass: cfg.Timestamp.CustomerPass,
		DigestType:   cfg.Timestamp.DigestType,
		Timeout:      cfg.Timestamp.Timeout,
	}
	if val, ok := dbSettings["kamusm_server_url"]; ok && val != "" {
		kamusmCfg.ServerURL = val
	}
	if val, ok := dbSettings["kamusm_customer_no"]; ok {
		kamusmCfg.CustomerNo = val
	}
	if val, ok := dbSettings["kamusm_customer_password"]; ok {
		kamusmCfg.CustomerPass = val
	}

	tsProvider := timestamp.NewAdaptiveTimestampProvider(stampingMode, autoFallback, kamusmCfg)
	log.Printf("[Timestamp] Adaptive timestamp provider activated (mode: %s, auto-fallback: %t)", stampingMode, autoFallback)

	// 5. Initialize Archival & Integrity Engine
	archEngine := archive.NewEngine(cfg.Archive.StoragePath, chClient, pgDB, tsProvider)
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()
	if cfg.Archive.Enabled {
		archEngine.StartAutoArchiving(appCtx, cfg.Archive.Interval, cfg.Archive.ScheduleMinutes)
	}

	// 6. Initialize Processing Pipeline
	pipe := pipeline.NewPipeline(
		cfg.Syslog.QueueCapacity,
		cfg.Syslog.Workers,
		cfg.Server.CollectorNode,
		chClient,
		deviceCache,
		pgDB,
	)
	// Initialize SIEM Detection & Correlation Engine
	siemNormalizer := normalizer.NewNormalizer()
	siemEngine := correlation.NewEngine(siemNormalizer, pgDB)
	_ = siemEngine.LoadRulesFromDB(context.Background())
	defer siemEngine.Stop()
	pipe.SetSIEMEngine(siemEngine)
	log.Println("[SIEM] Detection & Correlation Engine active with real-time sliding windows")

	pipe.Start()
	defer pipe.Stop()
	if val, ok := dbSettings["strict_device_filtering"]; ok && (val == "true" || val == "1") {
		pipe.SetStrictFiltering(true)
		log.Println("[Pipeline] Strict Device Filtering ENABLED (Rejecting unregistered syslog traffic)")
	} else {
		log.Println("[Pipeline] Ingestion mode: Permissive Auto-Discovery (Accepting all senders)")
	}
	log.Printf("[Pipeline] Ingestion ring buffer started with %d workers", cfg.Syslog.Workers)

	// 7. Initialize Syslog Socket Listeners (UDP/TCP/TLS)
	if val, ok := dbSettings["syslog_udp_listen_addr"]; ok && val != "" {
		cfg.Syslog.UDP.ListenAddr = val
	}
	if val, ok := dbSettings["syslog_tcp_listen_addr"]; ok && val != "" {
		cfg.Syslog.TCP.ListenAddr = val
	}
	if val, ok := dbSettings["syslog_tls_listen_addr"]; ok && val != "" {
		cfg.Syslog.TLS.ListenAddr = val
	}
	syslogServer := listener.NewServer(cfg.Syslog, pipe)
	if err := syslogServer.Start(); err != nil {
		log.Fatalf("Syslog listener startup error: %v", err)
	}
	defer syslogServer.Stop()

	// 8. Initialize Automated FIFO Storage Reclaim Cleaner
	fifoThresholdFunc := func() float64 {
		s, err := pgDB.GetSettings(context.Background())
		if err == nil {
			if tStr, ok := s["storage_fifo_threshold_pct"]; ok {
				if tVal, err := strconv.ParseFloat(tStr, 64); err == nil && tVal > 10 && tVal <= 99 {
					return tVal
				}
			}
		}
		return 85.0
	}
	autoCleaner := clickhouse.NewAutoCleaner(chClient, fifoThresholdFunc, func(target string, before, after, thresh float64) {
		log.Printf("[Auto-Cleaner] Automated FIFO Reclaim completed: %s purged (Usage: %.1f%% -> %.1f%%, threshold: %.1f%%)",
			target, before, after, thresh)
	}, 30*time.Second)
	autoCleaner.Start(appCtx)
	defer autoCleaner.Stop()

	// 9. Initialize System Telemetry & Performance Metrics Engine
	metricsCollector := metrics.NewCollector(pipe)
	metricsCollector.Start(context.Background())
	defer metricsCollector.Stop()
	log.Println("[Telemetry] Real-time CPU, RAM, EPS & Network I/O metrics collector running")

	// 10. Initialize REST & WebSocket HTTP Server
	apiHandler := api.NewHandler(pipe, chClient, pgDB, deviceCache, archEngine, tsProvider, metricsCollector, cfg.Server.CollectorNode)
	apiHandler.SetSyslogServer(syslogServer)
	apiHandler.StartMitreAutoSync(appCtx)
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)

	httpServer := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		log.Printf("[Web Server] Dashboard and REST API listening on http://%s", cfg.Server.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// 9. Graceful Shutdown on SIGINT / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[Syslog Platform] Caught signal %v, commencing graceful shutdown...", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = httpServer.Shutdown(shutdownCtx)
	fmt.Println("[Syslog Platform] Graceful shutdown completed safely.")
}

func runProduceLogsCLI(args []string) {
	fs := flag.NewFlagSet("produce-logs", flag.ExitOnError)
	target := fs.String("target", "127.0.0.1:514", "Destination syslog socket (e.g. 127.0.0.1:514)")
	protocol := fs.String("protocol", "udp", "Transport protocol ('udp' or 'tcp')")
	vendor := fs.String("vendor", "all", "Log vendor profile ('all', 'watchguard', 'fortinet', 'cisco', 'linux')")
	count := fs.Int("count", 25, "Number of test syslog packets to produce")
	delayMs := fs.Int("delay", 40, "Delay in milliseconds between packets")
	_ = fs.Parse(args)

	fmt.Printf("=== Valtrivo LogSeal Synthetic Log Generator ===\n")
	fmt.Printf("Target:   %s (%s)\n", *target, *protocol)
	fmt.Printf("Vendor:   %s\n", *vendor)
	fmt.Printf("Count:    %d packets\n", *count)
	fmt.Println("Sending test logs...")

	sent, err := generator.ProduceLogs(generator.Options{
		Target:   *target,
		Protocol: *protocol,
		Vendor:   *vendor,
		Count:    *count,
		Delay:    time.Duration(*delayMs) * time.Millisecond,
	})
	if err != nil {
		log.Fatalf("Error producing logs: %v\n", err)
	}
	fmt.Printf("Successfully produced and sent %d syslog packets to %s!\n", sent, *target)
}
