package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/syslog-platform/logger/agent/internal/agent"
	"github.com/syslog-platform/logger/agent/internal/config"
	"github.com/syslog-platform/logger/agent/internal/version"
)

func main() {
	serverURL := flag.String("server", "", "LOGGER Server URL (e.g. http://localhost:8080)")
	enrollToken := flag.String("token", "", "LOGGER Enrollment Token (lp_ea_...)")
	configPath := flag.String("config", "", "Path to logger-agent.json config file")
	showVersion := flag.Bool("version", false, "Print LOGGER Agent version and exit")
	flag.BoolVar(showVersion, "v", false, "Print LOGGER Agent version and exit (shorthand)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	log.Printf("Starting %s", version.String())

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	if *enrollToken != "" {
		cfg.EnrollmentToken = *enrollToken
	}

	agt, err := agent.NewAgent(cfg)
	if err != nil {
		log.Fatalf("Error initializing agent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Received termination signal, stopping agent...")
		cancel()
	}()

	if err := runAgent(agt, cfg, ctx, cancel); err != nil {
		log.Fatalf("Agent runtime error: %v", err)
	}
}
