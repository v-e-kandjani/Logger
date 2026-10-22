//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"github.com/syslog-platform/logger/agent/internal/agent"
	"github.com/syslog-platform/logger/agent/internal/config"
)

type agentService struct {
	agt    *agent.Agent
	ctx    context.Context
	cancel context.CancelFunc
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.agt.Run(s.ctx)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case err := <-errCh:
			if err != nil {
				log.Printf("[LOGGER Agent] Agent stopped: %v", err)
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				if s.cancel != nil {
					s.cancel()
				}
				select {
				case <-errCh:
				case <-time.After(5 * time.Second):
				}
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
			}
		}
	}
}

func setupServiceLogging(cfg *config.Config) func() {
	if cfg.DataDir == "" {
		return func() {}
	}
	_ = os.MkdirAll(cfg.DataDir, 0755)
	logFile := filepath.Join(cfg.DataDir, "agent.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return func() {}
	}
	mw := io.MultiWriter(os.Stdout, f)
	log.SetOutput(mw)
	return func() { f.Close() }
}

func runAgent(agt *agent.Agent, cfg *config.Config, ctx context.Context, cancel context.CancelFunc) error {
	cleanup := setupServiceLogging(cfg)
	defer cleanup()

	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("checking windows service state: %w", err)
	}

	if isService {
		log.Println("[LOGGER Agent] Running as native Windows Service (LoggerAgent)")
		return svc.Run("LoggerAgent", &agentService{agt: agt, ctx: ctx, cancel: cancel})
	}

	return agt.Run(ctx)
}
