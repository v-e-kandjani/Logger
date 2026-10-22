//go:build !windows

package main

import (
	"context"

	"github.com/syslog-platform/logger/agent/internal/agent"
	"github.com/syslog-platform/logger/agent/internal/config"
)

func runAgent(agt *agent.Agent, cfg *config.Config, ctx context.Context, cancel context.CancelFunc) error {
	return agt.Run(ctx)
}
