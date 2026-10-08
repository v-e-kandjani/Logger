package clickhouse

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ReclaimCallback is invoked when an automated FIFO disk reclaim occurs
type ReclaimCallback func(droppedTarget string, diskUsageBefore, diskUsageAfter float64, threshold float64)

// AutoCleaner coordinates background FIFO disk monitoring and automatic oldest data pruning
type AutoCleaner struct {
	client       *Client
	getThreshold func() float64
	callback     ReclaimCallback
	interval     time.Duration
	stopCh       chan struct{}
	mu           sync.Mutex
	running      bool
}

// NewAutoCleaner creates an automated FIFO storage manager
func NewAutoCleaner(client *Client, getThreshold func() float64, callback ReclaimCallback, interval time.Duration) *AutoCleaner {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &AutoCleaner{
		client:       client,
		getThreshold: getThreshold,
		callback:     callback,
		interval:     interval,
		stopCh:       make(chan struct{}),
	}
}

// Start launches the background monitoring loop
func (ac *AutoCleaner) Start(ctx context.Context) {
	ac.mu.Lock()
	if ac.running {
		ac.mu.Unlock()
		return
	}
	ac.running = true
	ac.stopCh = make(chan struct{})
	ac.mu.Unlock()

	go ac.runLoop(ctx)
	log.Printf("[Auto-Cleaner] Automated FIFO Storage Reclaim active (Check interval: %v)", ac.interval)
}

// Stop terminates the background monitor
func (ac *AutoCleaner) Stop() {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if !ac.running {
		return
	}
	ac.running = false
	close(ac.stopCh)
}

func (ac *AutoCleaner) runLoop(ctx context.Context) {
	ticker := time.NewTicker(ac.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ac.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			ac.evaluateAndReclaim(ctx)
		}
	}
}

func (ac *AutoCleaner) evaluateAndReclaim(ctx context.Context) {
	threshold := 85.0
	if ac.getThreshold != nil {
		if val := ac.getThreshold(); val > 10.0 && val <= 99.0 {
			threshold = val
		}
	}

	stats, err := ac.client.GetStorageStats(ctx)
	if err != nil {
		return
	}

	// If disk usage percent crosses configured threshold, trigger automated FIFO reclaim
	if stats.DiskUsagePercent < threshold {
		return
	}

	log.Printf("[Auto-Cleaner] WARNING: Disk usage %.1f%% exceeded threshold %.1f%%! Triggering automated FIFO storage reclaim...",
		stats.DiskUsagePercent, threshold)

	usageBefore := stats.DiskUsagePercent
	reclaimedTarget := ""

	// Strategy 1: Drop chronologically oldest partition if multiple partitions exist
	if stats.ActivePartitions > 1 {
		droppedPart, err := ac.client.PruneOldestPartition(ctx)
		if err == nil {
			reclaimedTarget = fmt.Sprintf("Partition %s", droppedPart)
			log.Printf("[Auto-Cleaner] Successfully dropped oldest partition %s via FIFO", droppedPart)
		} else {
			log.Printf("[Auto-Cleaner] Error pruning oldest partition: %v", err)
		}
	}

	// Strategy 2: If only 1 active partition, delete the oldest 24 hours of logs
	if reclaimedTarget == "" {
		deleteQuery := fmt.Sprintf(`
			ALTER TABLE %s.syslog_events 
			DELETE WHERE event_timestamp <= (
				SELECT min(event_timestamp) + INTERVAL 1 DAY 
				FROM %s.syslog_events
			)
		`, ac.client.Database(), ac.client.Database())

		if err := ac.client.conn.Exec(ctx, deleteQuery); err == nil {
			reclaimedTarget = "Oldest 24-hour log batch"
			log.Println("[Auto-Cleaner] Successfully purged oldest 24-hour log batch via FIFO")
		} else {
			log.Printf("[Auto-Cleaner] Error deleting oldest records: %v", err)
		}
	}

	if reclaimedTarget != "" {
		// Re-check stats after reclaim
		time.Sleep(1 * time.Second)
		newStats, _ := ac.client.GetStorageStats(ctx)
		usageAfter := usageBefore
		if newStats != nil {
			usageAfter = newStats.DiskUsagePercent
		}

		if ac.callback != nil {
			ac.callback(reclaimedTarget, usageBefore, usageAfter, threshold)
		}
	}
}
