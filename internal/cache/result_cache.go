package cache

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CacheEntry represents an item stored in memory
type CacheEntry struct {
	Value     []byte
	ExpiresAt time.Time
	SizeBytes int64
	LastUsed  time.Time
}

// CacheStats provides real-time telemetry on in-memory result caching
type CacheStats struct {
	Enabled             bool    `json:"enabled"`
	MaxMemoryBytes      int64   `json:"max_memory_bytes"`
	MaxMemoryMB         float64 `json:"max_memory_mb"`
	CurrentMemoryBytes  int64   `json:"current_memory_bytes"`
	CurrentMemoryMB     float64 `json:"current_memory_mb"`
	TotalSystemMemoryMB float64 `json:"total_system_memory_mb"`
	AvailSystemMemoryMB float64 `json:"avail_system_memory_mb"`
	TargetPercent       float64 `json:"target_percent"`
	ItemCount           int     `json:"item_count"`
	HitCount            uint64  `json:"hit_count"`
	MissCount           uint64  `json:"miss_count"`
	HitRatioPercent     float64 `json:"hit_ratio_percent"`
	EvictionCount       uint64  `json:"eviction_count"`
}

// ResultCache is a high-throughput, memory-bounded in-memory query cache
type ResultCache struct {
	mu           sync.RWMutex
	items        map[string]*CacheEntry
	currentBytes int64
	maxBytes     int64
	targetPct    float64
	enabled      atomic.Bool

	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64

	totalMemMB float64
	availMemMB float64
}

// Global default cache instance
var (
	defaultCache     *ResultCache
	defaultCacheOnce sync.Once
)

// GetResultCache returns the singleton cache configured to use up to 60% of available memory
func GetResultCache() *ResultCache {
	defaultCacheOnce.Do(func() {
		defaultCache = NewResultCache(0.60) // 60% of available memory
	})
	return defaultCache
}

// NewResultCache creates a memory-bounded cache instance
func NewResultCache(targetPercent float64) *ResultCache {
	if targetPercent <= 0 || targetPercent > 0.90 {
		targetPercent = 0.60
	}

	totalMB, availMB := readSystemMemory()
	var budgetBytes int64

	if availMB > 0 {
		budgetBytes = int64(availMB * targetPercent * 1024 * 1024)
	} else if totalMB > 0 {
		budgetBytes = int64(totalMB * targetPercent * 0.5 * 1024 * 1024)
	} else {
		budgetBytes = 256 * 1024 * 1024 // 256 MB conservative fallback
	}

	// Minimum budget: 64 MB; Maximum: up to calculated limit
	if budgetBytes < 64*1024*1024 {
		budgetBytes = 64 * 1024 * 1024
	}

	// Configure Go runtime soft memory limit (GOMEMLIMIT) to cooperate with system RAM
	debug.SetMemoryLimit(budgetBytes)

	rc := &ResultCache{
		items:        make(map[string]*CacheEntry),
		maxBytes:     budgetBytes,
		targetPct:    targetPercent * 100.0,
		totalMemMB:   totalMB,
		availMemMB:   availMB,
		currentBytes: 0,
	}
	rc.enabled.Store(true)

	log.Printf("[ResultCache] In-memory acceleration initialized: max RAM budget = %.2f MB (%.0f%% of %.2f MB available RAM)",
		float64(budgetBytes)/(1024*1024), rc.targetPct, availMB)

	// Background eviction routine for expired entries every 30 seconds
	go rc.cleanupRoutine()

	return rc
}

// MakeKey computes a deterministic cache key for query parameters
func MakeKey(prefix string, params ...string) string {
	h := sha256.New()
	for _, p := range params {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return prefix + ":" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Get retrieves an item from cache if present and unexpired
func (c *ResultCache) Get(key string) ([]byte, bool) {
	if !c.enabled.Load() {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	now := time.Now()
	if now.After(entry.ExpiresAt) {
		c.mu.Lock()
		// Double check under write lock
		if e, still := c.items[key]; still && now.After(e.ExpiresAt) {
			delete(c.items, key)
			c.currentBytes -= e.SizeBytes
		}
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}

	c.hits.Add(1)
	entry.LastUsed = now
	return entry.Value, true
}

// Set stores an item with specified TTL and manages memory eviction
func (c *ResultCache) Set(key string, value []byte, ttl time.Duration) {
	if !c.enabled.Load() || ttl <= 0 || len(value) == 0 {
		return
	}

	size := int64(len(value)) + int64(len(key)) + 64 // entry overhead
	if size > c.maxBytes/4 {
		// Single query result exceeds 25% of total budget; do not cache to prevent thrashing
		return
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	// If key already exists, deduct old size
	if old, ok := c.items[key]; ok {
		c.currentBytes -= old.SizeBytes
	}

	// Evict oldest entries if capacity exceeded
	for c.currentBytes+size > c.maxBytes && len(c.items) > 0 {
		c.evictOldestLocked()
	}

	c.items[key] = &CacheEntry{
		Value:     value,
		ExpiresAt: expiresAt,
		SizeBytes: size,
		LastUsed:  now,
	}
	c.currentBytes += size
}

// Invalidate removes a specific key
func (c *ResultCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		delete(c.items, key)
		c.currentBytes -= e.SizeBytes
	}
}

// Clear flushes all entries from memory
func (c *ResultCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*CacheEntry)
	c.currentBytes = 0
}

// SetEnabled toggles caching on or off
func (c *ResultCache) SetEnabled(enabled bool) {
	c.enabled.Store(enabled)
	if !enabled {
		c.Clear()
	}
}

// IsEnabled returns current caching state
func (c *ResultCache) IsEnabled() bool {
	return c.enabled.Load()
}

// Stats returns real-time cache metrics
func (c *ResultCache) Stats() CacheStats {
	c.mu.RLock()
	itemCount := len(c.items)
	curBytes := c.currentBytes
	c.mu.RUnlock()

	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses
	var ratio float64
	if total > 0 {
		ratio = (float64(hits) / float64(total)) * 100.0
	}

	// Refresh system memory reading
	totalMB, availMB := readSystemMemory()

	return CacheStats{
		Enabled:             c.enabled.Load(),
		MaxMemoryBytes:      c.maxBytes,
		MaxMemoryMB:         float64(c.maxBytes) / (1024 * 1024),
		CurrentMemoryBytes:  curBytes,
		CurrentMemoryMB:     float64(curBytes) / (1024 * 1024),
		TotalSystemMemoryMB: totalMB,
		AvailSystemMemoryMB: availMB,
		TargetPercent:       c.targetPct,
		ItemCount:           itemCount,
		HitCount:            hits,
		MissCount:           misses,
		HitRatioPercent:     ratio,
		EvictionCount:       c.evictions.Load(),
	}
}

func (c *ResultCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time

	for k, v := range c.items {
		if oldestKey == "" || v.LastUsed.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.LastUsed
		}
	}

	if oldestKey != "" {
		e := c.items[oldestKey]
		delete(c.items, oldestKey)
		c.currentBytes -= e.SizeBytes
		c.evictions.Add(1)
	}
}

func (c *ResultCache) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for k, v := range c.items {
			if now.After(v.ExpiresAt) {
				delete(c.items, k)
				c.currentBytes -= v.SizeBytes
			}
		}
		c.mu.Unlock()
	}
}

// readSystemMemory inspects Linux /proc/meminfo or falls back to runtime.MemStats
func readSystemMemory() (totalMB, availMB float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		var totalKB, availKB, freeKB, buffKB, cachedKB uint64
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				switch fields[0] {
				case "MemTotal:":
					totalKB = val
				case "MemAvailable:":
					availKB = val
				case "MemFree:":
					freeKB = val
				case "Buffers:":
					buffKB = val
				case "Cached:":
					cachedKB = val
				}
			}
		}
		if totalKB > 0 {
			totalMB = float64(totalKB) / 1024.0
			if availKB > 0 {
				availMB = float64(availKB) / 1024.0
			} else {
				availMB = float64(freeKB+buffKB+cachedKB) / 1024.0
			}
			return totalMB, availMB
		}
	}

	// Non-Linux or container fallback using Go runtime
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	sysMB := float64(m.Sys) / (1024 * 1024)
	totalMB = sysMB * 4
	if totalMB < 1024 {
		totalMB = 2048 // Assume at least 2GB
	}
	availMB = totalMB * 0.7
	return totalMB, availMB
}
