package quota

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/syslog-platform/logger/internal/database/postgres"
	"github.com/syslog-platform/logger/internal/models"
)

// QuotaEnforcer manages active tenant-level rate limiting (EPS) and node limits
type QuotaEnforcer struct {
	mu          sync.RWMutex
	db          *postgres.DB
	tenantEPS   map[string]*tenantRateBucket
	tenantCache map[string]*cachedTenant
	cacheTTL    time.Duration
}

type cachedTenant struct {
	tenant   *models.Tenant
	cachedAt time.Time
}

type tenantRateBucket struct {
	mu         sync.Mutex
	lastSec    int64
	secCount   int
	avgEPS     float64
	history    [10]int
	historyIdx int
}

// NewQuotaEnforcer creates a new quota enforcer instance
func NewQuotaEnforcer(db *postgres.DB) *QuotaEnforcer {
	return &QuotaEnforcer{
		db:          db,
		tenantEPS:   make(map[string]*tenantRateBucket),
		tenantCache: make(map[string]*cachedTenant),
		cacheTTL:    10 * time.Second,
	}
}

// CheckIngestQuota verifies tenant status and EPS rate limit
func (q *QuotaEnforcer) CheckIngestQuota(ctx context.Context, tenantSlug string, incomingCount int) (allowed bool, currentEPS float64, maxEPS int, err error) {
	// Root 'default' tenant has unlimited quotas (0 = ∞)
	if tenantSlug == "" || tenantSlug == "default" {
		return true, 0, 0, nil
	}

	tenant, err := q.getTenant(ctx, tenantSlug)
	if err != nil {
		// Fail-open to avoid dropping valid syslog traffic if database is unreachable
		return true, 0, 0, nil
	}
	if tenant == nil {
		return false, 0, 0, fmt.Errorf("tenant '%s' not found", tenantSlug)
	}

	if tenant.Status == "suspended" {
		return false, 0, tenant.MaxEPS, fmt.Errorf("tenant '%s' is suspended", tenantSlug)
	}

	maxEPS = tenant.MaxEPS
	// 0 means unlimited
	if maxEPS <= 0 {
		return true, 0, 0, nil
	}

	bucket := q.getRateBucket(tenantSlug)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	nowSec := time.Now().Unix()
	if bucket.lastSec != nowSec {
		bucket.historyIdx = (bucket.historyIdx + 1) % 10
		bucket.history[bucket.historyIdx] = bucket.secCount
		bucket.secCount = 0
		bucket.lastSec = nowSec

		sum := 0
		for _, c := range bucket.history {
			sum += c
		}
		bucket.avgEPS = float64(sum) / 10.0
	}

	currentEPS = bucket.avgEPS
	if bucket.secCount+incomingCount > maxEPS {
		return false, currentEPS, maxEPS, fmt.Errorf("tenant '%s' EPS quota exceeded: burst %d EPS > limit %d EPS", tenantSlug, bucket.secCount+incomingCount, maxEPS)
	}

	bucket.secCount += incomingCount
	return true, currentEPS, maxEPS, nil
}

// RecordIngest increments the counter for a tenant
func (q *QuotaEnforcer) RecordIngest(tenantSlug string, count int) {
	if tenantSlug == "" || tenantSlug == "default" {
		return
	}
	bucket := q.getRateBucket(tenantSlug)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	nowSec := time.Now().Unix()
	if bucket.lastSec != nowSec {
		bucket.historyIdx = (bucket.historyIdx + 1) % 10
		bucket.history[bucket.historyIdx] = bucket.secCount
		bucket.secCount = 0
		bucket.lastSec = nowSec
	}
	bucket.secCount += count
}

// GetCurrentEPS returns the real-time EPS calculation for a tenant
func (q *QuotaEnforcer) GetCurrentEPS(tenantSlug string) float64 {
	q.mu.RLock()
	bucket, ok := q.tenantEPS[tenantSlug]
	q.mu.RUnlock()
	if !ok {
		return 0
	}
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	return bucket.avgEPS
}

func (q *QuotaEnforcer) getRateBucket(tenantSlug string) *tenantRateBucket {
	q.mu.Lock()
	defer q.mu.Unlock()
	b, ok := q.tenantEPS[tenantSlug]
	if !ok {
		b = &tenantRateBucket{lastSec: time.Now().Unix()}
		q.tenantEPS[tenantSlug] = b
	}
	return b
}

func (q *QuotaEnforcer) getTenant(ctx context.Context, tenantSlug string) (*models.Tenant, error) {
	q.mu.RLock()
	cached, ok := q.tenantCache[tenantSlug]
	q.mu.RUnlock()

	if ok && time.Since(cached.cachedAt) < q.cacheTTL {
		return cached.tenant, nil
	}

	if q.db == nil {
		return nil, nil
	}

	t, err := q.db.GetTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}

	q.mu.Lock()
	q.tenantCache[tenantSlug] = &cachedTenant{
		tenant:   t,
		cachedAt: time.Now(),
	}
	q.mu.Unlock()

	return t, nil
}
