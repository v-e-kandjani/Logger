package quota

import (
	"context"
	"testing"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

func TestRootTenantUnlimitedQuota(t *testing.T) {
	enforcer := NewQuotaEnforcer(nil)
	ctx := context.Background()

	// Default root tenant must always be allowed
	allowed, _, _, err := enforcer.CheckIngestQuota(ctx, "default", 50000)
	if !allowed || err != nil {
		t.Fatalf("expected default tenant to be allowed with unlimited quota, got allowed=%t, err=%v", allowed, err)
	}

	allowedEmpty, _, _, err := enforcer.CheckIngestQuota(ctx, "", 50000)
	if !allowedEmpty || err != nil {
		t.Fatalf("expected empty tenant to be allowed with unlimited quota, got allowed=%t, err=%v", allowedEmpty, err)
	}
}

func TestBucketRateTracking(t *testing.T) {
	enforcer := NewQuotaEnforcer(nil)

	// Record burst of 100 packets
	enforcer.RecordIngest("acme", 100)
	enforcer.RecordIngest("acme", 50)

	b := enforcer.getRateBucket("acme")
	if b.secCount != 150 {
		t.Errorf("expected secCount 150, got %d", b.secCount)
	}
}

func TestEnforcerWithMockTenant(t *testing.T) {
	enforcer := NewQuotaEnforcer(nil)
	ctx := context.Background()

	// Manually inject a cached tenant with max_eps = 100
	enforcer.mu.Lock()
	enforcer.tenantCache["limited-corp"] = &cachedTenant{
		tenant: &models.Tenant{
			Slug:   "limited-corp",
			Status: "active",
			MaxEPS: 100,
		},
		cachedAt: time.Now(),
	}
	enforcer.mu.Unlock()

	// 80 packets should be allowed
	allowed, _, maxEPS, err := enforcer.CheckIngestQuota(ctx, "limited-corp", 80)
	if !allowed || err != nil {
		t.Fatalf("expected 80 packets to be allowed under 100 EPS limit, got allowed=%t, err=%v", allowed, err)
	}
	if maxEPS != 100 {
		t.Errorf("expected maxEPS 100, got %d", maxEPS)
	}

	// 30 more packets in the same second should exceed the 100 limit (80 + 30 = 110 > 100)
	allowedOver, _, _, errOver := enforcer.CheckIngestQuota(ctx, "limited-corp", 30)
	if allowedOver || errOver == nil {
		t.Fatalf("expected burst exceeding 100 EPS to be rejected, got allowed=%t, err=%v", allowedOver, errOver)
	}
}

func TestSuspendedTenantRejection(t *testing.T) {
	enforcer := NewQuotaEnforcer(nil)
	ctx := context.Background()

	enforcer.mu.Lock()
	enforcer.tenantCache["suspended-corp"] = &cachedTenant{
		tenant: &models.Tenant{
			Slug:   "suspended-corp",
			Status: "suspended",
			MaxEPS: 500,
		},
		cachedAt: time.Now(),
	}
	enforcer.mu.Unlock()

	allowed, _, _, err := enforcer.CheckIngestQuota(ctx, "suspended-corp", 1)
	if allowed || err == nil {
		t.Fatalf("expected suspended tenant to be rejected, got allowed=%t, err=%v", allowed, err)
	}
}
