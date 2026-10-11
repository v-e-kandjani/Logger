package postgres

import (
	"testing"

	"github.com/google/uuid"
	"github.com/syslog-platform/logger/internal/models"
)

func TestDeviceCacheOverlappingPrivateIPs(t *testing.T) {
	devA := &models.Device{
		ID:         uuid.New(),
		Name:       "Acme-Core-Switch",
		IPAddress:  "192.168.1.1",
		TenantSlug: "acme-corp",
		Vendor:     "Cisco",
		IsEnabled:  true,
	}

	devB := &models.Device{
		ID:         uuid.New(),
		Name:       "Beta-Edge-Router",
		IPAddress:  "192.168.1.1",
		TenantSlug: "beta-finance",
		Vendor:     "Fortinet",
		IsEnabled:  true,
	}

	devRoot := &models.Device{
		ID:         uuid.New(),
		Name:       "Default-DC-Gateway",
		IPAddress:  "10.0.0.1",
		TenantSlug: "default",
		Vendor:     "Palo Alto",
		IsEnabled:  true,
	}

	byIP := map[string]*models.Device{
		"192.168.1.1": devA, // fallback
		"10.0.0.1":    devRoot,
	}

	byIPAndTenant := map[string]*models.Device{
		"192.168.1.1|acme-corp":    devA,
		"192.168.1.1|beta-finance": devB,
		"10.0.0.1|default":         devRoot,
	}

	byID := map[uuid.UUID]*models.Device{
		devA.ID:    devA,
		devB.ID:    devB,
		devRoot.ID: devRoot,
	}

	policies := map[string]string{
		"acme-corp":    "strict",
		"beta-finance": "permissive",
		"default":      "permissive",
	}

	dc := &DeviceCache{}
	dc.maps.Store(&deviceMaps{
		byIP:           byIP,
		byIPAndTenant:  byIPAndTenant,
		byID:           byID,
		tenantPolicies: policies,
	})

	// Test 1: Lookup for acme-corp on 192.168.1.1 must return devA
	resA, foundA := dc.LookupIPAndTenant("192.168.1.1", "acme-corp")
	if !foundA || resA == nil {
		t.Fatalf("expected to find device for acme-corp")
	}
	if resA.Name != "Acme-Core-Switch" || resA.TenantSlug != "acme-corp" {
		t.Fatalf("expected Acme-Core-Switch, got %s (tenant: %s)", resA.Name, resA.TenantSlug)
	}

	// Test 2: Lookup for beta-finance on 192.168.1.1 must return devB
	resB, foundB := dc.LookupIPAndTenant("192.168.1.1", "beta-finance")
	if !foundB || resB == nil {
		t.Fatalf("expected to find device for beta-finance")
	}
	if resB.Name != "Beta-Edge-Router" || resB.TenantSlug != "beta-finance" {
		t.Fatalf("expected Beta-Edge-Router, got %s (tenant: %s)", resB.Name, resB.TenantSlug)
	}

	// Test 3: Root default tenant lookup
	resRoot, foundRoot := dc.LookupIPAndTenant("10.0.0.1", "default")
	if !foundRoot || resRoot.Name != "Default-DC-Gateway" {
		t.Fatalf("expected Default-DC-Gateway, got %v", resRoot)
	}

	// Test 4: Verify tenant ingest policies
	if dc.GetTenantIngestPolicy("acme-corp") != "strict" {
		t.Fatalf("expected acme-corp to be strict")
	}
	if dc.GetTenantIngestPolicy("beta-finance") != "permissive" {
		t.Fatalf("expected beta-finance to be permissive")
	}
}
