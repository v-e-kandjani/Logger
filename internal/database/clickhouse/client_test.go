package clickhouse

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMinuteMetricSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Minute)
	m := MinuteMetric{
		Minute:     now,
		Tenant:     "default",
		DeviceID:   "471456db-b2ea-4792-8a55-40da6b9b77f6",
		DeviceName: "fw-ankara-01",
		Vendor:     "Fortinet",
		Product:    "FortiGate",
		Severity:   "warning",
		Facility:   "local0",
		EventCount: 1540,
		TotalBytes: 382400,
	}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal MinuteMetric: %v", err)
	}

	var parsed MinuteMetric
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("failed to unmarshal MinuteMetric: %v", err)
	}

	if parsed.Tenant != "default" {
		t.Errorf("expected tenant default, got %s", parsed.Tenant)
	}
	if parsed.EventCount != 1540 {
		t.Errorf("expected EventCount 1540, got %d", parsed.EventCount)
	}
	if parsed.TotalBytes != 382400 {
		t.Errorf("expected TotalBytes 382400, got %d", parsed.TotalBytes)
	}
}
