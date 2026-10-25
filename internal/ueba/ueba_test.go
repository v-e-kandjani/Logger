package ueba

import (
	"testing"
	"time"
)

func TestHaversineDistance(t *testing.T) {
	// Distance between Istanbul (41.0082, 28.9784) and New York (40.7128, -74.0060) is ~8,015 km
	dist := HaversineDistance(41.0082, 28.9784, 40.7128, -74.0060)
	if dist < 7900 || dist > 8150 {
		t.Fatalf("expected distance ~8015km, got %.2f", dist)
	}

	// Distance between same coordinates should be zero
	zeroDist := HaversineDistance(41.0082, 28.9784, 41.0082, 28.9784)
	if zeroDist > 0.001 {
		t.Fatalf("expected identical coordinates to have 0 distance, got %.4f", zeroDist)
	}
}

func TestCalculateVelocity(t *testing.T) {
	t1 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 10, 25, 13, 0, 0, 0, time.UTC) // 1 hour later

	// Istanbul to New York in 1 hour -> velocity ~8015 km/h (> 900 km/h, impossible travel)
	velocity := CalculateVelocityKmPerHour(41.0082, 28.9784, 40.7128, -74.0060, t1, t2)
	if velocity < 7500 {
		t.Fatalf("expected high velocity >7500 km/h, got %.2f", velocity)
	}
}

func TestTemporalEvaluator(t *testing.T) {
	eval := NewTemporalEvaluator()

	// Sunday 03:00 is off-hours
	sundayNight := time.Date(2026, 10, 25, 3, 30, 0, 0, time.UTC)
	if !eval.IsOffHoursAccess(sundayNight) {
		t.Fatalf("expected Sunday 03:30 to be detected as off-hours")
	}

	// Wednesday 14:00 is normal business hours
	wednesdayAfternoon := time.Date(2026, 10, 28, 14, 0, 0, 0, time.UTC)
	if eval.IsOffHoursAccess(wednesdayAfternoon) {
		t.Fatalf("expected Wednesday 14:00 to be normal business hours")
	}
}
