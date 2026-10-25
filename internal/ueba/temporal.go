package ueba

import (
	"fmt"
	"time"
)

// TemporalEvaluator assesses time-of-day access anomalies based on 24-hour activity profiles
type TemporalEvaluator struct{}

// NewTemporalEvaluator creates a new temporal anomaly evaluator
func NewTemporalEvaluator() *TemporalEvaluator {
	return &TemporalEvaluator{}
}

// IsOffHoursAccess returns true if the event occurs during high-risk off-hours (22:00-06:00 or weekends)
func (t *TemporalEvaluator) IsOffHoursAccess(eventTime time.Time) bool {
	hour := eventTime.Hour()
	weekday := eventTime.Weekday()

	// Weekend access (Saturday or Sunday)
	if weekday == time.Saturday || weekday == time.Sunday {
		return true
	}

	// Deep night / early morning access
	if hour >= 22 || hour < 6 {
		return true
	}

	return false
}

// EvaluateDrift assesses whether access at this hour deviates significantly from the user's learned histogram
func (t *TemporalEvaluator) EvaluateDrift(hour int, histogram [24]int, totalEvents int64) (bool, float64, string) {
	if totalEvents < 25 {
		// Insufficient baseline data - don't trigger statistical drift until profile warms up
		return false, 1.0, "baseline_warming_up"
	}

	hourCount := histogram[hour]
	prob := float64(hourCount) / float64(totalEvents)

	// If access occurs in an hour that historically accounts for less than 1.5% of user activity
	if prob < 0.015 {
		desc := fmt.Sprintf("Activity at %02d:00 deviates from historical profile (P = %.2f%%, %d/%d events)",
			hour, prob*100, hourCount, totalEvents)
		return true, prob, desc
	}

	return false, prob, "normal_temporal_window"
}
