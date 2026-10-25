package ueba

import (
	"math"
	"net"
	"strings"
	"time"
)

// GeoLocation represents geographical coordinate data for an IP
type GeoLocation struct {
	Country   string
	City      string
	Latitude  float64
	Longitude float64
}

// HaversineDistance calculates the great-circle distance between two points on Earth in kilometers
func HaversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0

	dLat := (lat2 - lat1) * (math.Pi / 180.0)
	dLon := (lon2 - lon1) * (math.Pi / 180.0)

	rLat1 := lat1 * (math.Pi / 180.0)
	rLat2 := lat2 * (math.Pi / 180.0)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rLat1)*math.Cos(rLat2)*
			math.Sin(dLon/2)*math.Sin(dLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusKm * c
}

// CalculateVelocityKmPerHour computes the physical speed required to travel between two points
func CalculateVelocityKmPerHour(lat1, lon1, lat2, lon2 float64, t1, t2 time.Time) float64 {
	diff := t2.Sub(t1)
	if diff < 0 {
		diff = -diff
	}
	hours := diff.Hours()
	if hours <= 0.001 {
		// Almost simultaneous - if distance > 50km, velocity is astronomically high
		dist := HaversineDistance(lat1, lon1, lat2, lon2)
		if dist > 50.0 {
			return 99999.0
		}
		return 0.0
	}

	dist := HaversineDistance(lat1, lon1, lat2, lon2)
	return dist / hours
}

// ResolveIPGeo resolves an IP address to geographical location.
// Uses an embedded fast table for common subnets, private ranges, and regional geolocation.
func ResolveIPGeo(ipStr string) GeoLocation {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return GeoLocation{Country: "Unknown", City: "Unknown", Latitude: 0, Longitude: 0}
	}

	// Private / Loopback ranges
	if ip.IsLoopback() || ip.IsPrivate() {
		return GeoLocation{
			Country:   "Internal",
			City:      "Corporate LAN",
			Latitude:  41.0082, // Default HQ (Istanbul)
			Longitude: 28.9784,
		}
	}

	// Deterministic hash-based geolocation mock table for public IP blocks
	// Provides realistic coordinates across major global cyber hubs
	b := ip.To4()
	if b == nil {
		return GeoLocation{Country: "Global IPv6", City: "Cloud Network", Latitude: 50.1109, Longitude: 8.6821}
	}

	// Route based on first octet for test/simulation reproducibility
	switch b[0] % 10 {
	case 1:
		return GeoLocation{Country: "United States", City: "New York", Latitude: 40.7128, Longitude: -74.0060}
	case 2:
		return GeoLocation{Country: "Germany", City: "Frankfurt", Latitude: 50.1109, Longitude: 8.6821}
	case 3:
		return GeoLocation{Country: "United Kingdom", City: "London", Latitude: 51.5074, Longitude: -0.1278}
	case 4:
		return GeoLocation{Country: "Singapore", City: "Singapore", Latitude: 1.3521, Longitude: 103.8198}
	case 5:
		return GeoLocation{Country: "Japan", City: "Tokyo", Latitude: 35.6762, Longitude: 139.6503}
	case 6:
		return GeoLocation{Country: "Australia", City: "Sydney", Latitude: -33.8688, Longitude: 151.2093}
	case 7:
		return GeoLocation{Country: "Netherlands", City: "Amsterdam", Latitude: 52.3676, Longitude: 4.9041}
	case 8:
		return GeoLocation{Country: "France", City: "Paris", Latitude: 48.8566, Longitude: 2.3522}
	case 9:
		return GeoLocation{Country: "Turkey", City: "Ankara", Latitude: 39.9334, Longitude: 32.8597}
	default:
		return GeoLocation{Country: "Turkey", City: "Istanbul", Latitude: 41.0082, Longitude: 28.9784}
	}
}
