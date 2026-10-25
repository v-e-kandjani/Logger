package ti

import (
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/syslog-platform/logger/internal/models"
)

// MatcherSnapshot holds the in-memory lookup maps for sub-microsecond matching
type MatcherSnapshot struct {
	IPs     map[string]*models.IndicatorHit
	Domains map[string]*models.IndicatorHit
	Hashes  map[string]*models.IndicatorHit
	URLs    map[string]*models.IndicatorHit
}

// Matcher provides lock-free, concurrent-safe IOC lookups against streaming events
type Matcher struct {
	snapshot atomic.Pointer[MatcherSnapshot]
	mu       sync.Mutex
}

// NewMatcher initializes an empty matcher
func NewMatcher() *Matcher {
	m := &Matcher{}
	m.snapshot.Store(&MatcherSnapshot{
		IPs:     make(map[string]*models.IndicatorHit),
		Domains: make(map[string]*models.IndicatorHit),
		Hashes:  make(map[string]*models.IndicatorHit),
		URLs:    make(map[string]*models.IndicatorHit),
	})
	return m
}

// BuildSnapshot rebuilds the in-memory lookup sets from an active indicator slice
func (m *Matcher) BuildSnapshot(indicators []models.TIIndicator) {
	snap := &MatcherSnapshot{
		IPs:     make(map[string]*models.IndicatorHit, len(indicators)/2),
		Domains: make(map[string]*models.IndicatorHit, len(indicators)/4),
		Hashes:  make(map[string]*models.IndicatorHit, len(indicators)/8),
		URLs:    make(map[string]*models.IndicatorHit, len(indicators)/8),
	}

	for _, ind := range indicators {
		if !ind.IsActive {
			continue
		}
		val := strings.TrimSpace(ind.IndicatorValue)
		if val == "" {
			continue
		}

		hit := &models.IndicatorHit{
			IndicatorID:    ind.ID,
			IndicatorType:  ind.IndicatorType,
			IndicatorValue: val,
			ThreatCategory: ind.ThreatCategory,
			Severity:       ind.Severity,
			Confidence:     ind.Confidence,
			Source:         ind.Source,
			Description:    ind.Description,
		}

		switch strings.ToLower(ind.IndicatorType) {
		case "ip":
			// If it's a single IP or CIDR, clean it
			ipStr := normalizeIP(val)
			if ipStr != "" {
				snap.IPs[ipStr] = hit
			}
		case "domain":
			dom := normalizeDomain(val)
			if dom != "" {
				snap.Domains[dom] = hit
			}
		case "sha256", "md5", "hash":
			h := strings.ToLower(val)
			snap.Hashes[h] = hit
		case "url":
			u := strings.TrimSpace(val)
			snap.URLs[u] = hit
			// Also register the hostname of the URL into domains if present
			if parsed, err := url.Parse(u); err == nil && parsed.Hostname() != "" {
				snap.Domains[strings.ToLower(parsed.Hostname())] = hit
			}
		}
	}

	m.snapshot.Store(snap)
}

// MatchIP checks if an IP address exists in the threat indicator set
func (m *Matcher) MatchIP(ipStr string) *models.IndicatorHit {
	cleanIP := normalizeIP(ipStr)
	if cleanIP == "" {
		return nil
	}
	snap := m.snapshot.Load()
	if snap == nil {
		return nil
	}
	if hit, found := snap.IPs[cleanIP]; found {
		return hit
	}
	return nil
}

// MatchDomain checks if a domain or any of its parent domain segments match threat indicators
func (m *Matcher) MatchDomain(domain string) *models.IndicatorHit {
	cleanDom := normalizeDomain(domain)
	if cleanDom == "" {
		return nil
	}
	snap := m.snapshot.Load()
	if snap == nil {
		return nil
	}

	// Exact match
	if hit, found := snap.Domains[cleanDom]; found {
		return hit
	}

	// Subdomain match (e.g. evil.sub.attacker.com -> attacker.com)
	parts := strings.Split(cleanDom, ".")
	if len(parts) > 2 {
		for i := 1; i < len(parts)-1; i++ {
			parent := strings.Join(parts[i:], ".")
			if hit, found := snap.Domains[parent]; found {
				return hit
			}
		}
	}

	return nil
}

// MatchHash checks if a file hash matches threat indicators
func (m *Matcher) MatchHash(hashStr string) *models.IndicatorHit {
	h := strings.ToLower(strings.TrimSpace(hashStr))
	if h == "" {
		return nil
	}
	snap := m.snapshot.Load()
	if snap == nil {
		return nil
	}
	if hit, found := snap.Hashes[h]; found {
		return hit
	}
	return nil
}

// MatchURL checks if a URL matches threat indicators
func (m *Matcher) MatchURL(rawURL string) *models.IndicatorHit {
	cleanURL := strings.TrimSpace(rawURL)
	if cleanURL == "" {
		return nil
	}
	snap := m.snapshot.Load()
	if snap == nil {
		return nil
	}
	if hit, found := snap.URLs[cleanURL]; found {
		return hit
	}
	if parsed, err := url.Parse(cleanURL); err == nil && parsed.Hostname() != "" {
		return m.MatchDomain(parsed.Hostname())
	}
	return nil
}

// MatchSyslog checks all relevant extracted fields from a syslog message
func (m *Matcher) MatchSyslog(srcIP, dstIP, domain, msg string) *models.IndicatorHit {
	// 1. Check Destination IP (highest priority for C2 / egress beaconing)
	if dstIP != "" {
		if hit := m.MatchIP(dstIP); hit != nil {
			return hit
		}
	}
	// 2. Check Source IP
	if srcIP != "" {
		if hit := m.MatchIP(srcIP); hit != nil {
			return hit
		}
	}
	// 3. Check Domain
	if domain != "" {
		if hit := m.MatchDomain(domain); hit != nil {
			return hit
		}
	}
	return nil
}

// Helper: normalize IP string
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed := net.ParseIP(raw)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

// Helper: normalize Domain string
func normalizeDomain(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, ":"); idx != -1 {
		raw = raw[:idx]
	}
	return strings.Trim(raw, ".")
}
