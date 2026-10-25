package ti

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

// Harvester handles fetching external threat feeds and converting them into structured indicators
type Harvester struct {
	client *http.Client
}

// NewHarvester creates a new threat intelligence feed harvester
func NewHarvester() *Harvester {
	return &Harvester{
		client: &http.Client{
			Timeout: 45 * time.Second,
		},
	}
}

// FetchFeed downloads and parses a threat feed into normalized TIIndicator records
func (h *Harvester) FetchFeed(ctx context.Context, feed *models.TIFeed) ([]models.TIIndicator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid feed url: %w", err)
	}

	req.Header.Set("User-Agent", "Valtrivo-LogSeal-ThreatIntel/v1.10.0 (+https://valtrivo.com)")
	if feed.APIKey != "" {
		if feed.FeedType == "abuseipdb" {
			req.Header.Set("Key", feed.APIKey)
			req.Header.Set("Accept", "application/json")
		} else {
			req.Header.Set("Authorization", "Bearer "+feed.APIKey)
		}
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("feed server returned HTTP %d: %s", resp.StatusCode, string(bodySnippet))
	}

	var indicators []models.TIIndicator
	switch feed.FeedType {
	case "cisa_kev":
		indicators, err = h.parseCISAKEV(resp.Body, feed)
	case "csv":
		indicators, err = h.parseCSV(resp.Body, feed)
	case "abuseipdb":
		indicators, err = h.parseAbuseIPDB(resp.Body, feed)
	case "json":
		indicators, err = h.parseGenericJSON(resp.Body, feed)
	case "plain_list":
		fallthrough
	default:
		indicators, err = h.parsePlainList(resp.Body, feed)
	}

	if err != nil {
		return nil, fmt.Errorf("parsing feed %s failed: %w", feed.Name, err)
	}

	return indicators, nil
}

// parsePlainList parses line-by-line indicators (e.g. Tor exit nodes, ET blocklists)
func (h *Harvester) parsePlainList(r io.Reader, feed *models.TIFeed) ([]models.TIIndicator, error) {
	var indicators []models.TIIndicator
	scanner := bufio.NewScanner(r)
	// Support larger line buffers if needed
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	indType := feed.IndicatorType
	if indType == "" || indType == "mixed" {
		indType = "ip"
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}

		// Handle comments after values (e.g. "1.2.3.4 # attacker")
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// If line has multiple whitespace-separated tokens, take the first token
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		val := fields[0]

		// Auto-detect type if mixed
		detectedType := indType
		if indType == "mixed" {
			detectedType = detectIndicatorType(val)
		}

		indicators = append(indicators, models.TIIndicator{
			FeedID:         &feed.ID,
			IndicatorType:  detectedType,
			IndicatorValue: val,
			ThreatCategory: feed.ThreatCategory,
			Severity:       "high",
			Confidence:     feed.DefaultConfidence,
			Source:         feed.Name,
			Description:    fmt.Sprintf("Listed in %s threat feed", feed.Name),
			IsActive:       true,
		})

		// Limit to 10,000 items per feed per sync to keep memory bounded
		if len(indicators) >= 10000 {
			break
		}
	}

	return indicators, scanner.Err()
}

// parseCSV parses CSV feeds (e.g. URLhaus)
func (h *Harvester) parseCSV(r io.Reader, feed *models.TIFeed) ([]models.TIIndicator, error) {
	var indicators []models.TIIndicator
	scanner := bufio.NewScanner(r)

	// Filter out comment lines before handing to CSV reader
	var cleanLines strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		cleanLines.WriteString(line)
		cleanLines.WriteString("\n")
	}

	csvReader := csv.NewReader(strings.NewReader(cleanLines.String()))
	csvReader.FieldsPerRecord = -1 // flexible fields

	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	for _, row := range records {
		if len(row) < 3 {
			continue
		}
		// URLhaus CSV: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
		rawURL := strings.TrimSpace(row[2])
		if rawURL == "" || rawURL == "url" {
			continue
		}

		threatCat := feed.ThreatCategory
		if len(row) > 5 && row[5] != "" {
			threatCat = strings.ToLower(row[5])
		}

		// Add domain extracted from URL
		if parsed, err := url.Parse(rawURL); err == nil && parsed.Hostname() != "" {
			indicators = append(indicators, models.TIIndicator{
				FeedID:         &feed.ID,
				IndicatorType:  "domain",
				IndicatorValue: strings.ToLower(parsed.Hostname()),
				ThreatCategory: threatCat,
				Severity:       "high",
				Confidence:     feed.DefaultConfidence,
				Source:         feed.Name,
				Description:    fmt.Sprintf("Malicious host extracted from %s: %s", feed.Name, rawURL),
				IsActive:       true,
			})
		}

		indicators = append(indicators, models.TIIndicator{
			FeedID:         &feed.ID,
			IndicatorType:  "url",
			IndicatorValue: rawURL,
			ThreatCategory: threatCat,
			Severity:       "high",
			Confidence:     feed.DefaultConfidence,
			Source:         feed.Name,
			Description:    fmt.Sprintf("Malicious URL reported in %s", feed.Name),
			IsActive:       true,
		})

		if len(indicators) >= 10000 {
			break
		}
	}

	return indicators, nil
}

// parseCISAKEV parses CISA's Known Exploited Vulnerabilities JSON
func (h *Harvester) parseCISAKEV(r io.Reader, feed *models.TIFeed) ([]models.TIIndicator, error) {
	var payload struct {
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			ShortDescription  string `json:"shortDescription"`
			RequiredAction    string `json:"requiredAction"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return nil, err
	}

	var indicators []models.TIIndicator
	for _, vuln := range payload.Vulnerabilities {
		if vuln.CVEID == "" {
			continue
		}
		indicators = append(indicators, models.TIIndicator{
			FeedID:         &feed.ID,
			IndicatorType:  "cve",
			IndicatorValue: vuln.CVEID,
			ThreatCategory: "vulnerability_exploit",
			Severity:       "critical",
			Confidence:     feed.DefaultConfidence,
			Source:         feed.Name,
			Description:    fmt.Sprintf("[%s %s] %s", vuln.VendorProject, vuln.Product, vuln.VulnerabilityName),
			IsActive:       true,
		})

		if len(indicators) >= 10000 {
			break
		}
	}

	return indicators, nil
}

// parseAbuseIPDB parses AbuseIPDB blacklist JSON
func (h *Harvester) parseAbuseIPDB(r io.Reader, feed *models.TIFeed) ([]models.TIIndicator, error) {
	var payload struct {
		Data []struct {
			IPAddress            string `json:"ipAddress"`
			CountryCode          string `json:"countryCode"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			LastReportedAt       string `json:"lastReportedAt"`
		} `json:"data"`
	}

	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		// Try fallback to line-by-line if plain list returned
		return h.parsePlainList(r, feed)
	}

	var indicators []models.TIIndicator
	for _, item := range payload.Data {
		if item.IPAddress == "" {
			continue
		}
		conf := item.AbuseConfidenceScore
		if conf <= 0 {
			conf = feed.DefaultConfidence
		}
		sev := "high"
		if conf >= 90 {
			sev = "critical"
		} else if conf < 60 {
			sev = "medium"
		}

		indicators = append(indicators, models.TIIndicator{
			FeedID:         &feed.ID,
			IndicatorType:  "ip",
			IndicatorValue: item.IPAddress,
			ThreatCategory: feed.ThreatCategory,
			Severity:       sev,
			Confidence:     conf,
			Source:         feed.Name,
			Description:    fmt.Sprintf("AbuseIPDB reported IP (Country: %s, Score: %d%%)", item.CountryCode, conf),
			IsActive:       true,
		})

		if len(indicators) >= 10000 {
			break
		}
	}

	return indicators, nil
}

// parseGenericJSON parses an array of indicator strings or objects
func (h *Harvester) parseGenericJSON(r io.Reader, feed *models.TIFeed) ([]models.TIIndicator, error) {
	// First try string array
	var strArr []string
	dec := json.NewDecoder(r)
	if err := dec.Decode(&strArr); err == nil && len(strArr) > 0 {
		var indicators []models.TIIndicator
		for _, val := range strArr {
			val = strings.TrimSpace(val)
			if val == "" {
				continue
			}
			indicators = append(indicators, models.TIIndicator{
				FeedID:         &feed.ID,
				IndicatorType:  detectIndicatorType(val),
				IndicatorValue: val,
				ThreatCategory: feed.ThreatCategory,
				Severity:       "high",
				Confidence:     feed.DefaultConfidence,
				Source:         feed.Name,
				Description:    fmt.Sprintf("Extracted from %s", feed.Name),
				IsActive:       true,
			})
			if len(indicators) >= 10000 {
				break
			}
		}
		return indicators, nil
	}
	return nil, fmt.Errorf("unsupported json feed format")
}

// Helper: detect indicator type automatically
func detectIndicatorType(val string) string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(strings.ToLower(val), "cve-") {
		return "cve"
	}
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
		return "url"
	}
	if len(val) == 64 || len(val) == 32 {
		isHex := true
		for _, c := range val {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}
		if isHex {
			if len(val) == 64 {
				return "sha256"
			}
			return "md5"
		}
	}
	// Check if IP
	if normalizeIP(val) != "" {
		return "ip"
	}
	// Default to domain
	return "domain"
}
