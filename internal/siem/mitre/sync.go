package mitre

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Store persists the parsed catalog so it survives restarts and platform upgrades
type Store interface {
	LoadMitreCatalog(ctx context.Context) ([]byte, error) // returns (nil, nil) when nothing is stored
	SaveMitreCatalog(ctx context.Context, payload []byte) error
}

// minFullCatalogSize: a STIX bundle with at least this many techniques is treated as a complete
// replacement of the catalog (so deprecated/revoked techniques disappear). Smaller bundles are merged.
const minFullCatalogSize = 100

var reCitation = regexp.MustCompile(`\s*\(Citation:[^)]*\)`)

// snapshot is the compact persisted form of the catalog
type snapshot struct {
	Version         string      `json:"version"`
	AttackVersion   string      `json:"attack_version"`
	PreviousVersion string      `json:"previous_version"`
	Source          string      `json:"source"`
	ETag            string      `json:"etag"`
	LastUpdated     time.Time   `json:"last_updated"`
	LastSuccess     *time.Time  `json:"last_success,omitempty"`
	Tactics         []Tactic    `json:"tactics"`
	Techniques      []Technique `json:"techniques"`
	NewTechniqueIDs []string    `json:"new_technique_ids"`
}

// SetStore attaches a persistence backend
func (c *Catalog) SetStore(s Store) {
	c.mu.Lock()
	c.store = s
	c.autoSync.Persisted = s != nil
	c.mu.Unlock()
}

// LoadFromStore restores the last synchronized catalog (no-op if none stored)
func (c *Catalog) LoadFromStore(ctx context.Context) error {
	c.mu.RLock()
	store := c.store
	c.mu.RUnlock()
	if store == nil {
		return nil
	}
	data, err := store.LoadMitreCatalog(ctx)
	if err != nil || len(data) == 0 {
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("decode stored MITRE catalog: %w", err)
	}
	if len(snap.Techniques) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(snap.Tactics) > 0 {
		c.tactics = snap.Tactics
	}
	c.techniques = make(map[string]Technique, len(snap.Techniques))
	for _, t := range snap.Techniques {
		c.techniques[t.ID] = t
	}
	c.newTechIDs = make(map[string]bool, len(snap.NewTechniqueIDs))
	for _, id := range snap.NewTechniqueIDs {
		c.newTechIDs[id] = true
	}
	c.version = snap.Version
	c.attackVersion = snap.AttackVersion
	c.previousVersion = snap.PreviousVersion
	c.source = snap.Source
	c.etag = snap.ETag
	c.lastUpdated = snap.LastUpdated
	c.isBaseline = false
	c.autoSync.LastSuccess = snap.LastSuccess
	return nil
}

func (c *Catalog) persist(ctx context.Context) error {
	c.mu.RLock()
	store := c.store
	if store == nil {
		c.mu.RUnlock()
		return nil
	}
	snap := snapshot{
		Version:         c.version,
		AttackVersion:   c.attackVersion,
		PreviousVersion: c.previousVersion,
		Source:          c.source,
		ETag:            c.etag,
		LastUpdated:     c.lastUpdated,
		LastSuccess:     c.autoSync.LastSuccess,
		Tactics:         append([]Tactic(nil), c.tactics...),
		Techniques:      make([]Technique, 0, len(c.techniques)),
	}
	for _, t := range c.techniques {
		snap.Techniques = append(snap.Techniques, t)
	}
	for id := range c.newTechIDs {
		snap.NewTechniqueIDs = append(snap.NewTechniqueIDs, id)
	}
	c.mu.RUnlock()

	sort.Slice(snap.Techniques, func(i, j int) bool { return snap.Techniques[i].ID < snap.Techniques[j].ID })
	sort.Strings(snap.NewTechniqueIDs)
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return store.SaveMitreCatalog(ctx, data)
}

// SyncFromURL fetches the latest enterprise ATT&CK STIX bundle (unconditional) and persists it
func (c *Catalog) SyncFromURL(ctx context.Context, rawURL string) (int, error) {
	n, _, err := c.syncFromURL(ctx, rawURL, false)
	return n, err
}

// syncFromURL downloads the feed. When conditional is true the stored ETag is sent so an unchanged
// feed costs a single 304 round-trip instead of a 50+ MB download.
func (c *Catalog) syncFromURL(ctx context.Context, rawURL string, conditional bool) (int, bool, error) {
	if rawURL == "" {
		rawURL = DefaultMITRESTIXURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "Valtrivo-LogSeal-SIEM/1.0")

	c.mu.RLock()
	etag, baseline := c.etag, c.isBaseline
	c.mu.RUnlock()
	if conditional && etag != "" && !baseline {
		req.Header.Set("If-None-Match", etag)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("fetch MITRE STIX JSON: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return 0, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("MITRE source returned HTTP status %d", resp.StatusCode)
	}

	n, err := c.ParseSTIXStream(resp.Body, rawURL)
	if err != nil {
		return 0, false, err
	}
	if newTag := resp.Header.Get("ETag"); newTag != "" {
		c.mu.Lock()
		c.etag = newTag
		c.mu.Unlock()
	}
	c.markSuccess()
	if perr := c.persist(ctx); perr != nil {
		log.Printf("[MITRE] catalog parsed but could not be persisted: %v", perr)
	}
	return n, false, nil
}

// SyncFromFile loads updated ATT&CK STIX / JSON from a local filepath (e.g. for air-gapped systems)
func (c *Catalog) SyncFromFile(filePath string) (int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("open MITRE file: %w", err)
	}
	defer f.Close()

	n, err := c.ParseSTIXStream(f, filePath)
	if err != nil {
		return 0, err
	}
	c.markSuccess()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if perr := c.persist(ctx); perr != nil {
		log.Printf("[MITRE] catalog parsed but could not be persisted: %v", perr)
	}
	return n, nil
}

func (c *Catalog) markSuccess() {
	now := time.Now().UTC()
	c.mu.Lock()
	c.autoSync.LastSuccess = &now
	c.autoSync.LastError = ""
	c.mu.Unlock()
}

func cleanDescription(s string) string {
	s = reCitation.ReplaceAllString(s, "")
	if i := strings.Index(s, "\n"); i > 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		cut := strings.LastIndex(s[:400], " ")
		if cut < 200 {
			cut = 400
		}
		s = s[:cut] + "…"
	}
	return s
}

// ParseSTIXStream parses STIX 2.1 JSON or lightweight JSON matrix definition
func (c *Catalog) ParseSTIXStream(r io.Reader, sourceName string) (int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("read stream: %w", err)
	}

	// First try lightweight catalog schema
	type SimpleFormat struct {
		Version    string      `json:"version"`
		Techniques []Technique `json:"techniques"`
	}
	var sf SimpleFormat
	if jsonErr := json.Unmarshal(data, &sf); jsonErr == nil && len(sf.Techniques) > 0 {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, t := range sf.Techniques {
			if t.ID != "" {
				c.techniques[t.ID] = t
			}
		}
		if sf.Version != "" {
			c.version = sf.Version
		}
		c.lastUpdated = time.Now().UTC()
		c.source = sourceName
		c.isBaseline = false
		return len(sf.Techniques), nil
	}

	type stixRef struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
		URL        string `json:"url"`
	}
	type stixPhase struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	}
	type stixObject struct {
		ID              string      `json:"id"`
		Type            string      `json:"type"`
		Name            string      `json:"name"`
		Description     string      `json:"description"`
		ExternalRefs    []stixRef   `json:"external_references"`
		KillChainPhases []stixPhase `json:"kill_chain_phases"`
		Revoked         bool        `json:"revoked"`
		Deprecated      bool        `json:"x_mitre_deprecated"`
		IsSubtechnique  bool        `json:"x_mitre_is_subtechnique"`
		Platforms       []string    `json:"x_mitre_platforms"`
		ShortName       string      `json:"x_mitre_shortname"`
		TacticRefs      []string    `json:"tactic_refs"`
		XMitreVersion   string      `json:"x_mitre_version"`
	}
	var bundle struct {
		Objects []stixObject `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return 0, fmt.Errorf("unmarshal JSON: %w", err)
	}
	data = nil // release the raw buffer early (feed is 50+ MB)

	extID := func(o stixObject) (string, string) {
		for _, ref := range o.ExternalRefs {
			if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
				return ref.ExternalID, ref.URL
			}
		}
		return "", ""
	}

	// 1. Tactics (dynamic - a future ATT&CK release adding a tactic is picked up automatically)
	tacticByStixID := make(map[string]Tactic)
	for _, o := range bundle.Objects {
		if o.Type != "x-mitre-tactic" || o.Revoked || o.Deprecated {
			continue
		}
		id, url := extID(o)
		if id == "" || o.ShortName == "" {
			continue
		}
		tacticByStixID[o.ID] = Tactic{ID: id, Name: o.Name, ShortName: o.ShortName, Description: cleanDescription(o.Description), URL: url}
	}
	var orderedTactics []Tactic
	attackVersion := ""
	for _, o := range bundle.Objects {
		switch o.Type {
		case "x-mitre-matrix":
			if len(orderedTactics) == 0 {
				for _, ref := range o.TacticRefs {
					if t, ok := tacticByStixID[ref]; ok {
						orderedTactics = append(orderedTactics, t)
					}
				}
			}
		case "x-mitre-collection":
			if o.XMitreVersion != "" {
				attackVersion = o.XMitreVersion
			}
		}
	}
	if len(orderedTactics) == 0 && len(tacticByStixID) > 0 {
		for _, t := range tacticByStixID {
			orderedTactics = append(orderedTactics, t)
		}
		sort.Slice(orderedTactics, func(i, j int) bool { return orderedTactics[i].ID < orderedTactics[j].ID })
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	tacticList := c.tactics
	if len(orderedTactics) > 0 {
		tacticList = orderedTactics
	}
	phaseToTactic := make(map[string]Tactic, len(tacticList))
	for _, t := range defaultTactics() {
		phaseToTactic[t.ShortName] = t
	}
	for _, t := range tacticList {
		if t.ShortName != "" {
			phaseToTactic[t.ShortName] = t
		}
	}

	// 2. Techniques & sub-techniques
	parsed := make(map[string]Technique)
	for _, o := range bundle.Objects {
		if o.Type != "attack-pattern" || o.Revoked || o.Deprecated {
			continue
		}
		techID, techURL := extID(o)
		if techID == "" {
			continue
		}
		t := Technique{
			ID:          techID,
			Name:        o.Name,
			Description: cleanDescription(o.Description),
			URL:         techURL,
			Platforms:   o.Platforms,
		}
		if i := strings.Index(techID, "."); i > 0 {
			t.SubTechniqueOf = techID[:i]
		}
		for _, ph := range o.KillChainPhases {
			if ph.KillChainName != "mitre-attack" {
				continue
			}
			if tac, ok := phaseToTactic[ph.PhaseName]; ok {
				t.TacticIDs = append(t.TacticIDs, tac.ID)
				if t.TacticID == "" {
					t.TacticID, t.TacticName = tac.ID, tac.Name
				}
			}
		}
		parsed[techID] = t
	}
	// Prefix sub-technique names with their parent ("Brute Force: Password Spraying") for readability
	for id, t := range parsed {
		if t.SubTechniqueOf != "" {
			if p, ok := parsed[t.SubTechniqueOf]; ok && !strings.HasPrefix(t.Name, p.Name+":") {
				t.Name = p.Name + ": " + t.Name
				parsed[id] = t
			}
		}
	}

	if len(parsed) >= minFullCatalogSize {
		// Full release: replace the catalog and compute what is new versus the previous release
		newIDs := make(map[string]bool)
		if !c.isBaseline {
			for id := range parsed {
				if _, existed := c.techniques[id]; !existed {
					newIDs[id] = true
				}
			}
			// Keep the previous "new" markers when the feed has not actually changed
			if len(newIDs) == 0 && attackVersion == c.attackVersion {
				newIDs = c.newTechIDs
			}
		}
		if attackVersion != "" && attackVersion != c.attackVersion && c.attackVersion != "" {
			c.previousVersion = c.attackVersion
		}
		c.techniques = parsed
		c.newTechIDs = newIDs
		c.tactics = tacticList
		c.isBaseline = false
	} else {
		// Partial / custom bundle: merge
		for id, t := range parsed {
			if _, existed := c.techniques[id]; !existed && !c.isBaseline {
				c.newTechIDs[id] = true
			}
			c.techniques[id] = t
		}
	}

	if attackVersion != "" {
		c.attackVersion = attackVersion
		c.version = fmt.Sprintf("Enterprise ATT&CK v%s", attackVersion)
	} else {
		c.version = fmt.Sprintf("MITRE ATT&CK STIX 2.1 (%d techniques)", len(c.techniques))
	}
	c.lastUpdated = time.Now().UTC()
	c.source = sourceName

	return len(parsed), nil
}

// ---------------------------------------------------------------------------
// Automatic release watcher
// ---------------------------------------------------------------------------

// AutoSyncConfig controls the background ATT&CK release watcher
type AutoSyncConfig struct {
	Enabled       bool
	FeedURL       string
	CheckInterval time.Duration
	InitialDelay  time.Duration
}

var autoSyncRunning atomic.Bool

// SetAutoSyncEnabled toggles the watcher at runtime (takes effect on the next tick)
func (c *Catalog) SetAutoSyncEnabled(enabled bool) {
	c.mu.Lock()
	c.autoSync.Enabled = enabled
	c.mu.Unlock()
}

// AutoSyncStatus returns the current watcher state
func (c *Catalog) AutoSyncStatus() AutoSyncStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.autoSync
}

// CheckForUpdate performs one conditional check against the feed and loads a new release if present
func (c *Catalog) CheckForUpdate(ctx context.Context) (string, error) {
	c.mu.RLock()
	url := c.autoSync.FeedURL
	prevVersion := c.attackVersion
	prevCount := len(c.techniques)
	c.mu.RUnlock()

	now := time.Now().UTC()
	n, notModified, err := c.syncFromURL(ctx, url, true)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.autoSync.LastCheck = &now
	if err != nil {
		c.autoSync.LastError = err.Error()
		c.autoSync.LastResult = "error"
		return "", err
	}
	var result string
	switch {
	case notModified:
		result = fmt.Sprintf("Feed unchanged (ATT&CK v%s, %d techniques)", c.attackVersion, len(c.techniques))
	case c.attackVersion != prevVersion && prevVersion != "":
		result = fmt.Sprintf("New ATT&CK release v%s loaded (was v%s): %d techniques, %d new", c.attackVersion, prevVersion, len(c.techniques), len(c.newTechIDs))
	default:
		result = fmt.Sprintf("Catalog refreshed: %d techniques parsed (previously %d), %d new", n, prevCount, len(c.newTechIDs))
	}
	c.autoSync.LastResult = result
	c.autoSync.LastError = ""
	return result, nil
}

// StartAutoSync launches the background watcher. It is safe to call once at startup.
func (c *Catalog) StartAutoSync(ctx context.Context, cfg AutoSyncConfig) {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 24 * time.Hour
	}
	if cfg.InitialDelay <= 0 {
		cfg.InitialDelay = 45 * time.Second
	}
	if cfg.FeedURL == "" {
		cfg.FeedURL = DefaultMITRESTIXURL
	}

	c.mu.Lock()
	c.autoSync.Enabled = cfg.Enabled
	c.autoSync.FeedURL = cfg.FeedURL
	c.autoSync.IntervalHours = int(cfg.CheckInterval / time.Hour)
	next := time.Now().UTC().Add(cfg.InitialDelay)
	c.autoSync.NextCheck = &next
	c.mu.Unlock()

	if !autoSyncRunning.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer autoSyncRunning.Store(false)
		timer := time.NewTimer(cfg.InitialDelay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}

			wait := cfg.CheckInterval
			if c.AutoSyncStatus().Enabled {
				checkCtx, cancel := context.WithTimeout(ctx, 6*time.Minute)
				result, err := c.CheckForUpdate(checkCtx)
				cancel()
				if err != nil {
					log.Printf("[MITRE] auto-sync check failed: %v (retrying in 1h)", err)
					if !errors.Is(err, context.Canceled) {
						wait = time.Hour
					}
				} else {
					log.Printf("[MITRE] auto-sync: %s", result)
				}
			}

			next := time.Now().UTC().Add(wait)
			c.mu.Lock()
			c.autoSync.NextCheck = &next
			c.mu.Unlock()
			timer.Reset(wait)
		}
	}()
}
