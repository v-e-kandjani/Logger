package mitre

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syslog-platform/logger/internal/models"
)

type memStore struct {
	mu   sync.Mutex
	data []byte
}

func (m *memStore) LoadMitreCatalog(ctx context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data, nil
}
func (m *memStore) SaveMitreCatalog(ctx context.Context, p []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append([]byte(nil), p...)
	return nil
}

// buildBundle produces a synthetic but structurally faithful enterprise STIX bundle
func buildBundle(version string, techCount int, extra ...string) string {
	var b strings.Builder
	b.WriteString(`{"type":"bundle","objects":[`)
	fmt.Fprintf(&b, `{"type":"x-mitre-collection","id":"x-mitre-collection--1","x_mitre_version":"%s"},`, version)
	tactics := []struct{ stix, id, short, name string }{
		{"x-mitre-tactic--a", "TA0001", "initial-access", "Initial Access"},
		{"x-mitre-tactic--b", "TA0003", "persistence", "Persistence"},
		{"x-mitre-tactic--c", "TA0005", "defense-evasion", "Defense Evasion"},
	}
	refs := []string{}
	for _, t := range tactics {
		fmt.Fprintf(&b, `{"type":"x-mitre-tactic","id":"%s","name":"%s","x_mitre_shortname":"%s","description":"d","external_references":[{"source_name":"mitre-attack","external_id":"%s","url":"https://attack.mitre.org/tactics/%s/"}]},`, t.stix, t.name, t.short, t.id, t.id)
		refs = append(refs, `"`+t.stix+`"`)
	}
	fmt.Fprintf(&b, `{"type":"x-mitre-matrix","id":"x-mitre-matrix--1","tactic_refs":[%s]},`, strings.Join(refs, ","))
	// Multi-tactic technique, like T1078 Valid Accounts
	b.WriteString(`{"type":"attack-pattern","name":"Valid Accounts","description":"Abuse creds (Citation: X)","external_references":[{"source_name":"mitre-attack","external_id":"T1078","url":"u"}],"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"initial-access"},{"kill_chain_name":"mitre-attack","phase_name":"persistence"},{"kill_chain_name":"mitre-attack","phase_name":"defense-evasion"}]},`)
	b.WriteString(`{"type":"attack-pattern","name":"Local Accounts","x_mitre_is_subtechnique":true,"external_references":[{"source_name":"mitre-attack","external_id":"T1078.003","url":"u"}],"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"persistence"}]},`)
	b.WriteString(`{"type":"attack-pattern","name":"Old Revoked","revoked":true,"external_references":[{"source_name":"mitre-attack","external_id":"T0001","url":"u"}],"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"persistence"}]},`)
	for i := 0; i < techCount; i++ {
		fmt.Fprintf(&b, `{"type":"attack-pattern","name":"Tech %d","external_references":[{"source_name":"mitre-attack","external_id":"T5%03d","url":"u"}],"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"persistence"}]},`, i, i)
	}
	for _, e := range extra {
		b.WriteString(e + ",")
	}
	b.WriteString(`{"type":"identity","id":"identity--1"}]}`)
	return b.String()
}

func TestSTIX_MultiTacticAndDynamicTactics(t *testing.T) {
	cat := NewCatalog()
	if _, err := cat.ParseSTIXStream(strings.NewReader(buildBundle("17.1", 150)), "test"); err != nil {
		t.Fatal(err)
	}
	if _, ok := cat.GetTechnique("T1110"); ok {
		t.Errorf("full release must replace the embedded baseline (T1110 not in synthetic feed)")
	}
	if _, ok := cat.GetTechnique("T0001"); ok {
		t.Errorf("revoked technique must be skipped")
	}
	sub, _ := cat.GetTechnique("T1078.003")
	if sub.SubTechniqueOf != "T1078" || sub.Name != "Valid Accounts: Local Accounts" {
		t.Errorf("unexpected sub-technique: %+v", sub)
	}

	report := cat.GenerateCoverageReport([]models.SIEMRule{{ID: "R1", MitreTechnique: "T1078.003", IsEnabled: true}}, nil)
	if report.AttackVersion != "17.1" || report.TotalTactics != 3 || report.IsBaseline {
		t.Errorf("version/tactics wrong: %s %d %v", report.AttackVersion, report.TotalTactics, report.IsBaseline)
	}
	placed := 0
	for _, tac := range report.Tactics {
		for _, tech := range tac.Techniques {
			if tech.ID == "T1078" {
				placed++
				if !tech.Covered {
					t.Errorf("T1078 should be covered via its sub-technique in %s", tac.ID)
				}
			}
		}
	}
	if placed != 3 {
		t.Errorf("T1078 should appear under all 3 of its tactics, got %d", placed)
	}
	if report.TotalTechniques != 152 {
		t.Errorf("expected 152 unique techniques, got %d", report.TotalTechniques)
	}
	if report.NewTechniques != 0 {
		t.Errorf("initial sync from baseline must not flag everything as new, got %d", report.NewTechniques)
	}
}

func TestSTIX_NewReleaseFlagsNewTechniques(t *testing.T) {
	cat := NewCatalog()
	_, _ = cat.ParseSTIXStream(strings.NewReader(buildBundle("17.1", 150)), "test")
	_, _ = cat.ParseSTIXStream(strings.NewReader(buildBundle("18.0", 153)), "test")

	report := cat.GenerateCoverageReport(nil, nil)
	if report.NewTechniques != 3 || report.PreviousVersion != "17.1" || report.AttackVersion != "18.0" {
		t.Fatalf("expected 3 new in 18.0 (prev 17.1), got %d new, prev=%s cur=%s", report.NewTechniques, report.PreviousVersion, report.AttackVersion)
	}
	newSeen := 0
	for _, tac := range report.Tactics {
		for _, tech := range tac.Techniques {
			if tech.IsNew {
				newSeen++
			}
		}
	}
	if newSeen != 3 {
		t.Errorf("expected 3 techniques rendered with is_new, got %d", newSeen)
	}
}

func TestCatalog_PersistAndRestore(t *testing.T) {
	store := &memStore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v17"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v17"`)
		_, _ = w.Write([]byte(buildBundle("17.1", 150)))
	}))
	defer srv.Close()

	cat := NewCatalog()
	cat.SetStore(store)
	cat.StartAutoSync(context.Background(), AutoSyncConfig{Enabled: false, FeedURL: srv.URL, CheckInterval: time.Hour, InitialDelay: time.Hour})

	result, err := cat.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if store.data == nil {
		t.Fatalf("catalog was not persisted after sync (result: %s)", result)
	}

	// Second check: unchanged feed -> 304, no re-download
	result, err = cat.CheckForUpdate(context.Background())
	if err != nil || !strings.Contains(result, "unchanged") {
		t.Errorf("expected 304 'unchanged' result, got %q err=%v", result, err)
	}

	// Simulated restart / upgrade: a fresh catalog restores the synced release from the store
	restarted := NewCatalog()
	restarted.SetStore(store)
	if err := restarted.LoadFromStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	rep := restarted.GenerateCoverageReport(nil, nil)
	if rep.IsBaseline || rep.AttackVersion != "17.1" || rep.TotalTechniques != 152 {
		t.Errorf("restore failed: baseline=%v version=%s techs=%d", rep.IsBaseline, rep.AttackVersion, rep.TotalTechniques)
	}
}

// TestSTIX_LiveFeed parses the real MITRE feed. Run with: MITRE_LIVE_TEST=1 go test ./internal/siem/mitre -run LiveFeed -v
func TestSTIX_LiveFeed(t *testing.T) {
	if os.Getenv("MITRE_LIVE_TEST") == "" {
		t.Skip("set MITRE_LIVE_TEST=1 to download the official feed")
	}
	cat := NewCatalog()
	store := &memStore{}
	cat.SetStore(store)
	n, err := cat.SyncFromURL(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	rep := cat.GenerateCoverageReport(nil, nil)
	t.Logf("parsed=%d version=%s tactics=%d techniques=%d (parent %d / sub %d) persisted=%d bytes",
		n, rep.Version, rep.TotalTactics, rep.TotalTechniques, rep.TotalParent, rep.TotalSub, len(store.data))
	for _, tac := range rep.Tactics {
		t.Logf("  %s %-22s %d", tac.ID, tac.Name, tac.TotalTechniques)
	}
	if rep.TotalTactics < 14 || rep.TotalParent < 180 || rep.TotalSub < 350 {
		t.Errorf("live feed looks incomplete")
	}
}
