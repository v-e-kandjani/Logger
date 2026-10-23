package fim

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanner_BaselineAndDeviation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "fim_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "critical_config.conf")
	if err := os.WriteFile(testFile, []byte("initial content v1"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	scanner := NewScanner()
	scanner.defaultPaths = nil // clear system paths so test runs isolated

	// 1. Initial scan should establish baseline with 0 deviation events
	events, baselines := scanner.Scan([]string{testFile}, nil)

	if len(events) != 0 {
		t.Errorf("expected 0 events on initial scan, got %d", len(events))
	}
	if len(baselines) != 1 {
		t.Fatalf("expected 1 baseline item, got %d", len(baselines))
	}
	if baselines[0].TargetPath != testFile {
		t.Errorf("expected path %s, got %s", testFile, baselines[0].TargetPath)
	}
	if baselines[0].SHA256Hash == "" {
		t.Errorf("expected non-empty sha256 hash in baseline")
	}

	// 2. Scan again without modification -> 0 events
	events, _ = scanner.Scan([]string{testFile}, nil)
	if len(events) != 0 {
		t.Errorf("expected 0 events when file is unchanged, got %d", len(events))
	}

	// 3. Modify file -> 1 MODIFIED event with previous and current hash
	if err := os.WriteFile(testFile, []byte("tampered content v2!"), 0644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	events, _ = scanner.Scan([]string{testFile}, nil)
	if len(events) != 1 {
		t.Fatalf("expected 1 event on modification, got %d", len(events))
	}
	if events[0].EventType != "modified" {
		t.Errorf("expected event_type 'modified', got '%s'", events[0].EventType)
	}
	if events[0].PreviousHash == "" || events[0].CurrentHash == "" {
		t.Errorf("expected both previous and current hash populated")
	}
	if events[0].PreviousHash == events[0].CurrentHash {
		t.Errorf("expected previous and current hash to differ")
	}

	// 4. Delete file -> 1 DELETED event
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("failed to delete test file: %v", err)
	}

	events, _ = scanner.Scan([]string{testFile}, nil)
	if len(events) != 1 {
		t.Fatalf("expected 1 event on deletion, got %d", len(events))
	}
	if events[0].EventType != "deleted" {
		t.Errorf("expected event_type 'deleted', got '%s'", events[0].EventType)
	}
}
