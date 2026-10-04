package timestamp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestKamuSMCommandArgConstruction(t *testing.T) {
	cfg := KamuSMConfig{
		JavaBinary:   "/usr/bin/java",
		JarPath:      "/opt/syslog-platform/timestamp-client/tss-client-console-3.1.33.jar",
		ServerURL:    "http://zd.kamusm.gov.tr",
		ServerPort:   80,
		CustomerNo:   "123456",
		CustomerPass: "SecretPass!",
		DigestType:   "sha-256",
	}

	provider := NewKamuSMProvider(cfg)
	args := provider.BuildTimestampArgs("/archive/logs-20261004.jsonl.gz")

	expected := []string{
		"-jar", "/opt/syslog-platform/timestamp-client/tss-client-console-3.1.33.jar",
		"-z",
		"/archive/logs-20261004.jsonl.gz",
		"http://zd.kamusm.gov.tr",
		"80",
		"123456",
		"SecretPass!",
		"sha-256",
	}

	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d", len(expected), len(args))
	}

	for i := range args {
		if args[i] != expected[i] {
			t.Errorf("arg mismatch at %d: expected %s, got %s", i, expected[i], args[i])
		}
	}
}

func TestMockTimestampAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "test-archive.jsonl.gz")
	if err := os.WriteFile(sampleFile, []byte("syslog dummy data row 1\nsyslog dummy data row 2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockTimestampProvider()
	ctx := context.Background()

	result, err := mock.Timestamp(ctx, sampleFile)
	if err != nil {
		t.Fatalf("timestamp failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success true")
	}

	if _, err := os.Stat(result.EvidenceFile); os.IsNotExist(err) {
		t.Errorf("evidence file does not exist at %s", result.EvidenceFile)
	}

	// Verify original
	if err := mock.Verify(ctx, sampleFile, result.EvidenceFile); err != nil {
		t.Fatalf("expected valid verification: %v", err)
	}

	// Tamper with original file and verify it detects corruption
	if err := os.WriteFile(sampleFile, []byte("tampered data"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := mock.Verify(ctx, sampleFile, result.EvidenceFile); err == nil {
		t.Errorf("expected verification failure on tampered file, but it passed")
	}
}
