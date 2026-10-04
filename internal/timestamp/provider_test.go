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

func TestInternalTimestampProvider(t *testing.T) {
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "internal-archive.jsonl.gz")
	if err := os.WriteFile(sampleFile, []byte("5651 legal log slice data\n"), 0644); err != nil {
		t.Fatal(err)
	}

	it := NewInternalTimestampProvider()
	ctx := context.Background()

	res, err := it.Timestamp(ctx, sampleFile)
	if err != nil {
		t.Fatalf("internal timestamping failed: %v", err)
	}

	if !res.Success || res.EvidenceFile == "" {
		t.Fatalf("expected successful stamping with non-empty evidence token")
	}

	// Verify token
	if err := it.Verify(ctx, sampleFile, res.EvidenceFile); err != nil {
		t.Fatalf("expected valid verification: %v", err)
	}

	// Verify tampering detection
	_ = os.WriteFile(sampleFile, []byte("corrupted slice content"), 0644)
	if err := it.Verify(ctx, sampleFile, res.EvidenceFile); err == nil {
		t.Fatalf("expected verification error for modified file, but got nil")
	}
}

func TestAdaptiveTimestampProvider(t *testing.T) {
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "adaptive-archive.jsonl.gz")
	_ = os.WriteFile(sampleFile, []byte("test compliance data\n"), 0644)

	ctx := context.Background()

	// 1. Mode: Internal
	pInternal := NewAdaptiveTimestampProvider(ModeInternal, true, KamuSMConfig{})
	res1, err := pInternal.Timestamp(ctx, sampleFile)
	if err != nil || !res1.Success || res1.EvidenceFile == "" {
		t.Fatalf("expected internal stamping success: %v", err)
	}

	// 2. Mode: Disabled
	pDisabled := NewAdaptiveTimestampProvider(ModeDisabled, false, KamuSMConfig{})
	res2, err := pDisabled.Timestamp(ctx, sampleFile)
	if err != nil || res2.EvidenceFile != "" {
		t.Fatalf("expected disabled stamping to have empty evidence: %v", err)
	}

	// 3. Mode: KamuSM with auto-fallback (no credentials configured)
	pKamuSMFallback := NewAdaptiveTimestampProvider(ModeKamuSM, true, KamuSMConfig{})
	res3, err := pKamuSMFallback.Timestamp(ctx, sampleFile)
	if err != nil || !res3.Success || res3.EvidenceFile == "" {
		t.Fatalf("expected auto-fallback to internal stamping when credentials missing: %v", err)
	}

	// 4. Mode: KamuSM with auto-fallback DISABLED (must return error if no credentials)
	pKamuSMNoFallback := NewAdaptiveTimestampProvider(ModeKamuSM, false, KamuSMConfig{})
	_, err = pKamuSMNoFallback.Timestamp(ctx, sampleFile)
	if err == nil {
		t.Fatalf("expected error when credentials missing and auto-fallback disabled")
	}
}

