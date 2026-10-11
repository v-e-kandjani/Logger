package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestEvidenceManifestCanonicalFormat(t *testing.T) {
	now := time.Now().UTC()
	start := now.Add(-1 * time.Hour)

	manifest := EvidenceManifest{
		Version:             "1.0",
		Platform:            "Valtrivo LogSeal v1.6.0",
		TenantSlug:          "default",
		WindowStart:         start.Format(time.RFC3339),
		WindowEnd:           now.Format(time.RFC3339),
		TimeBasis:           "receipt_time",
		PayloadFile:         "default_2026-10-11_17-00-00_evidence.log.gz",
		PayloadBytes:        1024500,
		PayloadSHA256:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		RecordCount:         15240,
		TSAImprintAlgorithm: "SHA-256",
		CreatedAt:           now.Format(time.RFC3339),
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal canonical manifest: %v", err)
	}

	hasher := sha256.New()
	hasher.Write(manifestBytes)
	manifestHash := hex.EncodeToString(hasher.Sum(nil))

	if len(manifestHash) != 64 {
		t.Fatalf("expected 64-char hex SHA-256, got len %d", len(manifestHash))
	}

	var parsed EvidenceManifest
	if err := json.Unmarshal(manifestBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal manifest: %v", err)
	}

	if parsed.PayloadSHA256 != manifest.PayloadSHA256 {
		t.Fatalf("payload SHA-256 mismatch")
	}
	if parsed.RecordCount != 15240 {
		t.Fatalf("record count mismatch")
	}
}
