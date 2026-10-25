package ransomware

import (
	"os"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	// Plain text should have moderate/low entropy (< 5.0)
	plain := []byte("The quick brown fox jumps over the lazy dog 1234567890 hello world")
	hPlain := CalculateShannonEntropy(plain)
	if hPlain > 5.5 {
		t.Errorf("Expected low entropy for plain text, got %f", hPlain)
	}

	// Pseudo-random high-entropy bytes simulating AES/ChaCha20 ciphertext (> 7.0)
	var cipher []byte
	for i := 0; i < 256; i++ {
		cipher = append(cipher, byte(i))
	}
	hCipher := CalculateShannonEntropy(cipher)
	if hCipher < 7.9 {
		t.Errorf("Expected maximum entropy for uniformly distributed bytes, got %f", hCipher)
	}
}

func TestCanaryDeploymentAndTamperDetection(t *testing.T) {
	cm := NewCanaryManager()
	tokens := cm.DeployInitialCanaries()
	if len(tokens) == 0 {
		t.Fatalf("Expected initial canary tokens to be deployed")
	}

	// Initial inspection: all canaries should be ARMED and 0 incidents
	tokens2, incidents := cm.InspectCanaries()
	if len(incidents) != 0 {
		t.Errorf("Expected 0 incidents on fresh canary inspection, got %d", len(incidents))
	}
	if len(tokens2) == 0 || tokens2[0].Status != "ARMED" {
		t.Errorf("Expected canaries to be ARMED")
	}

	// Tamper with the first canary file
	firstCanary := tokens[0].FilePath
	tamperData := []byte("CORRUPTED_ENCRYPTED_DATA_RANSOMWARE_WAS_HERE_123456789")
	if err := os.WriteFile(firstCanary, tamperData, 0600); err != nil {
		t.Fatalf("Failed tampering canary file: %v", err)
	}

	// Second inspection: tamper must trigger an incident!
	tokens3, incidents2 := cm.InspectCanaries()
	if len(incidents2) == 0 {
		t.Errorf("Expected ransomware tripwire incident after canary tampering, got 0")
	}
	foundTriggered := false
	for _, tok := range tokens3 {
		if tok.FilePath == firstCanary && tok.Status == "TRIGGERED" {
			foundTriggered = true
			break
		}
	}
	if !foundTriggered {
		t.Errorf("Expected tampered canary status to be TRIGGERED")
	}

	// Clean up test file
	_ = os.Remove(firstCanary)
}
