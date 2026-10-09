package mfa

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestMFAWorkflow(t *testing.T) {
	pkg, err := GenerateSetupPackage("soc.analyst")
	if err != nil {
		t.Fatalf("GenerateSetupPackage failed: %v", err)
	}

	if len(pkg.Secret) < 16 {
		t.Errorf("Secret is too short: %s", pkg.Secret)
	}
	if len(pkg.RecoveryCodes) != 8 {
		t.Errorf("Expected 8 recovery codes, got %d", len(pkg.RecoveryCodes))
	}
	if len(pkg.QRCodeBase64) < 100 {
		t.Errorf("QRCodeBase64 is empty or invalid: %s", pkg.QRCodeBase64)
	}

	// Generate expected code right now
	now := time.Now()
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(pkg.Secret))
	if err != nil {
		t.Fatalf("Failed decoding secret: %v", err)
	}
	counter := uint64(now.Unix() / DefaultPeriod)
	validCode := generateCode(secretBytes, counter)

	// Validate TOTP
	if !ValidateTOTP(pkg.Secret, validCode, now) {
		t.Errorf("ValidateTOTP failed for freshly generated code: %s", validCode)
	}

	// Validate within 30s window
	if !ValidateTOTP(pkg.Secret, validCode, now.Add(25*time.Second)) {
		t.Errorf("ValidateTOTP should succeed within 30s window")
	}

	// Invalid code should fail
	if ValidateTOTP(pkg.Secret, "000000", now) && validCode != "000000" {
		t.Errorf("ValidateTOTP should fail for bogus code")
	}
}
