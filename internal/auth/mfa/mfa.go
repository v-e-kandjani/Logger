package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	// TOTP Default Parameters (RFC 6238)
	DefaultPeriod = 30 // seconds
	DefaultDigits = 6
	IssuerName    = "Valtrivo LogSeal"
)

// Supported MFA Provider Profiles
const (
	ProviderTOTP               = "totp"
	ProviderMSAuthenticator    = "ms_authenticator"
	ProviderGoogleAuth         = "google_authenticator"
	ProviderWatchguardAuthpoint= "watchguard_authpoint"
	ProviderFortiAuthenticator = "forti_authenticator"
)

// SetupResult holds enrollment assets for the user
type SetupResult struct {
	Secret        string   `json:"secret"`          // Base32 secret string
	OTPAuthURL    string   `json:"otpauth_url"`     // Standard otpauth:// URI
	QRCodeBase64  string   `json:"qr_code_base64"`  // data:image/png;base64,...
	RecoveryCodes []string `json:"recovery_codes"`  // 8 single-use recovery codes
	Issuer        string   `json:"issuer"`
	AccountName   string   `json:"account_name"`
	Digits        int      `json:"digits"`
	Period        int      `json:"period"`
	SupportedApps []string `json:"supported_apps"`
}

// GenerateSecret creates a cryptographically secure 20-byte (160-bit) random secret,
// encoded as unpadded uppercase Base32 (RFC 4648).
func GenerateSecret() (string, error) {
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generating random secret: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)
	return strings.ToUpper(encoded), nil
}

// GenerateRecoveryCodes generates 8 random 10-character recovery codes
func GenerateRecoveryCodes(count int) ([]string, error) {
	if count <= 0 {
		count = 8
	}
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Crockford-like safe charset
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		var sb strings.Builder
		for j, b := range bytes {
			sb.WriteByte(charset[int(b)%len(charset)])
			if j == 3 {
				sb.WriteByte('-') // e.g. ABCD-EFGH
			}
		}
		codes[i] = sb.String()
	}
	return codes, nil
}

// GenerateSetupPackage creates a complete MFA enrollment bundle including Base32 secret,
// standard otpauth:// URI, and base64 PNG QR code compatible with Microsoft Authenticator,
// Google Authenticator, WatchGuard AuthPoint, and FortiAuthenticator/FortiToken.
func GenerateSetupPackage(username string) (*SetupResult, error) {
	secret, err := GenerateSecret()
	if err != nil {
		return nil, err
	}

	recoveryCodes, err := GenerateRecoveryCodes(8)
	if err != nil {
		return nil, err
	}

	// Standard otpauth URI:
	// otpauth://totp/Valtrivo%20LogSeal:username?secret=...&issuer=Valtrivo%20LogSeal&algorithm=SHA1&digits=6&period=30
	label := fmt.Sprintf("%s:%s", IssuerName, username)
	vals := url.Values{}
	vals.Set("secret", secret)
	vals.Set("issuer", IssuerName)
	vals.Set("algorithm", "SHA1")
	vals.Set("digits", "6")
	vals.Set("period", "30")

	otpAuthURL := fmt.Sprintf("otpauth://totp/%s?%s", url.PathEscape(label), vals.Encode())

	// Generate QR Code PNG directly in memory
	pngBytes, err := qrcode.Encode(otpAuthURL, qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("encoding qr code: %w", err)
	}
	qrCodeBase64 := "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)

	return &SetupResult{
		Secret:        secret,
		OTPAuthURL:    otpAuthURL,
		QRCodeBase64:  qrCodeBase64,
		RecoveryCodes: recoveryCodes,
		Issuer:        IssuerName,
		AccountName:   username,
		Digits:        DefaultDigits,
		Period:        DefaultPeriod,
		SupportedApps: []string{
			"Microsoft Authenticator",
			"Google Authenticator",
			"WatchGuard AuthPoint",
			"FortiAuthenticator / FortiToken",
		},
	}, nil
}

// ValidateTOTP verifies a 6-digit TOTP code against a Base32 secret with a ±1 time-step window (±30s)
// to accommodate slight network/device clock drift.
func ValidateTOTP(secret string, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != DefaultDigits {
		return false
	}

	secret = strings.ToUpper(strings.TrimSpace(secret))
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// Try with standard padding
		secretBytes, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return false
		}
	}

	counter := uint64(t.Unix() / DefaultPeriod)

	// Test current step, previous step (-30s), and next step (+30s)
	windowOffsets := []int64{0, -1, 1}
	for _, offset := range windowOffsets {
		stepCounter := int64(counter) + offset
		if stepCounter < 0 {
			continue
		}
		expectedCode := generateCode(secretBytes, uint64(stepCounter))
		if subtle.ConstantTimeCompare([]byte(expectedCode), []byte(code)) == 1 {
			return true
		}
	}

	return false
}

// generateCode computes HMAC-SHA1 over the 8-byte big-endian counter
func generateCode(secret []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 section 5.3)
	offset := hash[len(hash)-1] & 0x0f
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	pin := truncatedHash % 1000000
	return fmt.Sprintf("%06d", pin)
}
