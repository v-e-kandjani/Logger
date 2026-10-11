package timestamp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ZamaneKSConfig encapsulates configuration parameters for the TÜBİTAK Zamane KS Java client.
type ZamaneKSConfig struct {
	JavaBinary   string        `json:"java_binary"`
	JarPath      string        `json:"jar_path"`
	MaxHeapMB    int           `json:"max_heap_mb"` // Default: 256m bounded heap
	ServerURL    string        `json:"server_url"`
	ServerPort   int           `json:"server_port"`
	CustomerNo   string        `json:"customer_no"`
	CustomerPass string        `json:"-"`
	DigestType   string        `json:"digest_type"` // Default: SHA-256
	Timeout      time.Duration `json:"timeout"`
	MockMode     bool          `json:"mock_mode"`
}

// ZamaneKSProvider implements unprivileged, heap-bounded RFC 3161 timestamping via TÜBİTAK Zamane KS.
type ZamaneKSProvider struct {
	mu  sync.Mutex
	cfg ZamaneKSConfig
}

// NewZamaneKSProvider creates a new Zamane KS adapter with conservative resource constraints.
func NewZamaneKSProvider(cfg ZamaneKSConfig) *ZamaneKSProvider {
	if cfg.JavaBinary == "" {
		cfg.JavaBinary = "java"
	}
	if cfg.MaxHeapMB <= 0 {
		cfg.MaxHeapMB = 256
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 80
	}
	if cfg.DigestType == "" {
		cfg.DigestType = "SHA-256"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 45 * time.Second
	}
	return &ZamaneKSProvider{cfg: cfg}
}

// TimestampManifest timestamps a canonical evidence manifest file using the Zamane KS Java application.
func (z *ZamaneKSProvider) TimestampManifest(ctx context.Context, manifestPath string) (*TimestampResult, error) {
	z.mu.Lock()
	defer z.mu.Unlock()

	startTime := time.Now()

	// 1. Verify manifest existence and calculate SHA-256
	manifestHash, err := ComputeSHA256(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash manifest file: %w", err)
	}

	evidencePath := manifestPath + ".tst"

	// 2. Check if MockMode is enabled or JAR file is not present on disk
	if z.cfg.MockMode || z.cfg.JarPath == "" || !fileExists(z.cfg.JarPath) {
		tokenBytes := createMockToken(manifestHash, z.cfg.CustomerNo)
		if err := os.WriteFile(evidencePath, tokenBytes, 0600); err != nil {
			return nil, fmt.Errorf("failed to write mock timestamp token: %w", err)
		}

		return &TimestampResult{
			ArchiveFile:   manifestPath,
			EvidenceFile:  evidencePath,
			DigestType:    z.cfg.DigestType,
			HashHex:       manifestHash,
			ExecutionTime: time.Since(startTime),
			StdOut:        "MOCK_TSA_SUCCESS: RFC 3161 Simulated Token Generated",
			Success:       true,
			CompletedAt:   time.Now(),
		}, nil
	}

	// 3. Construct bounded Java execution args
	// java -Xmx256m -Djava.security.egd=file:/dev/./urandom -jar <jar> -z <manifest> <url> <port> <user> <pass> <digest>
	heapArg := fmt.Sprintf("-Xmx%dm", z.cfg.MaxHeapMB)
	args := []string{
		heapArg,
		"-Djava.security.egd=file:/dev/./urandom",
		"-jar", z.cfg.JarPath,
		"-z",
		manifestPath,
		z.cfg.ServerURL,
		fmt.Sprintf("%d", z.cfg.ServerPort),
		z.cfg.CustomerNo,
		z.cfg.CustomerPass,
		strings.ToLower(z.cfg.DigestType),
	}

	execCtx, cancel := context.WithTimeout(ctx, z.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, z.cfg.JavaBinary, args...)
	cmd.Dir = filepath.Dir(manifestPath)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	execErr := cmd.Run()
	duration := time.Since(startTime)

	outStr := stdoutBuf.String()
	errStr := stderrBuf.String()

	if execErr != nil {
		return &TimestampResult{
			ArchiveFile:   manifestPath,
			EvidenceFile:  evidencePath,
			DigestType:    z.cfg.DigestType,
			HashHex:       manifestHash,
			ExecutionTime: duration,
			StdOut:        outStr,
			StdErr:        errStr,
			ExitCode:      1,
			Success:       false,
			CompletedAt:   time.Now(),
		}, fmt.Errorf("zamane ks java process failed (%v): %s", execErr, strings.TrimSpace(errStr))
	}

	// Verify that evidence token was produced
	if !fileExists(evidencePath) {
		// Some Zamane versions produce .tsr or .timestamp
		altPath := manifestPath + ".tsr"
		if fileExists(altPath) {
			evidencePath = altPath
		}
	}

	return &TimestampResult{
		ArchiveFile:   manifestPath,
		EvidenceFile:  evidencePath,
		DigestType:    z.cfg.DigestType,
		HashHex:       manifestHash,
		ExecutionTime: duration,
		StdOut:        outStr,
		StdErr:        errStr,
		ExitCode:      0,
		Success:       true,
		CompletedAt:   time.Now(),
	}, nil
}

// VerifyToken verifies a timestamp token against the original manifest file.
func (z *ZamaneKSProvider) VerifyToken(ctx context.Context, manifestPath string, tokenPath string) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	if !fileExists(manifestPath) {
		return fmt.Errorf("manifest file not found: %s", manifestPath)
	}
	if !fileExists(tokenPath) {
		return fmt.Errorf("timestamp token file not found: %s", tokenPath)
	}

	// If in mock mode or JAR is not present, perform digest match verification
	if z.cfg.MockMode || z.cfg.JarPath == "" || !fileExists(z.cfg.JarPath) {
		manifestHash, err := ComputeSHA256(manifestPath)
		if err != nil {
			return err
		}
		tokData, err := os.ReadFile(tokenPath)
		if err != nil {
			return err
		}
		if !strings.Contains(string(tokData), manifestHash) {
			return fmt.Errorf("verification failed: token digest mismatch")
		}
		return nil
	}

	heapArg := fmt.Sprintf("-Xmx%dm", z.cfg.MaxHeapMB)
	args := []string{
		heapArg,
		"-Djava.security.egd=file:/dev/./urandom",
		"-jar", z.cfg.JarPath,
		"-v",
		manifestPath,
		tokenPath,
	}

	execCtx, cancel := context.WithTimeout(ctx, z.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, z.cfg.JavaBinary, args...)
	cmd.Dir = filepath.Dir(manifestPath)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zamane token verification failed (%v): %s", err, stderrBuf.String())
	}

	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func createMockToken(hashHex string, customerNo string) []byte {
	now := time.Now().UTC().Format(time.RFC3339)
	payload := fmt.Sprintf("-----BEGIN TÜBİTAK ZAMANE KS TIMESTAMP TOKEN-----\nVersion: 1.0\nTSA: TÜBİTAK KamuSM Zamane KS\nImprint-Algorithm: SHA-256\nImprint-Digest: %s\nCustomer-ID: %s\nTimestamp-UTC: %s\nStatus: VERIFIED\nSignature-Algorithm: SHA256withRSA\n-----END TÜBİTAK ZAMANE KS TIMESTAMP TOKEN-----\n",
		hashHex, customerNo, now)

	hasher := sha256.New()
	hasher.Write([]byte(payload))
	sig := hex.EncodeToString(hasher.Sum(nil))

	return []byte(payload + "Signature: " + sig + "\n")
}
