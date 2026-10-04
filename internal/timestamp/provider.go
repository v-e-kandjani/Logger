package timestamp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// TimestampResult represents the outcome of a KamuSM or Mock stamping operation
type TimestampResult struct {
	ArchiveFile    string        `json:"archive_file"`
	EvidenceFile   string        `json:"evidence_file"`
	DigestType     string        `json:"digest_type"`
	HashHex        string        `json:"hash_hex"`
	ExecutionTime  time.Duration `json:"execution_time"`
	StdOut         string        `json:"stdout"`
	StdErr         string        `json:"stderr"`
	ExitCode       int           `json:"exit_code"`
	Success        bool          `json:"success"`
	CompletedAt    time.Time     `json:"completed_at"`
}

// TimestampProvider defines the contract for signing and verifying log archives
type TimestampProvider interface {
	Timestamp(ctx context.Context, inputFile string) (*TimestampResult, error)
	Verify(ctx context.Context, originalFile string, timestampEvidenceFile string) error
	QueryCredit(ctx context.Context) (string, error)
}

// KamuSMConfig holds verified command-line parameters for tss-client-console
type KamuSMConfig struct {
	JavaBinary   string        // default: /usr/bin/java
	JarPath      string        // e.g. /opt/syslog-platform/timestamp-client/tss-client-console-3.1.33.jar
	ServerURL    string        // http://zd.kamusm.gov.tr or http://tzd.kamusm.gov.tr
	ServerPort   int           // 80
	CustomerNo   string        // Client Account Number
	CustomerPass string        // Client Password
	DigestType   string        // sha-256
	ProxyIP      string        // optional proxy
	ProxyPort    int           // optional proxy port
	ProxyUser    string        // optional proxy auth
	ProxyPass    string        // optional proxy pass
	Timeout      time.Duration // command execution timeout
}

// KamuSMTimestampProvider executes official TÜBİTAK KamuSM console application via isolated exec.Command
type KamuSMTimestampProvider struct {
	mu  sync.RWMutex
	cfg KamuSMConfig
}

// NewKamuSMProvider creates an instance configured according to official documentation
func NewKamuSMProvider(cfg KamuSMConfig) *KamuSMTimestampProvider {
	if cfg.JavaBinary == "" {
		cfg.JavaBinary = "java"
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 80
	}
	if cfg.DigestType == "" {
		cfg.DigestType = "sha-256"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &KamuSMTimestampProvider{cfg: cfg}
}

// UpdateConfig allows runtime updates of credentials and endpoints from Web Settings
func (k *KamuSMTimestampProvider) UpdateConfig(cfg KamuSMConfig) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if cfg.JavaBinary != "" {
		k.cfg.JavaBinary = cfg.JavaBinary
	}
	if cfg.JarPath != "" {
		k.cfg.JarPath = cfg.JarPath
	}
	if cfg.ServerURL != "" {
		k.cfg.ServerURL = cfg.ServerURL
	}
	if cfg.CustomerNo != "" {
		k.cfg.CustomerNo = cfg.CustomerNo
	}
	if cfg.CustomerPass != "" {
		k.cfg.CustomerPass = cfg.CustomerPass
	}
	if cfg.DigestType != "" {
		k.cfg.DigestType = cfg.DigestType
	}
}

func (k *KamuSMTimestampProvider) GetConfig() KamuSMConfig {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.cfg
}

// ComputeSHA256 returns hex digest of the file
func ComputeSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// BuildTimestampArgs constructs the exact argument list based on KamuSM documentation:
// java -jar tss-client-console-3.1.33.jar -z [File] [TSS Address] [TSS Port] [Customer No] [Customer Password] [Digest Type]
func (k *KamuSMTimestampProvider) BuildTimestampArgs(inputFile string) []string {
	k.mu.RLock()
	defer k.mu.RUnlock()

	args := []string{
		"-jar", k.cfg.JarPath,
		"-z",
		inputFile,
		k.cfg.ServerURL,
		fmt.Sprintf("%d", k.cfg.ServerPort),
		k.cfg.CustomerNo,
		k.cfg.CustomerPass,
	}

	if k.cfg.ProxyIP != "" && k.cfg.ProxyPort > 0 {
		args = append(args, k.cfg.ProxyIP, fmt.Sprintf("%d", k.cfg.ProxyPort))
		if k.cfg.ProxyUser != "" {
			args = append(args, k.cfg.ProxyUser, k.cfg.ProxyPass)
		}
	}

	args = append(args, k.cfg.DigestType)
	return args
}

// BuildVerifyArgs constructs arguments for timestamp validation:
// java -jar tss-client-console-3.1.33.jar -c [File] [Time Stamp File]
func (k *KamuSMTimestampProvider) BuildVerifyArgs(inputFile, evidenceFile string) []string {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return []string{
		"-jar", k.cfg.JarPath,
		"-c",
		inputFile,
		evidenceFile,
	}
}

// Timestamp executes official KamuSM JAR and verifies the output evidence file
func (k *KamuSMTimestampProvider) Timestamp(ctx context.Context, inputFile string) (*TimestampResult, error) {
	if _, err := os.Stat(k.cfg.JarPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("KamuSM JAR file not found at %s: ensure client is placed in /opt/syslog-platform/timestamp-client/", k.cfg.JarPath)
	}

	hashVal, err := ComputeSHA256(inputFile)
	if err != nil {
		return nil, fmt.Errorf("calculating archive sha256: %w", err)
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, k.cfg.Timeout)
	defer cancel()

	args := k.BuildTimestampArgs(inputFile)
	// Safe execution: explicit argv slice, never shell=true
	cmd := exec.CommandContext(ctxTimeout, k.cfg.JavaBinary, args...)

	startTime := time.Now()
	outBytes, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	stdoutStr := string(outBytes)
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	result := &TimestampResult{
		ArchiveFile:   inputFile,
		DigestType:    k.cfg.DigestType,
		HashHex:       hashVal,
		ExecutionTime: duration,
		StdOut:        stdoutStr,
		ExitCode:      exitCode,
		CompletedAt:   time.Now().UTC(),
	}

	// KamuSM console client may exit with 0 even when throwing an exception; check output text
	if err != nil || strings.Contains(stdoutStr, "[ERROR]") || strings.Contains(stdoutStr, "ESYAException") {
		result.Success = false
		result.StdErr = stdoutStr
		return result, fmt.Errorf("kamusm timestamp failed (exit %d): %s", exitCode, stdoutStr)
	}

	// KamuSM outputs timestamp evidence alongside input: <inputFile>.zd
	expectedEvidence := inputFile + ".zd"
	if _, err := os.Stat(expectedEvidence); os.IsNotExist(err) {
		result.Success = false
		return result, fmt.Errorf("expected timestamp evidence file %s was not produced by KamuSM client", expectedEvidence)
	}

	result.EvidenceFile = expectedEvidence
	result.Success = true
	return result, nil
}

// Verify checks the timestamp token against the original file
func (k *KamuSMTimestampProvider) Verify(ctx context.Context, originalFile string, timestampEvidenceFile string) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, k.cfg.Timeout)
	defer cancel()

	args := k.BuildVerifyArgs(originalFile, timestampEvidenceFile)
	cmd := exec.CommandContext(ctxTimeout, k.cfg.JavaBinary, args...)

	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err != nil {
		return fmt.Errorf("verification failed: %v, output: %s", err, outStr)
	}

	// Detect negative verification indications in stdout
	if strings.Contains(strings.ToLower(outStr), "invalid") || strings.Contains(strings.ToLower(outStr), "failed") {
		return fmt.Errorf("kamusm reported verification failure: %s", outStr)
	}

	return nil
}

// QueryCredit runs the -k option to check remaining KamuSM timestamp credits
func (k *KamuSMTimestampProvider) QueryCredit(ctx context.Context) (string, error) {
	args := []string{
		"-jar", k.cfg.JarPath,
		"-k",
		k.cfg.ServerURL,
		fmt.Sprintf("%d", k.cfg.ServerPort),
		k.cfg.CustomerNo,
		k.cfg.CustomerPass,
	}

	cmd := exec.CommandContext(ctx, k.cfg.JavaBinary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("query credit failed: %v, output: %s", err, string(out))
	}
	return string(out), nil
}

// MockTimestampProvider provides deterministic SHA-256 pseudo-stamping for automated tests and dev
type MockTimestampProvider struct{}

func NewMockTimestampProvider() *MockTimestampProvider {
	return &MockTimestampProvider{}
}

func (m *MockTimestampProvider) Timestamp(ctx context.Context, inputFile string) (*TimestampResult, error) {
	hashVal, err := ComputeSHA256(inputFile)
	if err != nil {
		return nil, err
	}

	evidenceFile := inputFile + ".zd"
	evidenceContent := fmt.Sprintf("MOCK_KAMUSM_EVIDENCE\nFile: %s\nSHA256: %s\nStampedAt: %s\nServer: http://tzd.kamusm.gov.tr\n",
		inputFile, hashVal, time.Now().UTC().Format(time.RFC3339Nano))

	if err := os.WriteFile(evidenceFile, []byte(evidenceContent), 0644); err != nil {
		return nil, fmt.Errorf("writing mock evidence: %w", err)
	}

	return &TimestampResult{
		ArchiveFile:   inputFile,
		EvidenceFile:  evidenceFile,
		DigestType:    "sha-256",
		HashHex:       hashVal,
		ExecutionTime: 12 * time.Millisecond,
		StdOut:        "Mock timestamp generated successfully",
		ExitCode:      0,
		Success:       true,
		CompletedAt:   time.Now().UTC(),
	}, nil
}

func (m *MockTimestampProvider) Verify(ctx context.Context, originalFile string, timestampEvidenceFile string) error {
	currentHash, err := ComputeSHA256(originalFile)
	if err != nil {
		return fmt.Errorf("computing original file hash: %w", err)
	}

	data, err := os.ReadFile(timestampEvidenceFile)
	if err != nil {
		return fmt.Errorf("reading evidence file: %w", err)
	}

	if !strings.Contains(string(data), currentHash) {
		return fmt.Errorf("evidence hash mismatch: file was modified after timestamping")
	}

	return nil
}

func (m *MockTimestampProvider) QueryCredit(ctx context.Context) (string, error) {
	return "Mock Account: 999999 credits remaining", nil
}
