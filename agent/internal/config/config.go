package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Config represents local agent configuration
type Config struct {
	ServerURL       string `json:"server_url"`
	EnrollmentToken string `json:"enrollment_token,omitempty"`
	DataDir         string `json:"data_dir"`
	IdentityFile    string `json:"identity_file"`
	HeartbeatSec    int    `json:"heartbeat_sec"`
	LogLevel        string `json:"log_level"`
}

// DefaultConfig returns reasonable platform defaults
func DefaultConfig() *Config {
	dataDir := "./data"
	if runtime.GOOS == "windows" {
		dataDir = os.Getenv("ProgramData") + `\LoggerAgent`
	} else if runtime.GOOS == "linux" {
		dataDir = "/var/lib/logger-agent"
	} else if runtime.GOOS == "darwin" {
		dataDir = "/Library/Application Support/LoggerAgent"
	}

	return &Config{
		ServerURL:    "http://127.0.0.1:8080",
		DataDir:      dataDir,
		IdentityFile: filepath.Join(dataDir, "identity.json"),
		HeartbeatSec: 30,
		LogLevel:     "info",
	}
}

// LoadConfig loads from json file or returns defaults
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		}
	}

	// Environment variable overrides
	if u := os.Getenv("LOGGER_SERVER_URL"); u != "" {
		cfg.ServerURL = u
	}
	if t := os.Getenv("LOGGER_ENROLLMENT_TOKEN"); t != "" {
		cfg.EnrollmentToken = t
	}
	if d := os.Getenv("LOGGER_DATA_DIR"); d != "" {
		cfg.DataDir = d
		cfg.IdentityFile = filepath.Join(d, "identity.json")
	}

	return cfg, nil
}
