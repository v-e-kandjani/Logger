package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Syslog     SyslogConfig     `yaml:"syslog"`
	ClickHouse ClickHouseConfig `yaml:"clickhouse"`
	Postgres   PostgresConfig   `yaml:"postgres"`
	Archive    ArchiveConfig    `yaml:"archive"`
	Timestamp  TimestampConfig  `yaml:"timestamp"`
	Spool      SpoolConfig      `yaml:"spool"`
	Security   SecurityConfig   `yaml:"security"`
}

type ServerConfig struct {
	ListenAddr   string `yaml:"listen_addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	CollectorNode string `yaml:"collector_node"`
}

type SyslogConfig struct {
	AcceptUnknownSources bool              `yaml:"accept_unknown_sources"`
	SeedDemoDevices      bool              `yaml:"seed_demo_devices"`
	UDP                  ListenerConfig    `yaml:"udp"`
	TCP                  ListenerConfig    `yaml:"tcp"`
	TLS                  TLSListenerConfig `yaml:"tls"`
	Workers              int               `yaml:"workers"`
	QueueCapacity        int               `yaml:"queue_capacity"`
}

type ListenerConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
}

type TLSListenerConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ClientCA   string `yaml:"client_ca"`
	RequireClientCert bool `yaml:"require_client_cert"`
}

type ClickHouseConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Database     string        `yaml:"database"`
	Username     string        `yaml:"username"`
	Password     string        `yaml:"password"`
	BatchSize    int           `yaml:"batch_size"`
	FlushTimeout time.Duration `yaml:"flush_timeout"`
	MaxRetries   int           `yaml:"max_retries"`
}

type PostgresConfig struct {
	Host            string        `yaml:"host"`
	Port            int           `yaml:"port"`
	Database        string        `yaml:"database"`
	Username        string        `yaml:"username"`
	Password        string        `yaml:"password"`
	SSLMode         string        `yaml:"ssl_mode"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

type ArchiveConfig struct {
	Enabled         bool          `yaml:"enabled"`
	StoragePath     string        `yaml:"storage_path"`
	Interval        string        `yaml:"interval"` // hourly, daily
	ScheduleMinutes int           `yaml:"schedule_minutes"`
	HashAlgorithm   string        `yaml:"hash_algorithm"` // SHA-256
}

type TimestampConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Provider      string        `yaml:"provider"` // kamusm, mock
	JavaBinary    string        `yaml:"java_binary"`
	JarPath       string        `yaml:"jar_path"`
	ServerURL     string        `yaml:"server_url"` // http://zd.kamusm.gov.tr or http://tzd.kamusm.gov.tr
	ServerPort    int           `yaml:"server_port"`
	CustomerNo    string        `yaml:"customer_no"`
	CustomerPass  string        `yaml:"customer_password"`
	DigestType    string        `yaml:"digest_type"` // sha-256
	ProxyIP       string        `yaml:"proxy_ip"`
	ProxyPort     int           `yaml:"proxy_port"`
	ProxyUser     string        `yaml:"proxy_user"`
	ProxyPass     string        `yaml:"proxy_pass"`
	RetryInterval time.Duration `yaml:"retry_interval"`
	MaxRetries    int           `yaml:"max_retries"`
	Timeout       time.Duration `yaml:"timeout"`
}

type SpoolConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Directory    string `yaml:"directory"`
	MaxDiskMB    int64  `yaml:"max_disk_mb"`
	BatchFlushMB int    `yaml:"batch_flush_mb"`
}

type SecurityConfig struct {
	JWTSecret       string        `yaml:"jwt_secret"`
	SessionDuration time.Duration `yaml:"session_duration"`
	AdminUsername   string        `yaml:"admin_username"`
	AdminPassword   string        `yaml:"admin_password"`
	Argon2Memory    uint32        `yaml:"argon2_memory"`
	Argon2Iterations uint32       `yaml:"argon2_iterations"`
}

// DefaultConfig returns sane enterprise defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:    "0.0.0.0:8080",
			ReadTimeout:   60 * time.Second,
			WriteTimeout:  0, // 0 allows long-running SSE streams, WebSocket, and large log archive downloads
			CollectorNode: "node-01",
		},
		Syslog: SyslogConfig{
			AcceptUnknownSources: true,
			UDP: ListenerConfig{
				Enabled:    true,
				ListenAddr: "0.0.0.0:514,0.0.0.0:5514",
			},
			TCP: ListenerConfig{
				Enabled:    true,
				ListenAddr: "0.0.0.0:514,0.0.0.0:5514",
			},
			TLS: TLSListenerConfig{
				Enabled:    false,
				ListenAddr: "0.0.0.0:6514",
			},
			Workers:       32,
			QueueCapacity: 500000,
		},
		ClickHouse: ClickHouseConfig{
			Host:         "127.0.0.1",
			Port:         9000,
			Database:     "syslog",
			Username:     "default",
			Password:     "",
			BatchSize:    10000,
			FlushTimeout: 500 * time.Millisecond,
			MaxRetries:   5,
		},
		Postgres: PostgresConfig{
			Host:            "127.0.0.1",
			Port:            5432,
			Database:        "syslog_manager",
			Username:        "syslog_admin",
			Password:        "syslog_secret",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 15 * time.Minute,
		},
		Archive: ArchiveConfig{
			Enabled:         true,
			StoragePath:     "/opt/syslog-platform/archive",
			Interval:        "hourly",
			ScheduleMinutes: 5,
			HashAlgorithm:   "SHA-256",
		},
		Timestamp: TimestampConfig{
			Enabled:       true,
			Provider:      "mock", // default to mock until KamuSM JAR provided
			JavaBinary:    "/usr/bin/java",
			JarPath:       "/opt/syslog-platform/timestamp-client/tss-client-console-3.1.33.jar",
			ServerURL:     "http://tzd.kamusm.gov.tr",
			ServerPort:    80,
			CustomerNo:    "",
			CustomerPass:  "",
			DigestType:    "sha-256",
			RetryInterval: 10 * time.Minute,
			MaxRetries:    5,
			Timeout:       60 * time.Second,
		},
		Spool: SpoolConfig{
			Enabled:      true,
			Directory:    "/opt/syslog-platform/data/spool",
			MaxDiskMB:    20480, // 20GB disk limit
			BatchFlushMB: 64,
		},
		Security: SecurityConfig{
			JWTSecret:       "generate-a-secure-random-token-change-in-prod",
			SessionDuration: 24 * time.Hour,
			AdminUsername:   "admin",
			AdminPassword:   "Admin123456!",
			Argon2Memory:    64 * 1024,
			Argon2Iterations: 3,
		},
	}
}

// LoadConfig reads config file and applies environment variable overrides
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("reading config file: %w", err)
			}
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parsing yaml config: %w", err)
			}
		}
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("SERVER_LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	}
	if v := os.Getenv("COLLECTOR_NODE"); v != "" {
		cfg.Server.CollectorNode = v
	}
	if v := os.Getenv("SYSLOG_UDP_LISTEN_ADDR"); v != "" {
		cfg.Syslog.UDP.ListenAddr = v
	}
	if v := os.Getenv("SYSLOG_TCP_LISTEN_ADDR"); v != "" {
		cfg.Syslog.TCP.ListenAddr = v
	}

	if v := os.Getenv("CLICKHOUSE_HOST"); v != "" {
		cfg.ClickHouse.Host = v
	}
	if v := os.Getenv("CLICKHOUSE_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.ClickHouse.Port = p
		}
	}
	if v := os.Getenv("CLICKHOUSE_DATABASE"); v != "" {
		cfg.ClickHouse.Database = v
	}
	if v := os.Getenv("CLICKHOUSE_USER"); v != "" {
		cfg.ClickHouse.Username = v
	}
	if v := os.Getenv("CLICKHOUSE_PASSWORD"); v != "" {
		cfg.ClickHouse.Password = v
	}

	if v := os.Getenv("POSTGRES_HOST"); v != "" {
		cfg.Postgres.Host = v
	}
	if v := os.Getenv("POSTGRES_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Postgres.Port = p
		}
	}
	if v := os.Getenv("POSTGRES_DB"); v != "" {
		cfg.Postgres.Database = v
	}
	if v := os.Getenv("POSTGRES_USER"); v != "" {
		cfg.Postgres.Username = v
	}
	if v := os.Getenv("POSTGRES_PASSWORD"); v != "" {
		cfg.Postgres.Password = v
	}
	if v := os.Getenv("POSTGRES_SSLMODE"); v != "" {
		cfg.Postgres.SSLMode = v
	}

	if v := os.Getenv("ARCHIVE_PATH"); v != "" {
		cfg.Archive.StoragePath = v
	}
	if v := os.Getenv("TIMESTAMP_PROVIDER"); v != "" {
		cfg.Timestamp.Provider = v
	}
	if v := os.Getenv("TIMESTAMP_CLIENT_JAR"); v != "" {
		cfg.Timestamp.JarPath = v
	}
	if v := os.Getenv("JAVA_BINARY"); v != "" {
		cfg.Timestamp.JavaBinary = v
	}
	if v := os.Getenv("KAMUSM_SERVER_URL"); v != "" {
		cfg.Timestamp.ServerURL = v
	}
	if v := os.Getenv("KAMUSM_CUSTOMER_NO"); v != "" {
		cfg.Timestamp.CustomerNo = v
	}
	if v := os.Getenv("KAMUSM_CUSTOMER_PASSWORD"); v != "" {
		cfg.Timestamp.CustomerPass = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.Security.JWTSecret = v
	}
}

// PostgresDSN returns the connection string for pgx or database/sql
func (c *PostgresConfig) PostgresDSN() string {
	parts := []string{
		fmt.Sprintf("host=%s", c.Host),
		fmt.Sprintf("port=%d", c.Port),
		fmt.Sprintf("user=%s", c.Username),
		fmt.Sprintf("password=%s", c.Password),
		fmt.Sprintf("dbname=%s", c.Database),
		fmt.Sprintf("sslmode=%s", c.SSLMode),
	}
	return strings.Join(parts, " ")
}
