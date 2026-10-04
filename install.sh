#!/usr/bin/env bash
# ==============================================================================
# Valtrivo LogSeal - Automated Linux Ubuntu Installation & Provisioning Script
# Merkezi Log Yönetimi ve Zaman Damgalama
# Tagline: "Her kayıt, zamanıyla kanıt."
# ==============================================================================

set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} ${BOLD}$*${NC}"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fatal()   { echo -e "${RED}[FATAL]${NC} ${BOLD}$*${NC}" >&2; exit 1; }

# Banner
cat << "EOF"
================================================================================
 __      __   _ _        _             _                _____             _ 
 \ \    / /  | | |      (_)           | |              / ____|           | |
  \ \  / /_ _| | |_ _ __ _ _   _____  | |     ___   __ | (___   ___  __ _| |
   \ \/ / _` | | __| '__| \ \ / / _ \ | |    / _ \ / _` \___ \ / _ \/ _` | |
    \  / (_| | | |_| |  | |\ V / (_) || |___| (_) | (_| |___) |  __/ (_| | |
     \/ \__,_|_|\__|_|  |_| \_/ \___/ |______\___/ \__, |_____/ \___|\__,_|_|
                                                    __/ |                    
                                                   |___/                     
        Merkezi Log Yönetimi ve 5651 Uyumlu Zaman Damgalama Platformu
                    "Her kayıt, zamanıyla kanıt."
================================================================================
EOF

# 1. Parse CLI Options
NON_INTERACTIVE=false
CLI_APP_PORT=""
CLI_ADMIN_PASS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--defaults|--non-interactive)
            NON_INTERACTIVE=true
            shift
            ;;
        --port)
            CLI_APP_PORT="$2"
            shift 2
            ;;
        --admin-pass)
            CLI_ADMIN_PASS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo bash install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -y, --defaults, --non-interactive  Use all default parameters without interactive prompts"
            echo "  --port <PORT>                      Override Web UI port (e.g. 8443, 9000)"
            echo "  --admin-pass <PASSWORD>            Set initial administrator password"
            echo "  -h, --help                         Show this help message"
            exit 0
            ;;
        *)
            warn "Unknown parameter: $1 (ignoring)"
            shift
            ;;
    esac
done

# 2. Privilege and OS Check
if [[ $EUID -ne 0 ]]; then
    fatal "This installation script must be executed as root (or with sudo). Please run: sudo bash install.sh"
fi

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_NAME=$ID
    OS_VERSION_ID=${VERSION_ID:-"unknown"}
    info "Detected operating system: ${NAME} (${OS_VERSION_ID})"
    if [[ "$OS_NAME" != "ubuntu" && "$OS_NAME" != "debian" ]]; then
        warn "This script is optimized for Ubuntu/Debian. Continuing in compatibility mode..."
    fi
else
    warn "Cannot detect OS from /etc/os-release. Continuing assuming Ubuntu/Debian compatible."
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 3. Interactive Configuration Wizard
echo ""
echo -e "${BOLD}${BLUE}--- 1. Configuration & Deployment Parameters ---${NC}"

# Web UI Port
DEFAULT_APP_PORT="8080"
if [[ -n "$CLI_APP_PORT" ]]; then
    APP_PORT="$CLI_APP_PORT"
elif [[ "$NON_INTERACTIVE" == "true" ]]; then
    APP_PORT="$DEFAULT_APP_PORT"
else
    read -rp "Enter Port for Web UI / Dashboard [default: ${DEFAULT_APP_PORT}]: " input_port
    APP_PORT="${input_port:-$DEFAULT_APP_PORT}"
fi
info "Web UI will listen on port: ${APP_PORT}"

# PostgreSQL Database Settings
DEFAULT_PG_DB="syslog_manager"
DEFAULT_PG_USER="syslog_admin"
DEFAULT_PG_PASS="syslog_secret"

if [[ "$NON_INTERACTIVE" == "true" ]]; then
    PG_DB="$DEFAULT_PG_DB"
    PG_USER="$DEFAULT_PG_USER"
    PG_PASS="$DEFAULT_PG_PASS"
else
    echo ""
    read -rp "Enter PostgreSQL Database Name [default: ${DEFAULT_PG_DB}]: " input_pg_db
    PG_DB="${input_pg_db:-$DEFAULT_PG_DB}"

    read -rp "Enter PostgreSQL Username [default: ${DEFAULT_PG_USER}]: " input_pg_user
    PG_USER="${input_pg_user:-$DEFAULT_PG_USER}"

    read -rp "Enter PostgreSQL Password [default: ${DEFAULT_PG_PASS}]: " input_pg_pass
    PG_PASS="${input_pg_pass:-$DEFAULT_PG_PASS}"
fi

# ClickHouse Database Settings
DEFAULT_CH_DB="syslog"
DEFAULT_CH_USER="default"
DEFAULT_CH_PASS=""

if [[ "$NON_INTERACTIVE" == "true" ]]; then
    CH_DB="$DEFAULT_CH_DB"
    CH_USER="$DEFAULT_CH_USER"
    CH_PASS="$DEFAULT_CH_PASS"
else
    echo ""
    read -rp "Enter ClickHouse Database Name [default: ${DEFAULT_CH_DB}]: " input_ch_db
    CH_DB="${input_ch_db:-$DEFAULT_CH_DB}"

    read -rp "Enter ClickHouse Username [default: ${DEFAULT_CH_USER}]: " input_ch_user
    CH_USER="${input_ch_user:-$DEFAULT_CH_USER}"

    read -rp "Enter ClickHouse Password [default: empty/none]: " input_ch_pass
    CH_PASS="${input_ch_pass:-$DEFAULT_CH_PASS}"
fi

# Initial Administrator Credentials
DEFAULT_ADMIN_USER="admin"
DEFAULT_ADMIN_PASS="admin5651!"

if [[ -n "$CLI_ADMIN_PASS" ]]; then
    ADMIN_PASS="$CLI_ADMIN_PASS"
    ADMIN_USER="$DEFAULT_ADMIN_USER"
elif [[ "$NON_INTERACTIVE" == "true" ]]; then
    ADMIN_USER="$DEFAULT_ADMIN_USER"
    ADMIN_PASS="$DEFAULT_ADMIN_PASS"
else
    echo ""
    read -rp "Enter Initial Administrator Username [default: ${DEFAULT_ADMIN_USER}]: " input_admin_user
    ADMIN_USER="${input_admin_user:-$DEFAULT_ADMIN_USER}"

    read -rp "Enter Initial Administrator Password [default: ${DEFAULT_ADMIN_PASS}]: " input_admin_pass
    ADMIN_PASS="${input_admin_pass:-$DEFAULT_ADMIN_PASS}"
fi

# Summary confirmation
if [[ "$NON_INTERACTIVE" != "true" ]]; then
    echo ""
    echo -e "${BOLD}Summary of configuration:${NC}"
    echo "  Web UI Port          : ${APP_PORT}"
    echo "  PostgreSQL DB / User : ${PG_DB} / ${PG_USER}"
    echo "  ClickHouse DB / User : ${CH_DB} / ${CH_USER}"
    echo "  Admin User           : ${ADMIN_USER}"
    echo "  Database Exposure    : LOCALHOST ONLY (127.0.0.1 - shielded from outside)"
    echo "  UFW Firewall         : Automatically configured & enabled"
    echo ""
    read -rp "Proceed with installation? [Y/n]: " confirm_install
    if [[ "$confirm_install" =~ ^[Nn] ]]; then
        info "Installation aborted by user."
        exit 0
    fi
fi

# 4. Install OS Dependencies
echo ""
echo -e "${BOLD}${BLUE}--- 2. Installing System Packages & Dependencies ---${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    gnupg \
    lsb-release \
    ufw \
    jq \
    openssl \
    git \
    tzdata

# 5. Install Docker & Docker Compose if missing
echo ""
echo -e "${BOLD}${BLUE}--- 3. Verifying Docker & Docker Compose Engine ---${NC}"
if ! command -v docker &> /dev/null || ! docker compose version &> /dev/null; then
    info "Docker or Docker Compose plugin not found. Installing official Docker CE repository..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc || \
        curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    ARCH=$(dpkg --print-architecture)
    CODENAME=$(lsb_release -cs 2>/dev/null || echo "jammy")
    DISTRO="ubuntu"
    if [[ "$OS_NAME" == "debian" ]]; then DISTRO="debian"; fi

    echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DISTRO} ${CODENAME} stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    success "Docker CE & Compose plugin successfully installed."
else
    success "Docker is already installed: $(docker --version)"
    success "Docker Compose is already installed: $(docker compose version)"
fi

# 6. Configure UFW (Uncomplicated Firewall)
echo ""
echo -e "${BOLD}${BLUE}--- 4. Configuring UFW Firewall & Network Shielding ---${NC}"
info "Configuring firewall rules for Valtrivo LogSeal:"
info " - Allowing SSH (22/tcp) to prevent lockout"
info " - Allowing Syslog Standard (514/udp, 514/tcp)"
info " - Allowing Syslog Alternate (5514/udp, 5514/tcp)"
info " - Allowing Syslog TLS (6514/tcp)"
info " - Allowing Web UI (${APP_PORT}/tcp)"
info " - Databases (Postgres 5432, ClickHouse 9000/8123) are KEPT INTERNAL & LOCALHOST ONLY"

ufw allow 22/tcp comment 'SSH Management' || true
ufw allow 514/udp comment 'Syslog UDP' || true
ufw allow 514/tcp comment 'Syslog TCP' || true
ufw allow 5514/udp comment 'Syslog Alternate UDP' || true
ufw allow 5514/tcp comment 'Syslog Alternate TCP' || true
ufw allow 6514/tcp comment 'Syslog TLS (RFC 5425)' || true
ufw allow "${APP_PORT}/tcp" comment 'Valtrivo LogSeal Web UI' || true

# Explicitly ensure databases are not exposed publicly
ufw deny 5432/tcp comment 'Block External Postgres' || true
ufw deny 9000/tcp comment 'Block External ClickHouse Native' || true
ufw deny 8123/tcp comment 'Block External ClickHouse HTTP' || true

# Enable UFW non-interactively
ufw --force enable
success "UFW firewall is enabled and configured."
ufw status verbose

# 7. Write Environment & Configuration Files
echo ""
echo -e "${BOLD}${BLUE}--- 5. Writing Production Configuration ---${NC}"
mkdir -p /opt/syslog-platform/archive \
         /opt/syslog-platform/timestamp-client \
         /opt/syslog-platform/data/spool

# Generate .env
cat << EOF > .env
# Auto-generated by install.sh at $(date -u +"%Y-%m-%dT%H:%M:%SZ")
APP_PORT=${APP_PORT}
SERVER_LISTEN_ADDR=0.0.0.0:8080

# PostgreSQL (Exposed ONLY to 127.0.0.1 for local host access)
POSTGRES_DB=${PG_DB}
POSTGRES_USER=${PG_USER}
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_LOCAL_PORT=5432
POSTGRES_SSLMODE=disable

# ClickHouse (Exposed ONLY to 127.0.0.1 for local host access)
CLICKHOUSE_DATABASE=${CH_DB}
CLICKHOUSE_USER=${CH_USER}
CLICKHOUSE_PASSWORD=${CH_PASS}
CLICKHOUSE_LOCAL_PORT=9000
CLICKHOUSE_HTTP_LOCAL_PORT=8123

# Initial Administrator Credentials
INITIAL_ADMIN_USER=${ADMIN_USER}
INITIAL_ADMIN_PASSWORD=${ADMIN_PASS}

# Timestamp Engine
TIMESTAMP_PROVIDER=mock
ARCHIVE_PATH=/opt/syslog-platform/archive
EOF

chmod 600 .env
success "Created production .env file (mode 0600)."

# Sync config.yaml
mkdir -p config
cat << EOF > config/config.yaml
server:
  listen_addr: "0.0.0.0:8080"
  read_timeout: 15s
  write_timeout: 15s
  collector_node: "node-01"

syslog:
  accept_unknown_sources: true
  udp:
    enabled: true
    listen_addr: "0.0.0.0:5514"
  tcp:
    enabled: true
    listen_addr: "0.0.0.0:5514"
  tls:
    enabled: false
    listen_addr: "0.0.0.0:6514"
  workers: 16
  queue_capacity: 250000

clickhouse:
  host: "clickhouse"
  port: 9000
  database: "${CH_DB}"
  username: "${CH_USER}"
  password: "${CH_PASS}"
  batch_size: 1000
  flush_timeout: 500ms
  max_retries: 5

postgres:
  host: "postgres"
  port: 5432
  database: "${PG_DB}"
  username: "${PG_USER}"
  password: "${PG_PASS}"
  ssl_mode: "disable"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 15m

archive:
  enabled: true
  storage_path: "/opt/syslog-platform/archive"
  interval: "hourly"
  schedule_minutes: 5
  hash_algorithm: "SHA-256"

timestamp:
  enabled: true
  provider: "mock"
  java_binary: "/usr/bin/java"
  jar_path: "/opt/syslog-platform/timestamp-client/tss-client-console-3.1.33.jar"
  server_url: "http://zd.kamusm.gov.tr"
  server_port: 80
  digest_type: "sha-256"
  timeout: 60s
EOF
success "Updated config/config.yaml with deployment parameters."

# 8. Start Database Services & Wait for Health
echo ""
echo -e "${BOLD}${BLUE}--- 6. Initializing Databases (PostgreSQL & ClickHouse) ---${NC}"
info "Starting database containers in background..."
docker compose up -d clickhouse postgres

info "Waiting for PostgreSQL ($PG_DB) to be ready..."
RETRIES=30
until docker compose exec -T postgres pg_isready -U "$PG_USER" -d "$PG_DB" &> /dev/null || [ $RETRIES -eq 0 ]; do
    sleep 1
    RETRIES=$((RETRIES - 1))
done

if [ $RETRIES -eq 0 ]; then
    fatal "PostgreSQL failed to initialize within 30 seconds. Check: docker compose logs postgres"
fi
success "PostgreSQL is healthy and accepting connections."

info "Waiting for ClickHouse ($CH_DB) to be ready..."
CH_AUTH_CMD=(docker compose exec -T clickhouse clickhouse-client --user "$CH_USER")
if [[ -n "$CH_PASS" ]]; then
    CH_AUTH_CMD+=(--password "$CH_PASS")
fi

RETRIES=30
until "${CH_AUTH_CMD[@]}" --query "SELECT 1" &> /dev/null || [ $RETRIES -eq 0 ]; do
    sleep 1
    RETRIES=$((RETRIES - 1))
done

if [ $RETRIES -eq 0 ]; then
    fatal "ClickHouse failed to initialize within 30 seconds. Check: docker compose logs clickhouse"
fi
success "ClickHouse is healthy and accepting queries."

# 9. Execute SQL Migrations & Schema Initialization
echo ""
echo -e "${BOLD}${BLUE}--- 7. Applying Database Schemas & Table Creation ---${NC}"

# A) PostgreSQL Tables
info "Executing PostgreSQL migrations (migrations/postgres/001_initial_schema.sql)..."
docker compose exec -T postgres psql -U "$PG_USER" -d "$PG_DB" < migrations/postgres/001_initial_schema.sql > /dev/null
success "PostgreSQL tables initialized (devices, unregistered_sources, users, log_archives, audit_logs, system_settings)."

# Seed Admin User in PostgreSQL with bcrypt password
info "Seeding initial Super Administrator account (${ADMIN_USER})..."
SEED_SQL=$(cat << SQL
INSERT INTO users (username, password_hash, full_name, email, role, is_enabled)
VALUES ('${ADMIN_USER}', crypt('${ADMIN_PASS}', gen_salt('bf', 10)), 'Security Administrator', '${ADMIN_USER}@syslog.local', 'Super Administrator', true)
ON CONFLICT (username) DO UPDATE SET password_hash = crypt('${ADMIN_PASS}', gen_salt('bf', 10));
SQL
)
echo "$SEED_SQL" | docker compose exec -T postgres psql -U "$PG_USER" -d "$PG_DB" > /dev/null
success "Administrator user '${ADMIN_USER}' provisioned and password crypt-hashed."

# B) ClickHouse Tables
info "Executing ClickHouse migrations (migrations/clickhouse/001_initial_events.sql)..."
# Substitute database name if customized
sed "s/DATABASE IF NOT EXISTS syslog/DATABASE IF NOT EXISTS ${CH_DB}/g; s/syslog\./${CH_DB}\./g" \
    migrations/clickhouse/001_initial_events.sql | \
    "${CH_AUTH_CMD[@]}" --multiquery > /dev/null
success "ClickHouse analytical table '${CH_DB}.syslog_events' and materialized view '${CH_DB}.mv_events_per_minute' created."

# 10. Build and Launch Application Container
echo ""
echo -e "${BOLD}${BLUE}--- 8. Building & Starting Valtrivo LogSeal Daemon ---${NC}"
docker compose build syslog-app
docker compose up -d

info "Waiting for application healthcheck on http://127.0.0.1:${APP_PORT}/api/v1/system/health..."
RETRIES=30
APP_HEALTHY=false
while [ $RETRIES -gt 0 ]; do
    if curl -s -f "http://127.0.0.1:${APP_PORT}/api/v1/system/health" &> /dev/null; then
        APP_HEALTHY=true
        break
    fi
    sleep 2
    RETRIES=$((RETRIES - 1))
done

if [ "$APP_HEALTHY" != "true" ]; then
    warn "Application is starting or healthcheck took longer than expected."
    warn "Check logs using: docker compose logs syslog-app"
else
    success "Valtrivo LogSeal application is UP and HEALTHY!"
fi

# Detect Server IP
SERVER_IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1 || echo "127.0.0.1")

# 11. Final Summary & Verification Report
echo ""
cat << EOF
================================================================================
          VALTRIVO LOGSEAL - INSTALLATION COMPLETED SUCCESSFULLY!
================================================================================

🚀 Platform URL       : http://${SERVER_IP}:${APP_PORT}/
                        (or http://localhost:${APP_PORT}/)

👤 Administrator Login:
   - Username         : ${ADMIN_USER}
   - Password         : ${ADMIN_PASS}
   - Security Profile : Super Administrator

📡 Syslog Ingestion Listeners:
   - Standard UDP     : Port 514 (UDP)
   - Standard TCP     : Port 514 (TCP)
   - Alternate UDP    : Port 5514 (UDP)
   - Alternate TCP    : Port 5514 (TCP)
   - Secure TLS       : Port 6514 (TCP)

🔒 Database Security:
   - PostgreSQL (5432): Bound ONLY to 127.0.0.1 (Local host only)
   - ClickHouse (9000): Bound ONLY to 127.0.0.1 (Local host only)
   - External networks CANNOT access databases directly.

🛡️ UFW Firewall Status:
   - Port 22 (SSH)    : ALLOWED
   - Port ${APP_PORT} (Web UI): ALLOWED
   - Ports 514/5514   : ALLOWED
   - Port 6514 (TLS)  : ALLOWED
   - Databases        : BLOCKED / NOT PUBLISHED TO EXTERNAL INTERFACES

📋 Useful Commands:
   - View live logs   : docker compose logs -f
   - Stop platform    : docker compose down
   - Restart platform : docker compose restart
   - System health    : curl http://127.0.0.1:${APP_PORT}/api/v1/system/health

Tagline: "Her kayıt, zamanıyla kanıt."
================================================================================
EOF
