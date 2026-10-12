#!/usr/bin/env bash
# ==============================================================================
# Valtrivo LogSeal - Standalone (Bare-Metal / No Docker) Linux Installer
# Supported OS: Ubuntu 20.04, 22.04, 24.04, 26.04 LTS & Debian 11/12
# Tagline: "Her kayıt, zamanıyla kanıt."
# ==============================================================================
# This script installs and configures:
#   1. Native PostgreSQL (systemd service)
#   2. Native ClickHouse Server (systemd service)
#   3. OpenJDK 17 JRE Headless (TÜBİTAK KamuSM 5651 timestamping engine)
#   4. Go toolchain (if not present) to compile static binary
#   5. Database schemas, migrations & initial administrator credentials
#   6. Valtrivo LogSeal systemd unit (syslog-platform.service)
#   7. UFW firewall shielding and local loopback database security
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
      STANDALONE BARE-METAL INSTALLER (NO DOCKER) - UBUNTU LTS / DEBIAN
                    "Her kayıt, zamanıyla kanıt."
================================================================================
EOF

# 1. Parse CLI Options
NON_INTERACTIVE=false
CLI_APP_PORT="8080"
CLI_ADMIN_PASS="admin5651!"
CLI_ADMIN_USER="admin"

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
        --admin-user)
            CLI_ADMIN_USER="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo bash install_standalone.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -y, --defaults, --non-interactive  Run without interactive prompts using defaults"
            echo "  --port <PORT>                      Web dashboard port (default: 8080)"
            echo "  --admin-user <USER>                Initial admin username (default: admin)"
            echo "  --admin-pass <PASSWORD>            Initial admin password (default: admin5651!)"
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
    fatal "This standalone installer must be executed as root (or with sudo). Run: sudo bash install_standalone.sh"
fi

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_NAME=${ID:-"unknown"}
    OS_VERSION_ID=${VERSION_ID:-"unknown"}
    info "Detected operating system: ${NAME:-$OS_NAME} (${OS_VERSION_ID})"
else
    OS_NAME="ubuntu"
    OS_VERSION_ID="unknown"
    warn "Cannot detect OS from /etc/os-release. Assuming Ubuntu/Debian compatible."
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="/opt/syslog-platform"
APP_PORT="$CLI_APP_PORT"
ADMIN_USER="$CLI_ADMIN_USER"
ADMIN_PASS="$CLI_ADMIN_PASS"
PG_DB="syslog_manager"
PG_USER="syslog_admin"
PG_PASS="syslog_secret"
CH_DB="syslog"
CH_USER="default"
CH_PASS=""

if [[ "$NON_INTERACTIVE" != "true" ]]; then
    echo ""
    echo -e "${BOLD}${BLUE}--- 1. Deployment Parameters ---${NC}"
    read -rp "Enter Port for Web UI / Dashboard [default: ${APP_PORT}]: " input_port
    APP_PORT="${input_port:-$APP_PORT}"

    read -rp "Enter Initial Administrator Username [default: ${ADMIN_USER}]: " input_user
    ADMIN_USER="${input_user:-$ADMIN_USER}"

    read -rp "Enter Initial Administrator Password [default: ${ADMIN_PASS}]: " input_pass
    ADMIN_PASS="${input_pass:-$ADMIN_PASS}"

    echo ""
    echo -e "${BOLD}Summary of configuration:${NC}"
    echo "  Install Directory    : ${INSTALL_DIR}"
    echo "  Web UI Port          : ${APP_PORT}"
    echo "  PostgreSQL DB / User : ${PG_DB} / ${PG_USER} (localhost:5432)"
    echo "  ClickHouse DB / User : ${CH_DB} / ${CH_USER} (localhost:9000)"
    echo "  Admin User           : ${ADMIN_USER}"
    echo "  Runtime Mode         : Native Systemd (Docker-free)"
    echo ""
    read -rp "Proceed with installation? [Y/n]: " confirm_install
    if [[ "$confirm_install" =~ ^[Nn] ]]; then
        info "Installation cancelled by user."
        exit 0
    fi
fi

# 3. System Packages & Base Dependencies
echo ""
echo -e "${BOLD}${BLUE}--- 2. Installing Core System Packages & OpenJDK 17 ---${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    gnupg \
    lsb-release \
    apt-transport-https \
    ufw \
    jq \
    openssl \
    git \
    tzdata \
    build-essential \
    openjdk-17-jre-headless

# 4. Native PostgreSQL Installation & Setup
echo ""
echo -e "${BOLD}${BLUE}--- 3. Setting Up Native PostgreSQL ---${NC}"
apt-get install -y postgresql postgresql-contrib
systemctl enable --now postgresql

info "Configuring PostgreSQL user '${PG_USER}' and database '${PG_DB}'..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER ${PG_USER} WITH PASSWORD '${PG_PASS}';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE ${PG_DB} OWNER ${PG_USER};"

sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${PG_DB} TO ${PG_USER};"
sudo -u postgres psql -d "${PG_DB}" -c "GRANT ALL ON SCHEMA public TO ${PG_USER};" 2>/dev/null || true
success "Native PostgreSQL is running and provisioned."

# 5. Native ClickHouse Server Installation & Setup
echo ""
echo -e "${BOLD}${BLUE}--- 4. Setting Up Native ClickHouse Server ---${NC}"
if ! command -v clickhouse-server &> /dev/null; then
    info "Installing ClickHouse Server repository..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key 2>/dev/null | gpg --dearmor -o /etc/apt/keyrings/clickhouse.gpg 2>/dev/null || \
        curl -fsSL https://packages.clickhouse.com/deb/clickhouse.gpg | gpg --dearmor -o /etc/apt/keyrings/clickhouse.gpg

    echo "deb [signed-by=/etc/apt/keyrings/clickhouse.gpg] https://packages.clickhouse.com/deb stable main" | \
        tee /etc/apt/sources.list.d/clickhouse.list > /dev/null

    apt-get update -y || true
    # If official apt repo installs cleanly
    if apt-get install -y clickhouse-server clickhouse-client; then
        info "ClickHouse installed via apt."
    else
        warn "Apt install encountered repository issues for $OS_NAME $OS_VERSION_ID. Using official ClickHouse bootstrap script..."
        curl https://clickhouse.com/ | sh
        install -m 0755 clickhouse /usr/local/bin/clickhouse
        ln -sf /usr/local/bin/clickhouse /usr/bin/clickhouse-server
        ln -sf /usr/local/bin/clickhouse /usr/bin/clickhouse-client
        clickhouse install --user clickhouse || true
    fi
else
    info "ClickHouse Server is already installed."
fi

# Ensure ClickHouse listens locally
mkdir -p /etc/clickhouse-server/config.d
cat << 'CH_CFG' > /etc/clickhouse-server/config.d/listen_local.xml
<clickhouse>
    <listen_host>127.0.0.1</listen_host>
    <listen_host>::1</listen_host>
</clickhouse>
CH_CFG

systemctl enable --now clickhouse-server || service clickhouse-server start
sleep 2

# Verify ClickHouse connectivity
CH_RETRIES=20
until clickhouse-client --query "SELECT 1" &>/dev/null || [ $CH_RETRIES -eq 0 ]; do
    sleep 1
    CH_RETRIES=$((CH_RETRIES - 1))
done

if [ $CH_RETRIES -eq 0 ]; then
    fatal "ClickHouse Server failed to start. Check: journalctl -u clickhouse-server -e"
fi
success "Native ClickHouse Server is running and healthy."

# 6. Apply Database Migrations & Schemas
echo ""
echo -e "${BOLD}${BLUE}--- 5. Applying Database Schemas & Initial Migrations ---${NC}"

# A) PostgreSQL
info "Applying PostgreSQL migrations..."
PGPASSWORD="${PG_PASS}" psql -h 127.0.0.1 -U "${PG_USER}" -d "${PG_DB}" -f migrations/postgres/001_initial_schema.sql >/dev/null
if [[ -f migrations/postgres/002_siem_tables.sql ]]; then
    PGPASSWORD="${PG_PASS}" psql -h 127.0.0.1 -U "${PG_USER}" -d "${PG_DB}" -f migrations/postgres/002_siem_tables.sql >/dev/null
fi

# Seed initial Super Administrator
info "Seeding Super Administrator account (${ADMIN_USER})..."
PGPASSWORD="${PG_PASS}" psql -h 127.0.0.1 -U "${PG_USER}" -d "${PG_DB}" << SQL >/dev/null
INSERT INTO users (username, password_hash, full_name, email, role, is_enabled)
VALUES ('${ADMIN_USER}', crypt('${ADMIN_PASS}', gen_salt('bf', 10)), 'Security Administrator', '${ADMIN_USER}@syslog.local', 'Super Administrator', true)
ON CONFLICT (username) DO UPDATE SET password_hash = crypt('${ADMIN_PASS}', gen_salt('bf', 10));
SQL
success "PostgreSQL schemas and admin credentials configured."

# B) ClickHouse
info "Applying ClickHouse migrations..."
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS ${CH_DB};"
clickhouse-client --multiquery < migrations/clickhouse/001_initial_events.sql >/dev/null
success "ClickHouse events table and materialized views initialized."

# 7. Compile & Install Application Binaries
echo ""
echo -e "${BOLD}${BLUE}--- 6. Building & Installing Valtrivo LogSeal Daemon ---${NC}"

# Install Go if not present
if ! command -v go &> /dev/null; then
    info "Go compiler not found. Installing Go..."
    apt-get install -y golang-go || {
        ARCH=$(uname -m)
        GOARCH="amd64"
        if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then GOARCH="arm64"; fi
        GO_TAR="go1.22.8.linux-${GOARCH}.tar.gz"
        curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
        tar -C /usr/local -xzf "/tmp/${GO_TAR}"
        export PATH="/usr/local/go/bin:$PATH"
        ln -sf /usr/local/go/bin/go /usr/bin/go
    }
fi

# Determine version metadata
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "00fe77a")
CURRENT_VER=$(grep -E 'Version\s*=\s*' internal/version/version.go 2>/dev/null | cut -d'"' -f2 || echo "v1.7.6")
BUILD_DATE=$(date +%Y-%m-%d)

# Create directory structure
mkdir -p "${INSTALL_DIR}/bin" \
         "${INSTALL_DIR}/config" \
         "${INSTALL_DIR}/web/templates" \
         "${INSTALL_DIR}/web/static" \
         "${INSTALL_DIR}/archive" \
         "${INSTALL_DIR}/data/spool" \
         "${INSTALL_DIR}/timestamp-client" \
         "${INSTALL_DIR}/scripts" \
         "${INSTALL_DIR}/migrations" \
         "${INSTALL_DIR}/cmd" \
         "${INSTALL_DIR}/internal" \
         "${INSTALL_DIR}/docs"

info "Compiling static Linux binaries with version metadata (${CURRENT_VER} - ${COMMIT_SHA})..."
CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/syslog-platform/logger/internal/version.CommitSHA=${COMMIT_SHA} -X github.com/syslog-platform/logger/internal/version.Version=${CURRENT_VER} -X github.com/syslog-platform/logger/internal/version.BuildDate=${BUILD_DATE}" \
    -o "${INSTALL_DIR}/bin/syslog-platform" ./cmd/server/main.go

CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${INSTALL_DIR}/bin/logseal-proxy" ./cmd/proxy/main.go
chmod +x "${INSTALL_DIR}/bin/syslog-platform" "${INSTALL_DIR}/bin/logseal-proxy"

# Write version metadata for dynamic runtime inspection
cat << EOF > "${INSTALL_DIR}/config/.version_info"
COMMIT_SHA=${COMMIT_SHA}
VERSION=${CURRENT_VER}
BUILD_DATE=${BUILD_DATE}
UPDATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
UPDATED_BY=install_standalone
EOF
mkdir -p config
cp "${INSTALL_DIR}/config/.version_info" config/.version_info 2>/dev/null || true

# Copy assets and source files for in-place updates
cp -r web/templates/* "${INSTALL_DIR}/web/templates/"
cp -r web/static/* "${INSTALL_DIR}/web/static/"
cp -r scripts/* "${INSTALL_DIR}/scripts/" 2>/dev/null || true
cp -r migrations/* "${INSTALL_DIR}/migrations/" 2>/dev/null || true
cp -r cmd/* "${INSTALL_DIR}/cmd/" 2>/dev/null || true
cp -r internal/* "${INSTALL_DIR}/internal/" 2>/dev/null || true
cp -r docs/* "${INSTALL_DIR}/docs/" 2>/dev/null || true
cp go.mod go.sum "${INSTALL_DIR}/" 2>/dev/null || true

# Copy timestamping client jar if available
if [[ -f timestamp-client/tss-client-console-3.1.33.jar ]]; then
    cp timestamp-client/tss-client-console-3.1.33.jar "${INSTALL_DIR}/timestamp-client/"
fi

# Write production config.yaml
cat << EOF > "${INSTALL_DIR}/config/config.yaml"
server:
  listen_addr: "0.0.0.0:${APP_PORT}"
  read_timeout: 60s
  write_timeout: 0s
  collector_node: "node-01"

syslog:
  accept_unknown_sources: true
  seed_demo_devices: false
  udp:
    enabled: true
    listen_addr: "0.0.0.0:514,0.0.0.0:5514"
  tcp:
    enabled: true
    listen_addr: "0.0.0.0:514,0.0.0.0:5514"
  tls:
    enabled: false
    listen_addr: "0.0.0.0:6514"
  workers: 16
  queue_capacity: 250000

clickhouse:
  host: "127.0.0.1"
  port: 9000
  database: "${CH_DB}"
  username: "${CH_USER}"
  password: "${CH_PASS}"
  batch_size: 1000
  flush_timeout: 500ms
  max_retries: 5

postgres:
  host: "127.0.0.1"
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
  storage_path: "${INSTALL_DIR}/archive"
  interval: "hourly"
  schedule_minutes: 5
  hash_algorithm: "SHA-256"

timestamp:
  enabled: true
  provider: "mock"
  java_binary: "/usr/bin/java"
  jar_path: "${INSTALL_DIR}/timestamp-client/tss-client-console-3.1.33.jar"
  server_url: "http://tzd.kamusm.gov.tr"
  server_port: 80
  digest_type: "sha-256"
  timeout: 60s
EOF

success "Application layout and configuration created in ${INSTALL_DIR}."

# 8. Create Systemd Service Unit
echo ""
echo -e "${BOLD}${BLUE}--- 7. Registering Systemd Service Unit ---${NC}"

cat << EOF > /etc/systemd/system/syslog-platform.service
[Unit]
Description=Valtrivo LogSeal - Centralized Syslog & 5651 Timestamping Platform (Standalone)
After=network.target postgresql.service clickhouse-server.service
Wants=postgresql.service clickhouse-server.service

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/syslog-platform --config ${INSTALL_DIR}/config/config.yaml
Restart=always
RestartSec=5s
LimitNOFILE=262144

# Allow binding to privileged ports (<1024 like UDP/TCP 514) without running as full root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

Environment=GIN_MODE=release
Environment=ARCHIVE_PATH=${INSTALL_DIR}/archive

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now syslog-platform
sleep 2

if systemctl is-active --quiet syslog-platform; then
    success "syslog-platform.service is running actively under systemd."
else
    error "syslog-platform.service failed to start. Showing logs:"
    journalctl -u syslog-platform -n 30 --no-pager
    exit 1
fi

# 9. Configure UFW Firewall
echo ""
echo -e "${BOLD}${BLUE}--- 8. Configuring Network & UFW Firewall ---${NC}"
ufw allow 22/tcp comment 'SSH' || true
ufw allow 514/udp comment 'Syslog Standard UDP' || true
ufw allow 514/tcp comment 'Syslog Standard TCP' || true
ufw allow 5514/udp comment 'Syslog Alt UDP' || true
ufw allow 5514/tcp comment 'Syslog Alt TCP' || true
ufw allow 6514/tcp comment 'Syslog TLS' || true
ufw allow "${APP_PORT}/tcp" comment 'Valtrivo LogSeal Web' || true
ufw allow 8443/tcp comment 'Valtrivo LogSeal HTTPS' || true
ufw deny 5432/tcp comment 'Shield Postgres' || true
ufw deny 9000/tcp comment 'Shield ClickHouse Native' || true
ufw deny 8123/tcp comment 'Shield ClickHouse HTTP' || true
ufw --force enable || true
success "Firewall rules applied."

# 10. Installation Summary
IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "SERVER_IP")

echo ""
echo -e "${GREEN}${BOLD}================================================================================${NC}"
echo -e "${GREEN}${BOLD}    VALTRIVO LOGSEAL - STANDALONE INSTALLATION COMPLETED SUCCESSFULLY!         ${NC}"
echo -e "${GREEN}${BOLD}================================================================================${NC}"
echo ""
echo -e "  🌐 Web Dashboard     : ${CYAN}http://${IP_ADDR}:${APP_PORT}${NC}"
echo -e "  🔒 HTTPS Dashboard   : ${CYAN}https://${IP_ADDR}:8443${NC} (if TLS certificate configured)"
echo -e "  👤 Username          : ${BOLD}${ADMIN_USER}${NC}"
echo -e "  🔑 Password          : ${BOLD}${ADMIN_PASS}${NC}"
echo ""
echo -e "  📥 Syslog Receivers  : UDP 514 / 5514, TCP 514 / 5514, TLS 6514"
echo -e "  📁 Service Path      : ${INSTALL_DIR}"
echo -e "  ⚙️  Config File       : ${INSTALL_DIR}/config/config.yaml"
echo ""
echo -e "  🔧 Service Commands  :"
echo -e "     Status            : ${BOLD}systemctl status syslog-platform${NC}"
echo -e "     Restart           : ${BOLD}systemctl restart syslog-platform${NC}"
echo -e "     Live Logs         : ${BOLD}journalctl -u syslog-platform -f${NC}"
echo ""
echo -e "${GREEN}${BOLD}================================================================================${NC}"
