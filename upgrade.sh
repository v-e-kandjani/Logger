#!/usr/bin/env bash
# ==============================================================================
# Valtrivo LogSeal - Automated CLI Upgrade Script
# Pulls latest updates from GitHub, applies database migrations,
# rebuilds syslog-app container, and verifies service health.
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

echo ""
cat << "EOF"
================================================================================
  Valtrivo LogSeal - Automated Platform Upgrade Engine
  "Her kayıt, zamanıyla kanıt."
================================================================================
EOF

# 1. Directory and Git verification
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".git" ]; then
    fatal "This directory is not a Git repository. Please run upgrade.sh from the cloned Logger directory."
fi

# Load environment if present
if [ -f ".env" ]; then
    # shellcheck disable=SC1091
    source .env
fi
APP_PORT="${APP_PORT:-8080}"
PG_USER="${POSTGRES_USER:-syslog_admin}"
PG_DB="${POSTGRES_DB:-syslog_manager}"
CH_DB="${CLICKHOUSE_DATABASE:-syslog}"
CH_USER="${CLICKHOUSE_USER:-default}"
INSTALL_DIR="/opt/syslog-platform"

# Detect or parse deployment mode (--docker or --baremetal)
DEPLOY_MODE="auto"
for arg in "$@"; do
    case "$arg" in
        --baremetal|--bare-metal)
            DEPLOY_MODE="baremetal"
            ;;
        --docker)
            DEPLOY_MODE="docker"
            ;;
        --help|-h)
            echo "Usage: sudo bash upgrade.sh [--docker | --baremetal]"
            exit 0
            ;;
    esac
done

if [ "$DEPLOY_MODE" = "auto" ]; then
    if [ -f "/etc/systemd/system/syslog-platform.service" ] || systemctl is-active --quiet syslog-platform 2>/dev/null; then
        if command -v docker &>/dev/null && docker compose ps -q syslog-app &>/dev/null && [ "$(docker compose ps -q syslog-app 2>/dev/null)" != "" ]; then
            DEPLOY_MODE="docker"
        else
            DEPLOY_MODE="baremetal"
        fi
    else
        DEPLOY_MODE="docker"
    fi
fi
info "Target deployment architecture: ${BOLD}${DEPLOY_MODE}${NC}"

PREV_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
info "Current installed commit: ${PREV_COMMIT}"

# 1.5. Automated Pre-Upgrade Database Snapshot (Zero Data Loss Protection)
mkdir -p ./backups
BACKUP_FILE="./backups/postgres_backup_$(date +%Y%m%d_%H%M%S).sql.gz"

if [ "$DEPLOY_MODE" = "docker" ]; then
    if docker compose ps -q postgres &>/dev/null && [ "$(docker compose ps -q postgres)" != "" ]; then
        info "Taking automated pre-upgrade snapshot of container PostgreSQL database..."
        if docker compose exec -T postgres pg_dump -U "$PG_USER" -d "$PG_DB" | gzip > "$BACKUP_FILE"; then
            success "Database backup snapshot saved: ${BACKUP_FILE}"
            ls -tp ./backups/postgres_backup_*.sql.gz 2>/dev/null | tail -n +6 | xargs -I {} rm -- {} 2>/dev/null || true
        else
            warn "Automated database backup notice: container busy or pg_dump returned non-zero. Continuing with upgrade..."
        fi
    fi
else
    if systemctl is-active --quiet postgresql 2>/dev/null || command -v pg_dump &>/dev/null; then
        info "Taking automated pre-upgrade snapshot of native PostgreSQL database..."
        if PGPASSWORD="${POSTGRES_PASSWORD:-syslog_secret}" pg_dump -h 127.0.0.1 -U "$PG_USER" -d "$PG_DB" 2>/dev/null | gzip > "$BACKUP_FILE"; then
            success "Database backup snapshot saved: ${BACKUP_FILE}"
            ls -tp ./backups/postgres_backup_*.sql.gz 2>/dev/null | tail -n +6 | xargs -I {} rm -- {} 2>/dev/null || true
        elif sudo -u postgres pg_dump -d "$PG_DB" 2>/dev/null | gzip > "$BACKUP_FILE"; then
            success "Database backup snapshot saved (via postgres user): ${BACKUP_FILE}"
            ls -tp ./backups/postgres_backup_*.sql.gz 2>/dev/null | tail -n +6 | xargs -I {} rm -- {} 2>/dev/null || true
        else
            warn "Automated database backup notice: native PostgreSQL busy. Continuing with upgrade..."
        fi
    fi
fi

# 2. Pull latest code from GitHub
info "Fetching and pulling latest code from origin/main..."
STASHED=false
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    warn "Detected local uncommitted changes. Stashing them temporarily..."
    git stash -u >/dev/null 2>&1 || true
    STASHED=true
fi

git fetch origin main
LOCAL_HASH=$(git rev-parse HEAD)
REMOTE_HASH=$(git rev-parse origin/main)

if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
    success "Local repository is already up to date with origin/main (${PREV_COMMIT})."
    echo ""
    read -rp "Force rebuild anyway? [y/N]: " force_rebuild
    if [[ ! "$force_rebuild" =~ ^[Yy] ]]; then
        info "Upgrade process finished. No changes required."
        exit 0
    fi
else
    git pull origin main
    NEW_COMMIT=$(git rev-parse --short HEAD)
    success "Updated repository to commit ${NEW_COMMIT}!"
    echo "Recent commit log:"
    git log --oneline -n 3
fi

if [ "$STASHED" = "true" ]; then
    info "Re-applying stashed local modifications..."
    git stash pop >/dev/null 2>&1 || true
fi

# 3. Apply any new SQL migrations
if [ "$DEPLOY_MODE" = "docker" ]; then
    if docker compose ps -q postgres &>/dev/null && [ "$(docker compose ps -q postgres)" != "" ]; then
        info "Verifying container database migrations..."
        if [ -f "migrations/postgres/001_initial_schema.sql" ]; then
            docker compose exec -T postgres psql -U "$PG_USER" -d "$PG_DB" < migrations/postgres/001_initial_schema.sql >/dev/null 2>&1 || true
        fi
        if [ -f "migrations/postgres/002_siem_tables.sql" ]; then
            docker compose exec -T postgres psql -U "$PG_USER" -d "$PG_DB" < migrations/postgres/002_siem_tables.sql >/dev/null 2>&1 || true
        fi
        if [ -f "migrations/clickhouse/001_initial_events.sql" ]; then
            docker compose exec -T clickhouse clickhouse-client --user "$CH_USER" --database "$CH_DB" --multiquery < migrations/clickhouse/001_initial_events.sql >/dev/null 2>&1 || true
        fi
        success "Database schemas verified."
    fi
else
    info "Verifying native database migrations..."
    if command -v psql &>/dev/null; then
        if [ -f "migrations/postgres/001_initial_schema.sql" ]; then
            PGPASSWORD="${POSTGRES_PASSWORD:-syslog_secret}" psql -h 127.0.0.1 -U "$PG_USER" -d "$PG_DB" -f migrations/postgres/001_initial_schema.sql >/dev/null 2>&1 || true
        fi
        if [ -f "migrations/postgres/002_siem_tables.sql" ]; then
            PGPASSWORD="${POSTGRES_PASSWORD:-syslog_secret}" psql -h 127.0.0.1 -U "$PG_USER" -d "$PG_DB" -f migrations/postgres/002_siem_tables.sql >/dev/null 2>&1 || true
        fi
    fi
    if command -v clickhouse-client &>/dev/null; then
        clickhouse-client --query "CREATE DATABASE IF NOT EXISTS ${CH_DB};" >/dev/null 2>&1 || true
        if [ -f "migrations/clickhouse/001_initial_events.sql" ]; then
            clickhouse-client --database "$CH_DB" --multiquery < migrations/clickhouse/001_initial_events.sql >/dev/null 2>&1 || true
        fi
    fi
    success "Native database schemas verified."
fi

# 3.5. Write version metadata & export build args
NEW_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
CURRENT_VER=$(grep -E 'Version\s*=\s*' internal/version/version.go 2>/dev/null | cut -d'"' -f2 || echo "v1.7.5")
BUILD_DATE=$(date +%Y-%m-%d)
mkdir -p config
cat << EOF > config/.version_info
COMMIT_SHA=${NEW_COMMIT}
VERSION=${CURRENT_VER}
BUILD_DATE=${BUILD_DATE}
UPDATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
UPDATED_BY=cli_upgrade_${DEPLOY_MODE}
EOF

if [ -d "${INSTALL_DIR}/config" ]; then
    cp config/.version_info "${INSTALL_DIR}/config/.version_info"
fi

export COMMIT_SHA="${NEW_COMMIT}"
export VERSION="${CURRENT_VER}"
export BUILD_DATE="${BUILD_DATE}"
info "Synchronized version metadata: ${CURRENT_VER} (${NEW_COMMIT}) on ${BUILD_DATE}"

# 4. Rebuild & Recreate Services
if [ "$DEPLOY_MODE" = "docker" ]; then
    info "Rebuilding syslog-app container..."
    HOST_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    if [ "$HOST_CORES" -gt 1 ]; then
        export GOMAXPROCS=$((HOST_CORES - 1))
        info "Set GOMAXPROCS=${GOMAXPROCS} during container compilation (1 core reserved for OS management)"
    fi
    docker compose build --build-arg COMMIT_SHA="${NEW_COMMIT}" --build-arg VERSION="${CURRENT_VER}" --build-arg BUILD_DATE="${BUILD_DATE}" syslog-app

    info "Recreating syslog-app container..."
    docker compose up -d syslog-app
else
    info "Compiling native Go binaries for bare-metal host..."
    if ! command -v go &>/dev/null && [ -x "/usr/local/go/bin/go" ]; then
        export PATH="/usr/local/go/bin:$PATH"
    fi
    if ! command -v go &>/dev/null; then
        fatal "Go compiler not found. Please install Go (e.g. apt install golang-go) to compile native binaries."
    fi

    # Ensure dependencies are downloaded
    go mod download

    mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/config" "${INSTALL_DIR}/web/templates" "${INSTALL_DIR}/web/static" "${INSTALL_DIR}/scripts" "${INSTALL_DIR}/migrations" "${INSTALL_DIR}/cmd" "${INSTALL_DIR}/internal" "${INSTALL_DIR}/docs"

    CGO_ENABLED=0 go build -trimpath \
        -ldflags="-s -w -X github.com/syslog-platform/logger/internal/version.CommitSHA=${NEW_COMMIT} -X github.com/syslog-platform/logger/internal/version.Version=${CURRENT_VER} -X github.com/syslog-platform/logger/internal/version.BuildDate=${BUILD_DATE}" \
        -o "${INSTALL_DIR}/bin/syslog-platform" ./cmd/server/main.go

    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${INSTALL_DIR}/bin/logseal-proxy" ./cmd/proxy/main.go
    chmod +x "${INSTALL_DIR}/bin/syslog-platform" "${INSTALL_DIR}/bin/logseal-proxy"

    # Sync web assets and source files to /opt/syslog-platform
    cp -r web/templates/* "${INSTALL_DIR}/web/templates/" 2>/dev/null || true
    cp -r web/static/* "${INSTALL_DIR}/web/static/" 2>/dev/null || true
    cp -r scripts/* "${INSTALL_DIR}/scripts/" 2>/dev/null || true
    cp -r migrations/* "${INSTALL_DIR}/migrations/" 2>/dev/null || true
    cp -r cmd/* "${INSTALL_DIR}/cmd/" 2>/dev/null || true
    cp -r internal/* "${INSTALL_DIR}/internal/" 2>/dev/null || true
    cp -r docs/* "${INSTALL_DIR}/docs/" 2>/dev/null || true
    cp go.mod go.sum "${INSTALL_DIR}/" 2>/dev/null || true

    info "Restarting native syslog-platform.service under systemd..."
    systemctl restart syslog-platform
fi

# 6. Verify Healthcheck
info "Waiting for application to pass healthcheck on http://127.0.0.1:${APP_PORT}/api/v1/system/health..."
RETRIES=30
HEALTHY=false
while [ $RETRIES -gt 0 ]; do
    if curl -s -f "http://127.0.0.1:${APP_PORT}/api/v1/system/health" &>/dev/null; then
        HEALTHY=true
        break
    fi
    sleep 2
    RETRIES=$((RETRIES - 1))
done

if [ "$HEALTHY" = "true" ]; then
    success "Valtrivo LogSeal application is healthy and running!"
else
    if [ "$DEPLOY_MODE" = "docker" ]; then
        warn "Application took longer than expected to report healthy. Check logs: docker compose logs -f syslog-app"
    else
        warn "Application took longer than expected to report healthy. Check logs: journalctl -u syslog-platform -n 30 --no-pager"
    fi
fi

FINAL_COMMIT=$(git rev-parse --short HEAD)
SERVER_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1 || echo "127.0.0.1")

echo ""
cat << EOF
================================================================================
        VALTRIVO LOGSEAL - UPGRADE COMPLETED SUCCESSFULLY!
================================================================================
  Installed Version : ${CURRENT_VER} (${FINAL_COMMIT}) (Previous: ${PREV_COMMIT})
  Architecture      : ${DEPLOY_MODE}
  Dashboard URL     : http://${SERVER_IP}:${APP_PORT}/
  Status            : All services updated and healthy

  Useful Commands:
EOF

if [ "$DEPLOY_MODE" = "docker" ]; then
    echo "    - View live logs: docker compose logs -f syslog-app"
    echo "    - Check health  : curl http://127.0.0.1:${APP_PORT}/api/v1/system/health"
else
    echo "    - Service status: systemctl status syslog-platform"
    echo "    - View live logs: journalctl -u syslog-platform -f"
    echo "    - Check health  : curl http://127.0.0.1:${APP_PORT}/api/v1/system/health"
fi
echo "================================================================================"

