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

PREV_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
info "Current installed commit: ${PREV_COMMIT}"

# 2. Pull latest code from GitHub
info "Fetching and pulling latest code from origin/main..."
# Stash any local uncommitted files to prevent merge conflict
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
    read -rp "Force rebuild Docker container anyway? [y/N]: " force_rebuild
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

# 3. Apply any new SQL migrations (if containers are running)
if docker compose ps -q postgres &>/dev/null && [ "$(docker compose ps -q postgres)" != "" ]; then
    info "Verifying database migrations..."
    if [ -f "migrations/postgres/001_initial_schema.sql" ]; then
        docker compose exec -T postgres psql -U "$PG_USER" -d "$PG_DB" < migrations/postgres/001_initial_schema.sql >/dev/null 2>&1 || true
    fi
    if [ -f "migrations/clickhouse/001_initial_events.sql" ]; then
        docker compose exec -T clickhouse clickhouse-client --user "$CH_USER" --database "$CH_DB" --multiquery < migrations/clickhouse/001_initial_events.sql >/dev/null 2>&1 || true
    fi
    success "Database schemas verified."
fi

# 4. Rebuild syslog-app Docker image
info "Rebuilding syslog-app container..."
docker compose build syslog-app

# 5. Recreate and restart containers
info "Recreating syslog-app container..."
docker compose up -d syslog-app

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
    warn "Application took longer than expected to report healthy. Check logs: docker compose logs -f syslog-app"
fi

FINAL_COMMIT=$(git rev-parse --short HEAD)
SERVER_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1 || echo "127.0.0.1")

echo ""
cat << EOF
================================================================================
        VALTRIVO LOGSEAL - UPGRADE COMPLETED SUCCESSFULLY!
================================================================================
  Installed Version : ${FINAL_COMMIT} (Previous: ${PREV_COMMIT})
  Dashboard URL     : http://${SERVER_IP}:${APP_PORT}/
  Status            : All containers updated and healthy

  Useful Commands:
    - View live logs: docker compose logs -f syslog-app
    - Check health  : curl http://127.0.0.1:${APP_PORT}/api/v1/system/health
================================================================================
EOF
