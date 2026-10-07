# Valtrivo LogSeal — Upgrade & Maintenance Guide

This document describes how to update **Valtrivo LogSeal** to the latest version, both through the **Web Dashboard (Super Admin)** and via the **Command-Line Interface (CLI)** on Ubuntu VPS.

---

## 🚀 Quick CLI Upgrade (Recommended — 1 Command)

Valtrivo LogSeal includes an automated upgrade script ([upgrade.sh](upgrade.sh)) that pulls latest changes, applies new database schemas, rebuilds the container, and verifies health:

```bash
cd ~/Logger
sudo bash upgrade.sh
```

The script will:
1. Verify the Git repository and record the current version hash.
2. Stash any local uncommitted changes to avoid merge conflicts.
3. Fetch and pull latest commits from `origin/main`.
4. Apply any new PostgreSQL or ClickHouse migrations automatically.
5. Rebuild the `syslog-app` container (`docker compose build syslog-app`).
6. Restart the container without disturbing running databases (`docker compose up -d syslog-app`).
7. Verify the system healthcheck (`/api/v1/system/health`).

---

## 🖥️ Web UI Upgrade Menu (For Super Administrators)

If you are logged in as a **Super Administrator**, you can check and apply updates directly from the web browser:

1. Log into your Valtrivo LogSeal Web Dashboard (`http://<YOUR_VPS_IP>:8080`).
2. Navigate to **System Upgrade** (`🔄 Sistem Güncelleme`) on the left sidebar.
3. Click **🔍 Check for Updates**:
   * The platform queries the official GitHub repository (`https://api.github.com/repos/v-e-kandjani/Logger/commits/main`).
   * It displays the latest release commit, author, commit message, and whether your system is up to date or how many commits behind you are.
   * A table lists all modified and added files, showing which files are **Web Assets (Hot-patchable)** and which are **Go Engine (Requires Container Rebuild)**.
4. Click **🚀 Apply Upgrade (Changed Files)**:
   * The server pulls the updated templates, CSS, and JS files directly from GitHub.
   * If Go source code changed, you will be prompted to run `sudo bash upgrade.sh` or restart the container to compile backend changes.

---

## 🛠️ Manual Step-by-Step CLI Upgrade

If you prefer executing each upgrade command manually:

### Step 1: Navigate to Project Directory
```bash
cd ~/Logger
```

### Step 2: Pull Latest Commits from GitHub
```bash
# Check current commit
git log -1 --oneline

# Pull latest code
git pull origin main
```

> **Note on Local Changes:**
> If you modified `.env` or local files and `git pull` warns about untracked or modified files, run:
> ```bash
> git stash
> git pull origin main
> git stash pop
> ```

### Step 3: Apply Database Migrations (Idempotent)
If a release includes database schema updates:
```bash
# Apply PostgreSQL migrations (safe: uses IF NOT EXISTS)
docker compose exec -T postgres psql -U syslog_admin -d syslog_manager < migrations/postgres/001_initial_schema.sql

# Apply ClickHouse migrations (safe: uses IF NOT EXISTS)
docker compose exec -T clickhouse clickhouse-client --database syslog --multiquery < migrations/clickhouse/001_initial_events.sql
```

### Step 4: Rebuild and Restart Application
```bash
# Rebuild the syslog-app image with updated Go code and web assets
sudo docker compose build syslog-app

# Recreate and start the container
sudo docker compose up -d syslog-app
```

### Step 5: Verify Application Status
```bash
# Check container status
docker compose ps

# Check system health endpoint
curl -s http://127.0.0.1:8080/api/v1/system/health | jq
```

---

## ⏪ Rollback Procedure (Reverting to an Earlier Version)

If you ever need to rollback to a previous commit:

1. **Find the target commit hash:**
   ```bash
   git log --oneline -n 10
   ```
2. **Checkout the target commit:**
   ```bash
   git checkout <COMMIT_HASH>
   ```
3. **Rebuild and restart containers:**
   ```bash
   sudo docker compose build syslog-app && sudo docker compose up -d syslog-app
   ```
4. **Return to tracking main branch later:**
   ```bash
   git checkout main && git pull origin main
   ```

---

## ❓ Frequently Asked Questions (FAQ)

### 1. Does upgrading interrupt syslog log ingestion?
* Database services (`clickhouse` and `postgres`) remain online and are **not** stopped during `syslog-app` rebuilds.
* Recreating `syslog-app` takes approximately **2–3 seconds**, during which the OS UDP socket buffer queues incoming syslog packets.

### 2. Are historical logs or certificates affected?
* **No.** All ClickHouse logs, PostgreSQL databases, daily timestamped archive bundles (`.jsonl.gz.zd`), and configuration files are stored in persistent Docker volumes and host directories. They are untouched during upgrades.

### 3. What if `git pull` reports "Permission denied"?
Ensure the repository was cloned via HTTPS (`https://github.com/v-e-kandjani/Logger.git`) or that your user has read permissions.
