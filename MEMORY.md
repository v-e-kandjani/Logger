# Valtrivo LogSeal — Project Memory & State Guide

> **Important**: This document serves as the project memory for Valtrivo LogSeal. At the beginning of each session, review this document to resume work without needing to re-scan the codebase.

---

## 1. Project Overview & Environments
- **Name**: Valtrivo LogSeal (Merkezi Log Yönetimi ve Zaman Damgalama)
- **Tagline**: *"Her kayıt, zamanıyla kanıt."*
- **Path**: `/Users/valp/Documents/CLAUDE/Logger`
- **GitHub**: `https://github.com/v-e-kandjani/Logger` (main)
- **Current Version**: `v1.5.13` (Build Date: `2026-10-11`)
- **Production Server**:
  - **Host**: `168.231.106.208`
  - **SSH**: `alex` / `9m1KE=LPW=N*jd`
  - **Path**: `/home/alex/projects/logger`
  - **URL**: `https://168.231.106.208:8443`
  - **Default Admin**: `admin` / `admin5651!`
- **Database Architecture**:
  - PostgreSQL (`postgres:5432`) bound to `127.0.0.1`: Relational models, configuration, assets, tenants, edge nodes, users.
  - ClickHouse (`9000` native, `8123` HTTP) bound to `127.0.0.1`: Analytical log storage with LZ4 compression.

---

## 2. Key Modules & Features (as of v1.5.13)
1. **Certificate Management**:
   - Explicit Certificate Format selector (`cert-upload-type`):
     - **PKCS#12 / PFX Arşivi (`.pfx`, `.p12`)**: Single archive + password. Private key field is hidden.
     - **Standart X.509 PEM / CRT (`.crt`, `.pem`)**: Certificate + private key. Password field is hidden.
   - Hot-swappable certificate engine, automated SAN generation, and HTTP->HTTPS redirection.
2. **Multi-Tenant Architecture (MSSP)**:
   - Database `tenants` table with quotas (`max_nodes`, `max_eps`).
   - Global Tenant Context Switcher (`#tenant-context-selector`) in the header bar.
   - Settings > "Kiracı Yönetimi (Tenants)" tab with tenant creation and admin provisioning.
3. **Edge Proxy Forwarder Daemon (`logseal-proxy`)**:
   - Standalone Go binary (`cmd/proxy/main.go`) installable directly on minimal Ubuntu (22.04 / 24.04 / 26.04).
   - Minimum hardware requirements: 1 vCPU, 512 MB RAM, 2 GB disk space.
   - Cloud-controlled schedules (`online`, `every 60 second`, `every 5 min`, `every 15 min`, `every 30 min`, `every hour`).
   - 1-line curl automated installation via `scripts/proxy_install.sh`.
   - Node admin details, web order staging with `pending_activation`, and 1-click activation modal.
   - Proxy-routed LDAP / Active Directory branch directory tunneling.
4. **Law No. 5651 & TÜBİTAK KamuSM**:
   - Hourly immutable archive slicing (`.jsonl.gz`) with SHA-256 digests and `.zd` time stamps.
   - Built-in local cryptographic timestamp authority fallback.
5. **SIEM / SOC Engine**:
   - In-memory sliding window correlation engine.
   - Full MITRE ATT&CK Matrix (697 techniques) with automated daily STIX 2.1 release watcher.
   - Active device rule optimizer.
6. **Query Acceleration**:
   - In-memory result cache using up to 60% of available RAM (`GOMEMLIMIT` aware).

---

## 3. Mandatory Development Guidelines (`AGENTS.md`)
Whenever any code, configuration, or template is modified:
1. **Bump Version**:
   - `internal/version/version.go`: `Version = "v1.x.x"`, `BuildDate = "YYYY-MM-DD"`, `CommitSHA`.
   - `web/templates/index.html`: Update `#brand-version`, `#upd-current-version`, `#upd-build-date`, and `?v=...` query params.
   - `web/static/js/translations.js`: Update `app_version` in `tr` and `en`.
   - `README.md` & `README.tr.md`: Add entry under Release History.
2. **Sync to GitHub**:
   - `go test ./...`
   - `git push origin main`
3. **Sync to Production VPS (`168.231.106.208`)**:
   ```bash
   sshpass -p '9m1KE=LPW=N*jd' ssh -o StrictHostKeyChecking=no alex@168.231.106.208 \
     "cd /home/alex/projects/logger && git pull origin main && echo '9m1KE=LPW=N*jd' | sudo -S docker compose build syslog-app && echo '9m1KE=LPW=N*jd' | sudo -S docker compose up -d"
   ```
4. **Sync to Local Docker**:
   ```bash
   docker compose build syslog-app && docker compose up -d
   ```
