# Valtrivo LogSeal — Project Memory & State Guide

> **Important**: This document serves as the project memory for Valtrivo LogSeal. At the beginning of each session, review this document to resume work without needing to re-scan the codebase.

---

## 1. Project Overview & Environments
- **Name**: Valtrivo LogSeal (Merkezi Log Yönetimi ve Zaman Damgalama)
- **Tagline**: *"Her kayıt, zamanıyla kanıt."*
- **Path**: `/Users/valp/Documents/CLAUDE/Logger`
- **GitHub**: `https://github.com/v-e-kandjani/Logger` (main)
- **Current Version**: `v1.5.15` (Build Date: `2026-10-11`, Commit: `81b8687`)
- **Production Server**:
  - **Host**: `168.231.106.208`
  - **SSH**: `alex` / `9m1KE=LPW=N*jd`
  - **Path**: `/home/alex/projects/logger`
  - **URL**: `https://168.231.106.208:8443`
  - **Default Admin**: `admin` / `admin5651!`
- **Database Architecture**:
  - PostgreSQL (`postgres:5432`) bound to `127.0.0.1`: Relational models, configuration, assets, tenants, edge nodes, users, and multi-tenant SIEM alerts (`siem_alerts.tenant_slug`).
  - ClickHouse (`9000` native, `8123` HTTP) bound to `127.0.0.1`: Analytical log storage with LZ4 compression.

---

## 2. Key Modules & Features (as of v1.5.15)
1. **Certificate Management**:
   - Explicit Certificate Format selector (`cert-upload-type`):
     - **PKCS#12 / PFX Arşivi (`.pfx`, `.p12`)**: Single archive + password. Private key field is hidden.
     - **Standart X.509 PEM / CRT (`.crt`, `.pem`)**: Certificate + private key. Password field is hidden.
   - Hot-swappable certificate engine, automated SAN generation, and HTTP->HTTPS redirection.
2. **Multi-Tenant Architecture (MSSP)**:
   - Database `tenants` table with quotas (`max_nodes`, `max_eps`).
   - Tenant Context Switcher (`#tenant-context-selector`) lives in the **sidebar** (`.sidebar-tenant` card, usage/quota meta). Locked for tenant users.
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
5. **SIEM / SOC Engine (Multi-Tenant Scoped)**:
   - In-memory sliding window correlation engine keying buckets by `tenant::rule_id::group_val`.
   - SIEM alerts (`siem_alerts.tenant_slug`) and normalized events strictly tagged with tenant ownership.
   - Scoped SOC Overview stats, alerts listing, triage case notes, and live alert WebSocket stream (`/api/v1/siem/live?tenant=...`).
   - Full MITRE ATT&CK Matrix (697 techniques) with tenant-scoped alert metrics.
   - Active device rule optimizer.
6. **Query Acceleration**:
   - In-memory result cache using up to 60% of available RAM (`GOMEMLIMIT` aware).

---

## 2b. Multi-Tenant Data Isolation (v1.5.14 & v1.5.15)
- **Ownership columns**: ClickHouse `syslog_events.tenant LowCardinality(String) DEFAULT 'default'` (auto `ALTER ... ADD COLUMN IF NOT EXISTS` in `clickhouse.NewClient`), Postgres `devices.tenant_slug` (EnsureEdgeSchema), Postgres `siem_alerts.tenant_slug` (EnsureSIEMSchema). `models.LogEvent.Tenant`, `models.Device.TenantSlug`, `models.NormalizedEvent.Tenant`, `models.SIEMAlert.Tenant`.
- **Attribution**: `pipeline.RawPacket.Tenant` set by edge ingest (`node.TenantName`); else device's tenant; else `default`.
- **Scope resolution**: `Handler.tenantScope(r)` in `internal/api/auth.go` → tenant users forced to `Session.TenantSlug`; root reads `X-Tenant` header or `?tenant=` (`all`/empty = global). Frontend wraps `window.fetch` to send `X-Tenant` from `localStorage.active_tenant_slug`; WebSocket uses `?tenant=`.
- **Scoped endpoints**: `/api/v1/logs`, `/api/v1/logs/live`, `/api/v1/dashboard` (tenant_scope, tenant_eps), `/api/v1/devices` (GET/POST/DELETE), `/api/v1/settings/edge/nodes`, `/api/v1/unregistered/onboard-all`, `/api/v1/tenants` (usage, current_eps, totals, is_root), `/api/v1/siem/overview`, `/api/v1/siem/alerts`, `/api/v1/siem/alerts/{id}` (403 forbidden if across tenant boundary), `/api/v1/siem/alerts/{id}/status`, `/api/v1/siem/alerts/{id}/notes`, `/api/v1/siem/live` (WS tenant filter), `/api/v1/siem/simulate`, `/api/v1/siem/mitre/matrix`.
- **Root tenant** (`default`): max_nodes/max_eps = 0 (unlimited, ∞), aggregates all tenants. Node quota enforced on edge node creation only for customer tenants.
- **Users**: `tenant_slug`/`is_tenant_admin` now persisted by `CreateUser` and read by `GetUserByUsername/ID/ListUsers`; backfill for existing tenant admins. Sessions carry `TenantSlug`, `IsTenantAdmin`; `/api/v1/auth/me` returns `tenant_slug`, `is_root`.
- **SIEM rule optimizer**: `SetSIEMRulesEnabledState` persists is_enabled (BatchUpsertSIEMRules intentionally preserves operator toggles). 12 categories: authentication, privilege, network_admin, perimeter, network, windows, linux, cloud, mail_web, data, defense_evasion, health.
- **Query cache**: frontend reads backend `CacheStats` JSON names (`total_system_memory_mb`, `avail_system_memory_mb`, `current_memory_mb`, `item_count`, `hit_count`, `miss_count`, `hit_ratio_percent`). Search cache key uses time-bucketed `now` (15s / 1m).
- **Not yet tenant-scoped (future)**: archives/exports, storage retention stats, global users list.

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
