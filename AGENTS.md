# Logger Platform - Development & Synchronization Guidelines

Whenever code, configuration, templates, or scripts in this project are modified:

## 1. Version Management (MANDATORY)
- Whenever any changes, fixes, or new features are introduced, **bump the semantic version** (e.g. `v1.2.1` -> `v1.2.2`).
- Update:
  - `internal/version/version.go`: Increment `Version`, update `BuildDate` to current date (`YYYY-MM-DD`), and set `CommitSHA`.
  - `web/templates/index.html`: Update `#brand-version`, `#upd-current-version`, `#upd-build-date`, and cache buster query parameters (`?v=...`).
  - `web/static/js/translations.js`: Update `app_version` in both Turkish (`tr`) and English (`en`).
  - `README.md` & `README.tr.md`: Document changes under Release History.

## 2. Synchronize to GitHub
- Ensure tests and builds pass (`go test ./...`).
- Commit and push all changes directly to `origin/main`:
  ```bash
  git push origin main
  ```

## 3. Synchronize to Remote Production VPS
- **Host**: `168.231.106.208`
- **User**: `alex`
- **Password**: `9m1KE=LPW=N*jd`
- **Path**: `/home/alex/projects/logger`
- **Action**:
  - Pull latest repository changes from `origin/main`.
  - Rebuild `syslog-app` and restart containers:
    ```bash
    git pull origin main
    echo '9m1KE=LPW=N*jd' | sudo -S docker compose build syslog-app
    echo '9m1KE=LPW=N*jd' | sudo -S docker compose up -d
    ```

## 4. Synchronize to Local Docker Desktop
- Rebuild and restart the local Docker container:
  ```bash
  docker compose build syslog-app && docker compose up -d
  ```

---

## 5. Architectural Standards & Cross-Project Synergy
LogSeal operates alongside NetVault (Network Config Management) and FortiLens (FortiGate Firewall Management):
- **Ingestion & Dual Engine**:
  - ClickHouse handles raw/parsed high-speed logs (`syslog_events`). Always use time-partitioned filters (`timestamp >= ...`) and vectorized limits.
  - PostgreSQL handles relational entities (Tenants, Devices, EdgeNodes, Users, Archives, SIEM rules/alerts).
- **Multi-Tenant Data Isolation**:
  - Every operational query must respect `tenantScope(r)` (`active_tenant_slug` / `X-Tenant` header).
  - Scope applies across: Log search & live streams, Devices, Edge Nodes, Dashboard telemetry, SIEM alerts, Archives, and Tenant Quotas.
  - Root `default` tenant has unlimited quotas (`0` = `∞`). Customer tenants enforce explicit node/EPS constraints.
- **Enterprise Security (Synergy with NetVault & FortiLens)**:
  - Strong password policies (min 8 chars, uppercase, lowercase, number, symbol) & password history tracking.
  - Self-service password management for authenticated users.
  - Comprehensive Audit Trail logging for all administrative modifications.
  - Granular FortiGate & Network Device log enrichment (matching FortiLens policy/security posture and NetVault multi-vendor categories).

## 6. Code & Asset Hygiene Guidelines
- **Zero Framework Web Stack**: Keep UI lightweight in native HTML5, CSS3, and ES6 JS (`app.js`, `translations.js`).
- **Encoding Care**: `app.js` and `translations.js` must maintain clean UTF-8 encoding. Do not use scripts that double-encode Turkish characters.
- **Syntax Validation**: Validate JS changes before commit (e.g. `osascript -l JavaScript -e "..."` or browser headless check).
- **Concurrency & Cache Safety**: Ingestion pipeline device maps must use atomic pointer swapping (`atomic.Pointer[deviceMaps]`) without holding mutex locks in hot packet paths.

