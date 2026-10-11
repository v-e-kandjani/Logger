# Valtrivo LogSeal
### Merkezi Log Yönetimi ve Zaman Damgalama
> **“Her kayıt, zamanıyla kanıt.”**  
> Developed by **Valtrivo**

[![Language: English](https://img.shields.io/badge/Language-English-blue.svg)](README.md)
[![Language: Turkish](https://img.shields.io/badge/Dil-T%C3%BCrk%C3%A7e-red.svg)](README.tr.md)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary%20%2F%20Valtrivo-green.svg)](LICENSE)
[![Platform: Linux Ubuntu](https://img.shields.io/badge/Platform-Ubuntu%2020.04%20%7C%2022.04%20%7C%2024.04-orange.svg)](HOW_TO_INSTALL.md)

---

## 🌐 Language / Dil
- 🇬🇧 **[English Documentation (Current)](README.md)**
- 🇹🇷 **[Türkçe Dokümantasyon için Tıklayın](README.tr.md)**
- 📖 **[Docker Installation Guide (HOW_TO_INSTALL.md)](HOW_TO_INSTALL.md)**
- ⚡ **[Docker Ubuntu Installer Script (install.sh)](install.sh)**
- 🖥️ **[Standalone Bare-Metal (No Docker) Guide (STANDALONE_INSTALL.md)](STANDALONE_INSTALL.md)**
- 🚀 **[Standalone Linux Installer (install_standalone.sh)](install_standalone.sh)**

---

## Key Highlights

- **High-Throughput Ingestion**: Non-blocking UDP, TCP, and TLS socket listeners with ring buffer channel architectures capable of tens of thousands of EPS.
- **ClickHouse Columnar Storage**: Vectorized filtering, token bloom filter indexes, ZSTD compression, and `toYYYYMM` partitioning for analytics across billions of events.
- **TÜBİTAK KamuSM Zaman Damgası Client**: Official console integration (`tss-client-console-3.1.33.jar`) for RFC 3161 cryptographic timestamp evidence (.zd token) generation.
- **Relational Metadata Store**: PostgreSQL 16 backing device inventory, auto-discovered network sources, archive cataloging, and administrative audit trails.
- **Modern Dark-Mode Operations Dashboard**: Pure HTML5, CSS3, and ES6 JavaScript with zero dependencies and real-time WebSocket live streaming.

---

## Repository Structure

```
.
├── cmd/
│   ├── server/                  # Web dashboard, REST API & live stream hub
│   └── syslog-loadtest/         # High-speed synthetic syslog traffic generator
├── internal/
│   ├── api/                     # REST endpoints (/api/v1/...) & WebSocket handlers
│   ├── archive/                 # Deterministic JSONL.GZ creator & SHA-256 cataloger
│   ├── config/                  # YAML loader with environment overrides
│   ├── database/
│   │   ├── clickhouse/          # Connection pool & high-throughput batch writer
│   │   └── postgres/            # Relational database layer & in-memory DeviceCache
│   ├── models/                  # Domain entities (LogEvent, Device, Archive)
│   ├── syslog/
│   │   ├── listener/            # Kernel-tuned UDP, TCP, and TLS listeners
│   │   ├── parser/              # RFC 3164, RFC 5424, and vendor fallback parsers
│   │   └── pipeline/            # Worker pool, device enrichment, and broadcast
│   └── timestamp/               # TÜBİTAK KamuSM provider and Mock provider
├── migrations/
│   ├── clickhouse/              # 001_initial_events.sql
│   └── postgres/                # 001_initial_schema.sql
├── web/
│   ├── templates/               # index.html UI
│   └── static/                  # CSS styles and JavaScript logic
├── docker-compose.yml           # ClickHouse + PostgreSQL Docker Desktop stack
├── Makefile                     # Build, test, run, and benchmark commands
└── README.md
```

---

---

## Automated Linux Ubuntu Installation

> 📖 **Comprehensive Step-by-Step Guide**: For detailed instructions, firewall guidelines, and troubleshooting, see **[HOW_TO_INSTALL.md](HOW_TO_INSTALL.md)**.

For bare-metal or cloud Ubuntu servers (20.04, 22.04, 24.04 LTS), use the automated installer:

```bash
# Clone the repository
git clone https://github.com/v-e-kandjani/Logger.git
cd Logger

# Run the installation script as root
sudo bash install.sh
```

### What `install.sh` Does Automatically:
1. **Interactive Setup Wizard**:
   - Prompts for Web UI Port (e.g. `8080`, `8443`, or custom).
   - Prompts for PostgreSQL database name, user, and password (or accepts secure defaults).
   - Prompts for ClickHouse database name, user, and password (or accepts secure defaults).
   - Prompts for Initial Administrator username and password.
   - Supports automated unattended deployment via `sudo bash install.sh -y` or `--defaults`.
2. **System Dependencies & Docker Engine**:
   - Installs all runtime packages (`ca-certificates`, `curl`, `wget`, `gnupg`, `ufw`, `jq`, `openssl`, `git`).
   - Automatically installs and configures official **Docker CE** and the **Docker Compose** plugin if not already installed.
3. **UFW (Uncomplicated Firewall) Configuration**:
   - Automatically configures UFW and allows **SSH (22/tcp)** to prevent administrator lockout.
   - Allows Syslog Ingestion: Standard **514/udp & 514/tcp**, Alternate **5514/udp & 5514/tcp**, and Secure TLS **6514/tcp**.
   - Allows Web Dashboard on the user-selected port (`APP_PORT/tcp`).
   - Explicitly blocks and shields database ports (5432, 9000, 8123) from external interfaces.
   - Non-interactively enables UFW.
4. **Local-Only Database Shielding**:
   - PostgreSQL and ClickHouse host ports are bound **strictly to 127.0.0.1 (loopback)**.
   - Local administrative users on the server can connect (`psql -h 127.0.0.1`, `clickhouse-client`), while outside network traffic is completely barred.
5. **Database Initialization & Table Creation**:
   - Boots database containers and waits for healthchecks.
   - Automatically executes PostgreSQL migration `migrations/postgres/001_initial_schema.sql` (devices, users, archives, audit logs, settings).
   - Seeds the administrator account with bcrypt crypt-hashing.
   - Automatically executes ClickHouse migration `migrations/clickhouse/001_initial_events.sql` (`syslog_events` table and `mv_events_per_minute` materialized view).
   - Starts the full stack and validates system health.

---

## Quickstart with Docker Compose

### 1. Start the Platform
```bash
# Copy and configure environment if needed
cp .env.example .env

# Launch containers
docker compose up -d
```
- **Local Database Access Only**: ClickHouse (`127.0.0.1:9000`, `127.0.0.1:8123`) and PostgreSQL (`127.0.0.1:5432`) are bound strictly to localhost (`127.0.0.1`) and cannot be reached from outside networks.
- **Configurable Entrypoint**: Web UI port defaults to `${APP_PORT:-8080}`.
- **Syslog Ingestion**: Ports `514` & `5514` (UDP/TCP) and `6514` (TLS).

### 2. Access Web Platform & Authenticate
Open `http://localhost:8080` in your browser. All unauthenticated requests are automatically redirected to the secure login gateway (`/login`).
- **Default Administrator**:
  - **Username**: `admin`
  - **Password**: `admin5651!`
- **Session Security**: Backed by HttpOnly SameSite session cookies, bcrypt password hashing, and active session invalidation on logout.

### 3. Generate Test Syslog Traffic
```bash
./bin/syslog-loadtest -target 127.0.0.1:514 -vendor watchguard -eps 500 -duration 10s
```

### 4. Trigger Archive & Timestamp Evidence
Click **"Create Archive Now"** in the web UI or run:
```bash
curl -X POST http://127.0.0.1:8080/api/v1/archives/create
```
Inspect generated `.jsonl.gz`, `.sha256`, and `.zd` evidence in `/opt/syslog-platform/archive/`.

---

## Law No. 5651 & TÜBİTAK Timestamping Architecture

The platform supports multiple timestamping strategies designed for flexible compliance, testing, and production operations:

### 1. Stamping Modes & Strategies
- **Internal Cryptographic Authority (`internal` - Default)**:
  - Generates verifiable HMAC-SHA256 digital signature tokens (`.zd`) locally.
  - **Zero external dependencies**: Requires **no** TÜBİTAK subscription, no account credentials, and zero network credit consumption.
  - Produces tamper-evident proof tokens matching standard archive verification protocols.
- **Official TÜBİTAK KamuSM (`kamusm`)**:
  - Connects to official TÜBİTAK TSS servers (`http://zd.kamusm.gov.tr:80` for Production or `http://tzd.kamusm.gov.tr:80` for Test) using the official console client JAR (`tss-client-console-3.1.33.jar`).
  - RFC 3161 and Law No. 5070 / 5651 compliant digital signatures.
- **Disable Stamping (`disabled`)**:
  - Completely disables external TÜBİTAK and internal digital timestamp generation.
  - Archives are still deterministic, SHA-256 hashed, and compressed into `.jsonl.gz` format for storage and audit.

### 2. Auto-Fallback Protection
- When configured, if the mode is set to `kamusm` but **no active account credentials** are entered, or if the TÜBİTAK TSS servers are unreachable, the system automatically falls back to the **Internal Cryptographic Authority**.
- This guarantees uninterrupted archival cycles: log slices are never rejected or left unsealed even during network outages or before a KamuSM account is provisioned.

### 3. Official TÜBİTAK KamuSM Integration Notes
- **Client Binary Location**: `/opt/syslog-platform/timestamp-client/tss-client-console-3.1.33.jar`
- **Official Specification Verified**:
  ```bash
  java -jar tss-client-console-3.1.33.jar -z [File] [TSS Address] [TSS Port] [Customer No] [Customer Password] sha-256
  ```
- **Verification Protocol**:
  ```bash
  java -jar tss-client-console-3.1.33.jar -c [File] [Time Stamp File (.zd)]
  ```
- **Authority Testing**: The Web UI features an immediate **"Test Authority / Query Credits"** button to check TÜBİTAK account balances or verify local authority status without generating an archive slice.
- **Legal Compliance Distinction**: The application implements technical controls (cryptographic SHA-256 hashing, deterministic archival, and RFC 3161 timestamp evidence association). Legal compliance under Law No. 5651 requires operational compliance, organizational certificate validation, and statutory retention periods.

---

## WatchGuard Firebox / Fireware FW Support

The platform natively identifies, parses, enriches, and indexes logs from **WatchGuard Firebox** appliances running **Fireware OS**:

### Supported Message Formats
1. **Firewall & Proxy Traffic Logs**:
   - `msg_id="3000-0148"` Deny/Allow packets with source IP, destination IP, ports, interfaces, and proxy policies.
   - Standard BSD RFC 3164 and ISO 8601 timestamps.
   - Enriched action tag (`Firewall (Allow)` / `Firewall (Deny)`).
2. **Management & Authentication Logs**:
   - `sessiond` (`msg_id="3E00-xxxx"`): Web UI / CLI / SSL-VPN administrator and user authentication events.
3. **VPN & Tunneling Logs**:
   - `iked` (`msg_id="0204-xxxx"`): Phase 1 / Phase 2 IPsec and BOVPN negotiations.
4. **Intrusion Prevention & Gateway AntiVirus**:
   - `ipsd`, `scand`: Blocked threats and signatures.

### Configuring WatchGuard Firebox Syslog
1. Log in to **Fireware Web UI** (or Policy Manager).
2. Navigate to **System** > **Logging** > **Syslog Server**.
3. Check **Send log messages to the syslog server**.
4. Enter your collector IP (`<IP of this logger>`), Port `514` (or `5514`), and select **Syslog** format.
5. In your policies (e.g. Proxy or Packet Filter rules), enable **Send a log message**.

---

## Syslog Ingestion Security & Device Access Control (Zero-Trust)

To prevent rogue, random, or unauthorized network devices from sending syslog traffic or flooding the ClickHouse analytical store, the platform includes a dynamic **Zero-Trust Network Ingestion Gate**:

### 1. Ingestion Modes
- **Permissive / Auto-Discovery Mode (Default)**:
  - Accepts incoming syslog packets from any IP address.
  - Automatically parses and enriches known devices.
  - Senders not yet present in Asset Management are dynamically cataloged in the **Auto-Discovered Senders** table for review and 1-click registration.
- **Strict Zero-Trust Mode**:
  - Accepts syslog packets **ONLY** from registered devices present in the active in-memory Device Cache.
  - Packets originating from unapproved, random, or spoofed IPs are immediately discarded at the pipeline boundary.
  - Unregistered packets are tracked via the real-time **Dropped Unauthorized Packets** counter and exposed in health telemetry.

### 2. Configuration & Live Toggle
Toggle directly in the Web UI under **Settings** > **Network Ingestion Security & Device Access Control**, or via REST API:
```bash
# Enable Strict Zero-Trust Filtering
curl -X POST http://localhost:8080/api/v1/settings \
  -H "Content-Type: application/json" \
  -d '{"strict_device_filtering":"true"}'
```

---

---

## Operator Management & Access Governance

- **Role-Based Access Control (RBAC)**: Supports 5 granular security profiles: *Super Administrator*, *Security Analyst*, *Auditor*, *Operator*, and *Read Only*.
- **Admin-Only Visibility & Management**: Only **Super Administrators** have permission to view operator accounts or access the Users & Access Control console. All user API endpoints (`/api/v1/users`) enforce strict 403 Forbidden checks for non-administrators.
- **Self-Deletion Protection**: An active operator **cannot delete or deactivate their own account** via the UI or API, preventing accidental administrator lockouts.
- **Admin Password Reset**: Super Administrators can reset operator credentials directly in **Users & Access Control** > **Reset Password** (minimum 8 characters with bcrypt salted hashing).
- **Automated Source Onboarding**: When registering auto-discovered senders, assets are assigned a Device Group / Tier (e.g. *Perimeter Firewalls*, *Core Switches & Routers*, *Datacenter Servers*) and automatically purged from the unknown sources queue.

---

## Compliance Archive Downloads & Verification

From the **Archives & Legal Evidence** tab, administrators and auditors can download:
1. **Compliance Bundle (`.zip`)**: A bundled package containing the compressed log archive (`.jsonl.gz`), official KamuSM timestamp token (`.zd`), and SHA-256 digest (`.sha256`).
2. **Raw Log Archive (`.gz`)**: Compressed RFC-compliant JSON Lines syslog slice.
3. **KamuSM Timestamp Evidence (`.zd`)**: RFC 3161 digital signature token for independent verification via `tss-client-console-3.1.33.jar -c`.

```bash
# Download compliance bundle via API
curl -O -J "http://localhost:8080/api/v1/archives/download?id=<ARCHIVE_ID>&type=bundle"
```

---

## Architecture & Technical Documentation

- 📘 [**Comprehensive System Architecture Specification**](docs/ARCHITECTURE.md) — Multi-tier ingestion, dual-engine storage (ClickHouse + PostgreSQL), in-memory correlation, and 5651 timestamping architecture.
- 🛡️ [**MITRE ATT&CK® Integration & Synchronization Guide**](docs/MITRE_ATTACK_GUIDE.md) — Adversary tactic taxonomy, multi-vendor log normalization, and online/air-gapped STIX 2.1 synchronization.
- 🚀 [**Upgrade & Zero-Data-Loss Maintenance Guide**](UPGRADE.md) — 1-click web upgrades, automated pre-upgrade database snapshots, and rollback instructions.

- **v1.6.2** (ClickHouse 1-Minute Materialized Views & Sub-Millisecond Time-Series Analytics):
  - **1-Minute Materialized Views (`events_1m` & `mv_events_1m`)**: Implemented pre-aggregated `SummingMergeTree((event_count, total_bytes))` partitioned by `toYYYYMM(minute)` and ordered by `(tenant, minute, device_id, vendor, product, severity, facility)`, automatically populated on log ingestion.
  - **Ultra-Fast Time-Series API**: Added `/api/v1/analytics/timeseries` endpoint providing sub-millisecond historical minute-by-minute metrics without scanning billions of raw log events.
  - **Dashboard Query Offloading**: Offloaded dashboard today log count and tenant statistics to `events_1m`, decreasing disk read amplification by over 97%.

- **v1.6.1** (Hourly SHA-256 Evidence Pipeline & TÜBİTAK Zamane KS Law 5651 Integration):
  - **Deterministic 6-Stage Sealing Engine (`internal/archive/sealer.go`)**: Built an immutable evidence pipeline (`QUEUED` ➔ `BUILDING` ➔ `SEALED` ➔ `TSA_PENDING` ➔ `VERIFIED` ➔ `COMMITTED`) with atomic SHA-256 tree hashing, canonical manifests, and background hourly reconciler (`StartHourlyScheduler`).
  - **TÜBİTAK Zamane KS Adapter (`internal/timestamp/zamane.go`)**: Implemented unprivileged subprocess runner with memory limits (`-Xmx256m`), timeouts, and RFC 3161 DER verification for Law 5651 legal compliance.
  - **Relational Evidence Catalog**: Migrated PostgreSQL schema to store archive jobs, manifests, timestamp proofs, and audit logs.
  - **Manual Sealing API & Dashboard Modal**: Added `/api/v1/archives/manual` and `/api/v1/archives/jobs` REST endpoints with a dedicated dashboard modal (`#modal-manual-archive`) for on-demand forensic sealing and instant status tracking.

- **v1.6.0** (Web-Based SIEM Architecture: CPU/RAM Resource Governor & Cgroups v2 Slice Isolation):
  - **Linux Cgroups v2 & Systemd Slice Hierarchy**: Introduced three-tier cgroup slices (`siem.slice`, `siem-control.slice`, `siem-data.slice`) with strict CPU quotas and memory boundaries (`AllowedCPUs`, `CPUQuota`, `MemoryHigh`, `MemoryMax`, `MemoryLow`), separating management access from worker load.
  - **Dynamic Resource Governor (`internal/governor`)**: Implemented automated host and cgroup metric probe with 4-phase state machine (`Normal`, `Pressure`, `Critical`, `Recovery`) to dynamically arbitrate query admission, report execution, and memory pressure.
  - **Governor Telemetry API**: Added `/api/v1/governor/status` exposing real-time CPU throttling, memory pressure (PSI), cgroup allocations, and admission states.

- **v1.5.24** (Multi-Tenant Isolation, Enterprise Audit Trail, Self-Service Password Policy & Deep Firewall Log Intelligence):
  - **Comprehensive Administrative Audit Trail**: Added PostgreSQL audit trail storage (`audit_logs`) and REST API (`/api/v1/audit/logs`) recording authentication events, user lifecycles, and tenant operations with IP extraction and multi-tenant scoping; introduced dedicated settings panel (`#setting-section-audit`) with instant action and text search filters.
  - **Enterprise Password Policy & Self-Service Change**: Enforced strict password complexity (min 8 chars, uppercase, lowercase, number, symbol) across user creation, administrative password resets, and introduced self-service password update endpoint (`/api/v1/auth/change-password`) with interactive client-side strength evaluation badge indicator.
  - **Deep Firewall & Multi-Vendor Network Log Intelligence**: Normalized Fortinet FortiGate UTM, traffic, VPN, and system logs with automatic threat severity escalation; integrated Cisco IOS/NX-OS, HPE Aruba, and Juniper Junos telemetry extraction with vendor and application badges across forensic search and live streams.
  - **Tenant Storage Breakdown & Scoped User Management**: Added ClickHouse tenant-level log distribution aggregation (`GetTenantStorageBreakdown`) for MSSP quota monitoring and enforced strict organization scoping in PostgreSQL user management.

- **v1.5.23** (Diagnostic Support Database Last 8,000 Logs & SIEM Security Activity Last 1,000 Alerts Export):
  - **ClickHouse Last 8,000 Syslog Events Extraction**: Increased database diagnostic export depth from 1,000 to 8,000 events (`database_last_8000_logs.json`) with tenant scoping support, providing deeper forensic context for support investigations.
  - **SIEM Security Activity & Last 1,000 Alerts Export**: Expanded SIEM security incident extraction to up to 1,000 alerts (`siem_security_activity_last_1000_alerts.json`), adjusting database pagination limits from 200 to 1,000.
  - **UI & Checkbox Synchronization**: Updated Support & Diagnostics scope options and multilingual descriptions across Turkish and English to reflect 8,000 logs and 1,000 alerts.

- **v1.5.22** (Support Diagnostics 7-Day TTL Auto-Purge & Retention Governance):
  - **Automated 1-Week TTL Server Auto-Cleaner**: Introduced background retention worker running every hour (`StartSupportBundleCleaner`) to automatically delete expired `.tar.gz` diagnostic bundles from disk and purge database catalog records once 7 days elapse.
  - **Gate & Download Route Expiration Enforcement**: Enhanced `/support/download` to verify bundle `expires_at` (7-day window); automatically removes file and returns `410 Gone` if expired, preventing stale diagnostic bundles from persisting on disk.
  - **TTL & Expiry Telemetry in UI**: Added prominent 7-day TTL countdown telemetry across both the Result Card (`⏳ 7 Gün (1 Hafta TTL)`) and Support Bundles History table (`Geçerlilik` badge with remaining days or expired status).

- **v1.5.21** (Support Portal Universal Clipboard & One-Click Download Optimization):
  - **Universal Clipboard Copy Engine (`copyToClipboard`)**: Implemented robust clipboard helper with asynchronous `navigator.clipboard.writeText` and transparent fallback to `document.execCommand('copy')`, fixing "Copy Passcode" and "Copy Link" buttons across all browsers and SSL contexts with instant visual confirmation feedback ("✓ Copied!").
  - **Full-Width Responsive Download URL & 1-Click Direct Download**: Resolved narrow input truncation by applying fluid flexbox width and automatic click-to-select (`onclick="this.select()"`); enhanced direct download button (`⬇️ Download Bundle Directly`) with absolute URL resolution and download trigger guarantees.
  - **Persistent Support Bundle Storage (`syslog_support_bundles`)**: Added persistent named Docker volume for `/opt/syslog-platform/data/support_bundles`, preventing diagnostic bundle loss during container upgrades and maintenance cycles.

- **v1.5.20** (Diagnostic Support Database Last 1,000 Logs & SIEM Security Activity Export):
  - **ClickHouse Last 1,000 Syslog Events Extraction**: Added selectable option (`include_db_logs`) to query and include the latest 1,000 raw and parsed events from ClickHouse (`syslog_events`) directly into `database_last_1000_logs.json` inside the `.tar.gz` diagnostic bundle, with tenant scoping support.
  - **SIEM Security Activity & Incident Records Extraction**: Added selectable option (`include_siem_events`) to extract recent security incidents and detection activity from PostgreSQL (`siem_alerts`) into `siem_security_activity.json` inside the diagnostic bundle.
  - **Granular Diagnostic Generator UI**: Expanded the Support & Diagnostics panel (`#pane-support`) with checkboxes for both ClickHouse database events and SIEM incident history alongside system settings, host telemetry, and service log tails.

- **v1.5.19** (Standalone Sidebar Support Menu & Dedicated Diagnostics Hub):
  - **Dedicated Top-Level Support & Diagnostics Menu (`#support`)**: Promoted the diagnostic support module from an embedded panel in Settings to a first-class, standalone sidebar menu item (`#nav-tab-support`) and dedicated full-width tab pane (`#pane-support`), ensuring immediate, 1-click access for operators seeking technical support.
  - **Clean Navigation Separation**: Completely decoupled diagnostic bundle generation and history cataloging from system configuration settings (`#pane-settings`), streamlining both views.
  - **Seamless Cross-Tab Redirection**: Health telemetry quick-action card and helper triggers now navigate directly to the standalone `#support` pane, with automated bundle history loading and dynamic localization in Turkish and English.

- **v1.5.18** (Diagnostic Support & Debug Package Generator, Password-Protected Download Portal & Root SuperAdmin Dispatch):
  - **Diagnostic Support & Debug Package (.tar.gz Bundle)**: Automated support bundle generator collecting system environment, host hardware specs, sanitized system settings (all passwords, keys, and tokens redacted), ingestion pipeline telemetry, database inventory counts, network interfaces, and recent application log tail into a standard compressed `.tar.gz` archive.
  - **Password-Protected & Credential-Gated Download Gateway (`/support/download`)**: Standalone secure download portal requiring either active Super Administrator credentials or a unique 10-character cryptographic Access Passcode (`SUP-XXXX-XXXX`) to download the archive, completely blocking unauthorized access.
  - **Root SuperAdmin Automated Email Dispatch (SMTP)**: Integrates with SMTP notification engine to automatically dispatch an email alert to the Root SuperAdmin containing the ticket ID, requester, issue description, direct link, and access passcode upon bundle generation.
  - **Operations Dashboard & Settings UI Integration**: Dedicated "Destek & Hata Ayıklama (Debug)" panel under Settings with inline generator form and past bundles history table, plus a quick-action diagnostic banner inside System Health (`#pane-health`).

- **v1.5.17** (Standalone Bare-Metal Installer without Docker, Tenant Device Assignment & Full UI Localization):
  - **Standalone Bare-Metal Linux Installer (`install_standalone.sh` & `STANDALONE_INSTALL.md`)**: Complete support for installing and running the entire platform directly on Ubuntu 20.04, 22.04, 24.04, and 26.04 LTS (and Debian 11/12) without Docker. Automatically installs native PostgreSQL, official ClickHouse Server, OpenJDK 17 JRE Headless, builds Go binaries, provisions schemas, and configures `syslog-platform.service` under systemd.
  - **Device Tenant Assignment & Reassignment**: Enabled assigning registered devices and auto-discovered network sources to specific tenants (e.g., `1ware`). Added `PUT /api/v1/devices` and `UpdateDevice` to reassign tenants, change groups, and update device metadata with atomic cache refresh.
  - **Device Editing & Onboarding UX**: Added `✏️ Edit` action button on the devices table with prefilled modal and tenant selector; single-device and bulk onboarding (`⚡ Auto-Onboard All`) automatically tag devices with the active tenant scope.
  - **Comprehensive Multi-Modal Localization (TR / EN)**: Audited and localized all remaining modals and panels: Device Registration/Edit, User Creation, Password Reset, Custom 5651 Export, SIEM Incident Investigation, CPU & Network Telemetry, and Active Directory Sync.

- **v1.5.16** (Multi-Tenant Log Archive Isolation & Comprehensive Page Document Localization):
  - **Multi-Tenant 5651 Log Archive Isolation**: Extended legal log archives (`log_archives.tenant_slug`) and ClickHouse extraction queries to strictly isolate archive records per customer/tenant. Hourly auto-archiving automatically generates discrete archives for each active tenant in that time slice.
  - **Custom Range Export & Download Authorization**: Custom export requests, job tracking, and download endpoints (`/api/v1/archives/{id}/download`, `/api/v1/archives/custom/...`) enforce tenant scoping. Attempted downloads across tenant boundaries are strictly rejected with HTTP 403 Forbidden.
  - **Tenant-Scoped Archives Table & Context Refresh**: Added Tenant column and chip (`🏢 {tenant}`) to the legal archives table; changing tenant context in the sidebar instantly filters available archives.
  - **Comprehensive Page Document & UI Localization**: Fixed untranslated text when switching languages (TR / EN). Modals (Add Edge Node, Activate Edge Node, New Tenant), hardware specification reference cards, table headers, form placeholders, helper labels, dynamic interval options, and empty states now update dynamically and accurately based on the active language.

- **v1.5.15** (Multi-Tenant SIEM & SOC Isolation, Tenant-Scoped Security Alerts & Live Threat Streams):
  - **Multi-Tenant SIEM Alert Isolation**: Extended SIEM alerts (`siem_alerts.tenant_slug`) and normalized events to carry tenant ownership. Alerts, incident counts, SOC metrics, and forensic evidence are strictly segregated by tenant.
  - **Tenant-Scoped Correlation Buckets**: Updated the sliding-window correlation engine to key evaluation buckets by `tenant::rule_id::group_val`. Sliding window thresholds and password-spraying counters are strictly isolated per tenant, preventing cross-tenant threshold leaks or cross-tenant alert triggers.
  - **Tenant-Filtered SOC Overview & Telemetry**: `/api/v1/siem/overview`, `/api/v1/siem/alerts`, and MITRE ATT&CK coverage reports filter metrics and incident lists server-side according to the active tenant scope (`X-Tenant` header / `?tenant=`). Root administrators can view all aggregated alerts or scope down to any individual tenant.
  - **Live WebSocket Alert Filtering**: The real-time SOC alert WebSocket stream (`/api/v1/siem/live?tenant=...`) filters incoming alerts in real-time by tenant, ensuring analysts only receive incidents belonging to their tenant scope.
  - **Frontend SOC Multi-Tenant UX**: The SIEM alerts table displays tenant chips (`🏢 {tenant}`) on incident rows, the investigation modal shows tenant attribution, and switching tenants in the sidebar instantly refreshes all SOC telemetry, incident tables, and active incident badges.
  - **Incident Access Control**: Secured `/api/v1/siem/alerts/{id}` detail, triage status updates, and case notes endpoints so tenant users cannot inspect or alter alerts belonging to other organizations (HTTP 403 Forbidden).

- **v1.5.14** (Real Tenant Data Isolation, Sidebar Tenant Selector, Unlimited Root Tenant, Working Rule Optimizer & Query Cache Telemetry):
  - **True Multi-Tenant Data Isolation**: Logs (`syslog_events.tenant` ClickHouse column) and devices (`devices.tenant_slug`) now carry tenant ownership. Edge-proxy logs inherit their node's tenant; direct syslog inherits the registered device's tenant. Search, dashboard counters, devices, edge nodes, live stream and EPS are filtered server-side by the selected tenant (`X-Tenant` header / `?tenant=`). Tenant users are always locked to their own tenant.
  - **Sidebar Tenant Selector**: The tenant context switcher moved from the header into the sidebar, showing usage (nodes · devices · EPS) and quota for the selected tenant; switching instantly refreshes all scoped views. Locked (🔒) for tenant admins.
  - **Unlimited Root Tenant**: The `default` (root/MSSP) tenant has no node/EPS quota (shown as ∞) and aggregates every tenant's nodes and EPS. Node quotas are enforced only for customer tenants.
  - **Tenant Admin Persistence Fix**: `tenant_slug` / `is_tenant_admin` are now stored and loaded for users (previously dropped), with an automatic backfill for existing tenant admins.
  - **Device-Aware Rule Optimizer Fix**: "Optimize rules for my devices" now really enables/disables detection rules (the upsert previously ignored `is_enabled`), maps devices to the 12 real rule categories, and reports enabled/disabled counts.
  - **Detection Rules Header**: Shows "12 Categories · active/shown rules" instead of the raw "72" rule count; fixed category filter values (`data`, `health`).
  - **In-Memory Query Cache Telemetry Fix**: Total/available host RAM, budget, usage, items, hits/misses now display correctly (JSON field mismatch). Search cache keys are time-bucketed so repeated queries actually hit the cache; tenant counters/EPS are cached too.

- **v1.5.13** (Dedicated Certificate Type Selection (PFX/P12 vs PEM), Multi-Tenant MSSP Management, Node Admin Activation & Pre-Configuration, Proxy-Routed LDAP, Hardware Specs Pre-Flight):
  - **Dedicated Certificate Format Selector (PFX/P12 Archive vs. Standart PEM/CRT)**: Added an explicit certificate type selector. Selecting `PFX / PKCS#12` prompts exclusively for the single archive file (`.pfx`, `.p12`) and password, hiding separate private key inputs. Selecting `PEM / CRT` prompts for certificate and private key files.
  - **Multi-Tenant Organization Management & Global Context Switching**: Built a full MSSP multi-tenant governance module with a dedicated `tenants` table, tenant administrator account provisioning, and a global Tenant Context Switcher dropdown in the top header. Root Super Admins can seamlessly view and manage tenant-specific datasets or global views.
  - **Edge Node Administrator & Cloud Pre-Configuration**: Edge proxy nodes store friendly names, administrator contact details (name, email, username, password), and activation status (`active` vs `pending_activation`). Root Super Admins can activate pending nodes with pre-configured administrator credentials and policies in one click.
  - **Proxy-Routed LDAP / Active Directory Integration**: Centralized Cloud configuration for remote branch Active Directory and LDAP directories tunneled through edge forwarders, dynamically synchronizing configuration over proxy heartbeats.
  - **Minimum Hardware Specifications & Pre-Flight Installer Inspection**: Established hardware requirements (Minimum: 1 vCPU, 512 MB RAM, 2 GB disk; Recommended: 2-4 vCPU, 1-2 GB RAM, 10-20 GB SSD) with automated pre-flight checks in `proxy_install.sh` and informative reference cards in Cloud UI.

- **v1.5.12** (Edge Proxy Forwarder Daemon (`logseal-proxy`), Cloud-Managed Schedules & Automated Ubuntu Installer (`proxy_install.sh`)):
  - **Lightweight Standalone Linux Forwarder Daemon (`logseal-proxy`)**: Implemented a standalone, zero-dependency Go daemon installable directly on minimal Ubuntu Linux (20.04 / 22.04 / 24.04 / 26.04) without requiring Docker. Includes an interactive connection setup wizard (`-setup`), dual UDP/TCP 514 syslog listeners, local disk spool buffering (`/var/spool/logseal`), and GZIP-compressed HTTPS batch delivery.
  - **Centrally Cloud-Controlled Transmission Scheduling**: Transmission frequency is configured strictly in Cloud Settings, not on the proxy itself. The proxy polls the cloud and dynamically adjusts its buffer flushing to the selected schedule: `"online"` (real-time stream), `"every 60 second"`, `"every 5 min"`, `"every 15 min"`, `"every 30 min"`, or `"every hour"` (defaults to `"online"`).
  - **Automated Ubuntu Installer Script (`proxy_install.sh`)**: Created an automated installer deployed via 1-line curl (`curl -k -sSL https://<host>:8443/api/v1/edge/install.sh | sudo bash`) that configures directories, downloads the binary, writes `/etc/logseal/proxy.json`, and registers/starts the systemd unit `logseal-proxy.service`.
  - **Cloud UI Edge Node Management**: Added a dedicated "Edge Proxy Düğümleri" panel in Settings with active node heartbeat tracking, inline transmission schedule dropdowns, token generation, and one-click copyable installation commands.

- **v1.5.11** (Multi-Format Certificate File Upload (.crt, .pfx, .pem), Role Logo Badges & Header Layout Optimization):
  - **Direct Multi-Format Certificate Upload with PFX Password Support**: Replaced raw PEM textareas with direct file uploads (`.crt`, `.pfx`, `.pem`, `.p12`). Native PKCS#12 decoding automatically decrypts password-protected PFX archives into leaf certificates, intermediate chains, and private keys. Single-file PEM bundles and standalone cert + key pairs are parsed seamlessly.
  - **Active User Role Identity Badges**: Integrated dynamic role-specific SVG logos and color themes for the authenticated user in the top right header (Crown for Super Administrator, Threat Radar for Security Analyst, Scale of Justice for Auditor, Server Rack for Operator, and Eye for Read Only).
  - **Responsive Header & Compact Topbar Scaling**: Streamlined header padding, font sizes, EPS counter, and action buttons. Responsive media queries dynamically adjust elements to guarantee optimal visibility across all screen and window sizes without layout overflow.
  - **Sidebar Scroll Fix for Extended Submenus**: Added a dedicated sleek scroll container (`overflow-y: auto; scrollbar-width: thin;`) to the sidebar navigation menu, ensuring all menu items remain fully accessible when submenus are expanded.

- **v1.5.10** (Isolated Settings Section Tab Navigation & Submenu Scope Display):
  - **Isolated Settings Section Display**: Transformed the Settings page from a vertically scrolled monolithic view into an isolated, dedicated modular section view (`displaySettingsSection()`). When selecting any settings submenu item (e.g., KamuSM, Ingestion, HTTPS & TLS, FQDN, Cache, Active Directory, MFA, Retention, SMTP), only the target configuration panel is rendered on the page (`.settings-panel-single`) while extraneous sections are cleanly hidden without auto-scrolling jitter.
  - **Full-Breadth Settings Subnav Navigation**: Added dedicated "All Settings" (`all`) and "MFA & TOTP Governance" (`setting-section-mfa`) navigation targets across both the sidebar collapsible submenu and the in-pane sticky glassmorphic pill bar.
  - **Smooth View Entrance Animation**: Integrated refined subtle entrance animations (`settingSectionFadeIn`) and instant top-alignment for focused, distraction-free configuration management.

- **v1.5.9** (Sidebar Navigation Fix, Minimal Modern SVG Icons, Settings Sub-Menu Navigation & Dashboard Ingestion Telemetry):
  - **Syntax Error Fix & Sidebar Navigation Restoration**: Resolved duplicate `redEl` and `badge` variable declarations in `loadHTTPSSettings()`, eliminating client-side script parse exceptions and restoring smooth navigation tab switching across all dashboard panes.
  - **Minimal Modern SVG Iconography**: Replaced generic emoji icons in the sidebar navigation with crisp, scalable, minimal SVG vector icons (Dashboard, Live Stream, Log Search, SIEM & SOC, Registered Devices, Unknown Sources, Archives, System Health, Settings, Users, and Upgrades).
  - **Settings Expandable Submenu & Sticky Subnav Bar**: Introduced a nested collapsible submenu in the sidebar for Settings (KamuSM, Syslog Ingestion, HTTPS & TLS, FQDN, Memory Cache, Active Directory, Storage Retention, and SMTP) coupled with an in-pane sticky glassmorphic pill bar (`.settings-subnav`) with smooth section scrolling.
  - **Persistent Ingested Logs Telemetry**: Updated `handleDashboard` to incorporate stored ClickHouse table rows into `total_inserted`, ensuring Total Inserted logs telemetry accurately reflects all persisted records even across daemon restarts.

- **v1.5.8** (Active Device SIEM Rule Optimizer & Certificate-Gated HTTP Redirection):
  - **SIEM Rule Optimization for Active Inventory Devices**: Introduced 1-click intelligent threat detection rule optimization (`POST /api/v1/siem/mitre/optimize-devices`) both in the MITRE ATT&CK matrix modal and the SIEM operations header. Automatically maps registered network firewalls (Fortinet, WatchGuard, Cisco), servers, and directory controllers to relevant tactical threat objectives, activating tailored rules and silencing irrelevant false positives.
  - **Certificate-Gated HTTP-to-HTTPS Redirection**: Fixed toggle payload parsing and enforced strict safety validation: HTTP-to-HTTPS redirection can only be enabled when a valid TLS certificate is active. Added automated prompt to enable redirection immediately upon self-signed certificate generation or custom certificate installation.
  - **TLS Certificate Display Harmonization**: Fixed attribute serialization and UI binding so generated self-signed and uploaded certificates display their Common Name, Issuer, expiry date, key parameters, and SANs directly in the Active TLS Certificate Details card.

- **v1.5.7** (Secure Web HTTPS, SSL/TLS Governance, FQDN Routing & 60% RAM Result Acceleration):
  - **Secure Web (HTTPS) & SSL/TLS Governance**: Native cryptographic HTTPS listener on port 8443 with atomic certificate hot-swapping (`tls.Config.GetCertificate`), dynamic toggle, and optional HTTP-to-HTTPS automatic redirection without interrupting log ingestion or health probes.
  - **1-Click Self-Signed Certificate Generator & Custom CA Upload**: Built-in 2048-bit RSA X.509 v3 certificate generator with automatic SAN inclusion (FQDN, host IPs, localhost) alongside enterprise CA / PEM certificate & private key upload and `.crt` download capability.
  - **Fully Qualified Domain Name (FQDN) Access Control**: Host header enforcement and automatic raw IP-to-FQDN redirection for enterprise SOC URL canonicalization.
  - **In-Memory Query Acceleration (Up to 60% Available RAM)**: Dynamic RAM budget detection and thread-safe LRU/TTL result cache utilizing up to 60% of available host memory, integrated with Go runtime `debug.SetMemoryLimit` for sub-millisecond repeated search queries with zero ClickHouse disk I/O.

- **v1.5.6** (Automated SIEM Correlation & Detection Catalog Rule Synchronization on Matrix Updates):
  - **Automated Rule Synchronization Pipeline**: Extended the MITRE ATT&CK update pipeline (`AutoAddMitreCorrelationRules`) to automatically map and inject related SIEM Correlation & Detection Catalog Rules directly into the active rule set on every matrix update (manual feed sync, air-gapped STIX import, automatic background release checks, and server startup self-healing).
  - **Curated Catalog & Dynamic Generator Hybrid Integration**: Automatically matches techniques against curated rules from `internal/siem/catalog` (e.g. AUTH-001, SSH-002, HEALTH-006) and falls back to dynamic tactical objective generation for newly discovered techniques, ensuring immediate active detection coverage without manual administrator intervention.
  - **Live Correlation Engine Hot-Reload**: Automatically hot-reloads the active in-memory correlation engine (`h.pipeline.GetSIEMEngine()`) and commits rules to PostgreSQL atomically without interrupting incoming log ingestion streams.

- **v1.5.5** (Official MITRE ATT&CK Matrix 697-Technique Installation & Interactive Matrix Rule Toggling):
  - **Full MITRE ATT&CK Enterprise Catalog Rule Generator**: Auto-generates high-fidelity SIEM detection rules for all 697 techniques in the official MITRE Enterprise ATT&CK catalog (`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`), automatically mapping tactical objectives, custom thresholds, severity levels, and risk scoring.
  - **Interactive Matrix Technique Toggling**: Clicking any technique card within the ATT&CK matrix modal directly activates or deactivates its corresponding detection rule in real time, updating the in-memory correlation engine and PostgreSQL state without disrupting event ingestion.
  - **Bulk Installation & Operations Controls**: Added `Install All Rules`, `Enable All`, and `Disable All` administrative action buttons in the MITRE ATT&CK dashboard view for 1-click comprehensive threat matrix enablement.

- **v1.5.4** (Zero-Allocation Batch Ingestion & Lock-Free Atomic Device Cache Optimization):
  - **ClickHouse Batch Ingestion Zero-Allocation Pipeline**: Pre-allocated and cached the parameterized `INSERT INTO` query template at client initialization, eliminating runtime `fmt.Sprintf` overhead during batch flushes. Reused internal micro-batch slice capacity via `batch = batch[:0]` and introduced static fallback IPv4 representations to minimize garbage collection cycles under high EPS loads.
  - **Lock-Free Atomic Device Cache**: Transitioned `DeviceCache` to `atomic.Pointer[deviceMaps]`, eliminating read/write mutex lock contention (`sync.RWMutex`) across concurrent worker ingestion routines and providing instantaneous wait-free IP resolution.
  - **CHANGES.md Audit Compliance**: Documented Phase 2 security hardening, zero-trust perimeter ingestion filtering, database isolation, and high-concurrency ingestion benchmarks in `CHANGES.md`.

- **v1.5.3** (Admin MFA Reset Payload Alignment & Parameter Harmonization):
  - **MFA Admin Reset Multi-Payload Parser**: Updated `handleMFAAdminResetAPI` to accept target user identification from both URL query parameters (`?id=...` and `?user_id=...`) and JSON request bodies (`{"user_id": ...}` and `{"id": ...}`). Updated client-side `resetUserMFA` to pass both parameters simultaneously with pre-validation, eliminating the `user id required` error when resetting MFA for operator accounts.

- **v1.5.2** (MFA Verification Route Alignment & Payload Harmonization):
  - **MFA Activation Endpoint & Payload Alignment**: Registered `/api/v1/auth/mfa/verify-enable` alongside `/api/v1/auth/mfa/verify` to eliminate 404 responses. Updated client-side activation to submit the active Base32 secret key, code, and recovery codes bundle, and added safe non-JSON response parsing to prevent unexpected JSON.parse parse exceptions.

- **v1.5.1** (MFA Enrollment QR Code Rendering Fix):
  - **MFA QR Code Dual Key Compatibility**: Resolved a property key mismatch between backend JSON serialization (`qr_code_base64`) and client-side setup modal receiver (`qr_png_base64`). Setup package now provides dual field serialization and the UI handles both keys seamlessly, ensuring instant, crisp QR code rendering for scanning into Microsoft Authenticator, Google Authenticator, WatchGuard AuthPoint, and FortiAuthenticator.

- **v1.5.0** (Active Directory / LDAP Integration, Universal Multi-Factor Authentication (MFA), & SMTP Email Dispatcher):
  - **Active Directory / LDAP Directory Integration**: Native LDAP/LDAPS client (`internal/auth/ad`) supporting Microsoft Active Directory and OpenLDAP. Features automated domain user discovery, preview scanner (`POST /api/v1/auth/ad/preview`), 1-click batch user synchronization into PostgreSQL (`POST /api/v1/auth/ad/sync`), direct LDAP credential bind authentication with auto-provisioning, StartTLS, LDAPS (port 636), and flexible LDAP attribute mapping (`sAMAccountName`, `mail`).
  - **Universal RFC 6238 Multi-Factor Authentication (MFA)**: High-assurance Time-Based One-Time Password (TOTP) engine (`internal/auth/mfa`) verified and certified with **Microsoft Authenticator**, **Google Authenticator**, **WatchGuard AuthPoint**, and **FortiAuthenticator / FortiToken**. Supports Base64 QR code generation, secret key manual entry, 8 emergency single-use backup recovery codes, 5-minute expiring MFA login challenge tickets, admin MFA reset/clear overrides, and optional or enforced system-wide MFA policies.
  - **SMTP Mail Server & Alert Task Dispatcher**: Enterprise email notification client (`internal/notification/smtp`) supporting Plain (port 25), STARTTLS (port 587), and SSL/TLS (port 465). Features immediate asynchronous email dispatch to designated security analysts when SIEM alerts/tasks are assigned to them (`POST /api/v1/siem/alerts/:id/status`), emergency broadcast alerts to SOC teams on CRITICAL detections, rich dark-mode responsive HTML email templates with severity badges and direct SIEM hyperlinks, and diagnostics test email tooling (`POST /api/v1/smtp/test`).
  - **Enhanced Operator Management UI**: Expanded Operator Accounts table with Auth Source (`🏢 Active Directory` vs `👤 Local DB`) and MFA Status (`🔐 Active (TOTP)` vs `Disabled`) badges, 1-click AD Sync modal, user MFA enrollment modal, and interactive analyst autocomplete for incident task assignments.

- **v1.4.3** (Telemetry Card Event Handler & Pointer Pass-Through Optimization):
  - **Universal Event Binding**: Added direct DOM event listeners (`addEventListener`), global window exports (`window.openCPUDetailsModal`), and keyboard shortcut handlers (`Escape` key modal dismissal) ensuring 100% reliable telemetry detail popup triggering across all browser engines.
  - **Canvas Pointer Pass-Through**: Applied `pointer-events: none` to telemetry graph canvases, ensuring clicks on chart graphics reliably bubble up to open CPU and Network detail modals.

- **v1.4.2** (Interactive Per-CPU Core Topology & Network Interface Statistics Modals):
  - **Per-CPU Core Topology Modal**: Clicking the CPU Utilization card opens a dedicated modal displaying real-time per-core utilization meters, worker thread vs reserved OS management core roles, total host CPU load, and `GOMAXPROCS` status.
  - **Network Interface Statistics Modal**: Clicking the Network Throughput card opens a modal showing per-interface bandwidth rates (KB/s and MB/s), packet rates (Packets/sec), cumulative Rx/Tx packet and byte counters, and drop/error statistics across all host network adapters.
  - **Live 2-Second Telemetry Sync**: Modal viewports automatically sync live telemetry every 2 seconds without requiring manual refreshes.

- **v1.4.1** (Dynamic Management Core Reservation & Build Thread Throttling):
  - **Host OS & Management Interface Protection**: Implemented automated core reservation (`configureCPUCoreReservation`) dynamically setting `GOMAXPROCS = NumCPU - 1` whenever `NumCPU > 1`. This guarantees at least 1 dedicated CPU core remains free for Host OS, SSH management, and critical web interface handling, preventing 100% CPU lockouts under heavy system load or log ingestion spikes.
  - **Build Core Throttling**: Added `GOMAXPROCS` environment exports to `upgrade.sh` so container compilation (`docker compose build`) leaves 1 logical CPU core available for system administration tasks.
  - **Telemetry Dashboard Indicator**: Updated CPU Telemetry panel (`web/static/js/app.js`) to display an active status badge whenever core reservation is enforced.

- **v1.4.0** (SIEM Alert Lifecycle Deduplication & In-Place Event Aggregation):
  - **Single Active Incident Record per Threat Entity**: Resolved an issue where continuous network scanning or brute force attacks generated duplicate alert rows every 30 seconds. The correlation engine now checks for an existing active (`NEW` or `IN_PROGRESS`) alert for the same Rule ID and Source IP / Entity. Subsequent matching logs directly increment `EventCount`, update `LastSeen` timestamp, append evidence log snippets, and refresh the summary in place.
  - **Restart-Resilient Active Bucket State**: The engine restores existing active alerts from PostgreSQL (`GetActiveSIEMAlertByRuleAndGroup`) upon startup, ensuring SIEM restarts do not fragment open security incidents.
  - **Optimized Database Indexing**: Added `idx_siem_alerts_rule_status` for sub-millisecond lookup of active alert records.

- **v1.3.9** (Persistent MITRE ATT&CK Catalog & Automatic Release Activation):
  - **Synced Catalog Survives Restarts/Upgrades**: The official STIX catalog was held only in memory, so every restart or web upgrade silently reverted the matrix to the 30-technique embedded baseline. The parsed catalog is now persisted in PostgreSQL (`mitre_catalog_cache`, ~430 KB) and restored at startup.
  - **Automatic New-Release Activation**: A background watcher checks the official feed (first check ~45 s after start, then every 24 h) with a conditional ETag request — unchanged feeds cost a `304`, new ATT&CK releases are downloaded, parsed and activated without operator action. Techniques introduced by a new release are flagged **NEW** with a release banner. Toggle in the matrix modal or via `MITRE_AUTO_SYNC=false`; tune with `MITRE_SYNC_INTERVAL_HOURS` and `MITRE_STIX_URL` (internal mirror for air-gapped sites). API: `GET/POST /api/v1/siem/mitre/autosync`.
  - **Dynamic Tactics & Full Catalog**: Tactics are read from the STIX `x-mitre-tactic`/`x-mitre-matrix` objects instead of a hard-coded list (ATT&CK v19 adds *Defense Impairment* TA0112 and renames Defense Evasion to *Stealth*). Techniques are placed under **every** tactic they belong to, sub-techniques carry their parent name, and the ATT&CK version is shown. Verified: v19.2 → 15 tactics, 222 techniques + 475 sub-techniques.
  - **Accurate Coverage Counts**: Alert attribution aggregates all alerts per technique in SQL (previously only the latest 200), and a data race in coverage report generation was fixed. New index `idx_siem_alerts_technique`.
  - **Matrix UI**: Filters (All / Covered / Uncovered / With Alerts / New), search, sub-technique toggle, collapsible tactics, watcher status and “Check for New Release” button. Manual sync timeout raised to 5 minutes.

- **v1.3.8** (Severity-Aware FortiGate IPS Triage):
  - **IPS Signature Severity Honoured**: FortiGate IPS events are now graded by the FortiGuard signature `severity` field. Blocked `info`/`low` signatures (commodity internet scanners such as `ZGrab.Scanner`, Masscan, Nmap probes) normalize to `threat / ips-recon-blocked` (LOW, risk 15, MITRE `T1595` Active Scanning) instead of raising a P1 `PERIM-004` incident. `medium` signatures map to `intrusion-blocked` / `intrusion-detected`; `high`/`critical` (or unspecified) still escalate to `intrusion-high-priority`.
  - **Allowed High-Severity Intrusions Now Alert**: `PERIM-004` previously required `outcome=blocked`, so a critical signature passed by a monitor-mode IPS sensor raised nothing. It now fires on both blocked and detected outcomes (risk 95 when not blocked).
  - **Attack Context Retained**: IPS `attack` name and `attackid` are carried into the normalized event for analyst triage.

- **v1.3.7** (Fortinet UTM False Positive Elimination, Category-Indexed SIEM Engine & High-Throughput CPU Optimization):
  - **Fortinet UTM Accurate Subtype Normalization**: Overhauled FortiOS UTM normalization to precisely differentiate Application Control (`subtype="app-ctrl"`), Web Filtering (`subtype="webfilter"`), DNS Filtering (`subtype="dns"`), and true threats (`subtype="ips"`, `subtype="virus"`, `subtype="waf"`). Benign permitted traffic (`action="pass"`, `action="passthrough"`, `eventtype="ftgd_allow"`, or FortiGuard encrypted SSL classification `apprisk="elevated"` / `apprisk="medium"`) is accurately mapped to `network` / `app-control-allowed` or `web-filter-allowed` with informational severity, eliminating false-positive triggers for `PERIM-004` (High-priority intrusion event).
  - **Category-Indexed Correlation Engine & Fast-Path Bypass**: Re-architected `Engine.Evaluate` to index detection rules by `MatchCategory`, bypassing rule iterations entirely for standard permitted network traffic (<5ns execution). Reduced evaluation overhead from 72 sequential rule checks to zero for benign flows.
  - **Decoupled Asynchronous SIEM Pipeline Buffer**: Separated SIEM evaluation from syslog socket ingestion workers into a dedicated ring buffer queue (`siemQueue`), preventing SIEM mutex lock contention from blocking the 16 pipeline socket workers.
  - **PostgreSQL Device Metadata Write Cooldown**: Introduced an in-memory 30-second cooldown per IP for `UpdateDeviceLastSeen` and `RecordUnregisteredSource`, slashing per-packet database writes and goroutine allocations by over 99%.
  - **ClickHouse Dashboard Telemetry Caching & Partition Pruning**: Added in-memory 10-second caching for dashboard log count and storage stats, optimized `logs_today` query to prune ClickHouse parts directly by month partition, and relaxed UI telemetry polling from 2s to 5s to eliminate storage query thrashing.
- **v1.3.6** (Real-Time Export & Sealing Progress Terminal, Background Job Engine & Zero-Drop Streamers):
  - **Live Server Activity Terminal & Progress Tracking**: Integrated real-time stage badges, percentage progress meters, and glowing terminal consoles inside the Custom Date & Time Range Log Export & Seal modal (`#custom-export-modal`), streaming every backend operation in real-time.
  - **Asynchronous Export Job Manager**: Offloaded long-running multi-range log extractions and sealing into decoupled background goroutines (`POST /api/v1/archives/export-custom/start`), eliminating 60s HTTP request aborts and preventing browser hangs on large datasets (100k+ logs).
  - **Server-Sent Events (SSE) Live Feed**: Added `/api/v1/archives/export-custom/progress` SSE stream broadcasting granular stage transitions (`INITIALIZING`, `QUERYING`, `EXTRACTING`, `STREAMING`, `HASHING`, `STAMPING`, `PACKAGING`, `REGISTERING`, `COMPLETED`), record counts, and timestamped console output with automatic proxy keep-alives.
  - **HTTP Write-Timeout Zero-Drop Streaming**: Configured `write_timeout: 0s` and per-connection `http.ResponseController.SetWriteDeadline` across all streaming and archive download handlers, preventing connection severance during multi-minute queries and multi-gigabyte bundle transfers.
  - **Instant Post-Seal Auto-Download**: Automatically initiates the browser file download upon task completion while displaying full cryptographic audit metadata (record counts, file size, SHA-256 hash, KamuSM RFC 3161 evidence status) and one-click re-download options.
- **v1.3.5** (Fortinet Traffic Actions Normalization & Clean API 401 Session Handling):
  - **Fortinet Session Teardown & Close Normalization**: Expanded `normalizeFortinet` to natively recognize FortiOS traffic session outcomes `client-rst`, `server-rst`, `close`, `timeout`, and `ip-conn`, accurately normalizing them to `network / connection-allowed` and preventing unclassified network events.
  - **Embedded Device Name Attribution**: Extracts `devname` from Fortinet syslog payloads (e.g. `devname="FGT-1"`) into `NormalizedEvent.DeviceName`.
  - **Quote-Aware Key-Value Scanner**: Rewrote `parseKeyValuePairs` tokenizer to properly handle quoted values with spaces (e.g. complex policy names, attack descriptions).
  - **API 401 Unauthorized Guard**: Guaranteed that all `/api/` endpoints strictly return JSON 401 (`{"error":"unauthorized"}`) rather than HTTP 303 redirects to HTML `/login`, eliminating `JSON.parse` syntax errors when sessions expire.
  - **Seamless Client Session Re-Authentication**: Added proactive 401 interception across all SOC dashboard async fetch handlers to cleanly redirect expired sessions to `/login`.
- **v1.3.4** (Categorized 72-Rule SIEM Detection Catalog & Multi-Domain Correlation):
  - **Categorized 72-Rule SIEM Detection Catalog**: Implemented complete enterprise detection catalog across 12 distinct operational and threat domains: Authentication (`AUTH-001`–`006`), Privilege & AD (`PRIV-001`–`006`), Switch & Router Administration (`NETADM-001`–`006`), Firewall & Perimeter (`PERIM-001`–`006`), Network Reconnaissance (`NET-001`–`006`), Windows Execution (`WIN-001`–`006`), Linux Privilege (`LIN-001`–`006`), Cloud Identity (`CLOUD-001`–`006`), Email & Web Apps (`MAILWEB-001`–`006`), Data Theft & Ransomware (`DATA-001`–`006`), Defense Evasion (`DEF-001`–`006`), and Logger Health & Integrity (`HEALTH-001`–`006`).
  - **Priority & Upstream Source Attribution**: Every rule enriched with implementation urgency priority (`P1` baseline vs `P2` historical/enriched) and upstream reference citations (Splunk Security Content, Microsoft Sentinel, Google Cloud Operations / YARA-L, and Original Logger Controls).
  - **Dynamic MITRE ATT&CK® Hierarchy Mapping**: Comprehensive defensive linkage across all 14 tactics with recursive sub-technique prefix matching (e.g. `T1110.003` -> `T1110`) and automatic dynamic technique discovery.
  - **Interactive SOC Rules Catalog Modal**: Upgraded rules viewer with live multi-field search, 12-category dropdown filter, priority filter (`P1`/`P2`), priority badge styling, and one-click rule activation toggles.
  - **Schema & Persistence Migrations**: Idempotent PostgreSQL schema expansion with `priority` and `source_ref` columns, and automatic 72-rule catalog synchronization on startup.
- **v1.3.3** (Device Type & Vendor Auto-Discovery Engine):
  - **Automated Deep Asset Fingerprinting**: Real-time inspection engine analyzing incoming syslog event patterns, RFC headers, hostnames, and application signatures to automatically detect both device vendor (Fortinet, WatchGuard, Cisco, Palo Alto, MikroTik, pfSense, OPNsense, HPE Aruba, Juniper, Sophos, Check Point, Ubiquiti, Linux, Windows, VMware) and device type (Firewall, Switch, Router, Server, Wireless Controller, Access Point, VPN Gateway).
  - **Asset Cataloging & Confidence Rating**: Automatically extracts hostnames, tags confidence ratings (`HIGH`, `MEDIUM`, `LOW`), and saves metadata to PostgreSQL `unregistered_sources` without dropping or delaying in-flight log ingestion.
  - **1-Click Discovered Asset Onboarding**: Pre-populates vendor, device type, network tier group, and hostname inside `#device-modal` for rapid single-device onboarding.
  - **Bulk Onboarding Action (`⚡ Auto-Onboard All Discovered Assets`)**: 1-click batch onboarding converting all discovered network senders into registered inventory assets simultaneously with automated naming conventions.
  - **Retrospective Log Analysis (`🔍 Detect`)**: On-demand device type detection for existing registered devices by querying their latest ClickHouse historical logs via `POST /api/v1/devices/auto-detect`.
- **v1.3.2** (Automated FIFO Storage Reclaim & Dynamic Listener Management):
  - **Bounded Live Stream (Last 15 Logs)**: Restructured live websocket stream and buffer to strictly retain only the last 15 receiving events, preventing browser memory exhaustion and high-volume clutter while preserving instant visibility of incoming traffic.
  - **Dynamic Syslog Network Listeners & Hot-Reload**: Ability to configure and change UDP, TCP, and TLS bind IP addresses and port numbers directly from the Web UI Settings panel with zero-downtime socket hot-reload without container restarts.
  - **Automated FIFO Storage Reclaim Cleaner**: Configurable disk usage threshold percentage (e.g. 85%) with background continuous monitoring every 30 seconds. When disk utilization reaches or exceeds the threshold, the system automatically purges the chronologically oldest ClickHouse partition or oldest 24h log batch via FIFO, ensuring zero missed or dropped incoming logs due to storage exhaustion.
  - **Dashboard Automation**: Removed manual prune button from dashboard and replaced with real-time automated FIFO status indicator and threshold telemetry.
- **v1.3.1** (Zero Data Loss Optimization & MITRE ATT&CK Sync):
  - **Zero Data Loss Database Persistence & Optimization**: Configured `stop_grace_period: 30s` across all containers ensuring in-flight ClickHouse batch queues and PostgreSQL WAL checkpoints flush cleanly before restart. Tuned PostgreSQL server parameters (`shared_buffers=256MB`, `work_mem=16MB`, `wal_buffers=16MB`, `max_connections=200`).
  - **Automated Pre-Upgrade Snapshots**: `upgrade.sh` automatically creates compressed PostgreSQL database backups (`./backups/postgres_backup_YYYYMMDD_HHMMSS.sql.gz`) with 5-snapshot retention prior to code pull or container rebuild.
  - **MITRE ATT&CK® Catalog & Synchronization Engine**: Built-in Enterprise ATT&CK v15.1 catalog with online STIX 2.1 JSON parser (`POST /api/v1/siem/mitre/sync`) and air-gapped offline file sync capability.
  - **SOC ATT&CK Matrix Visualizer Modal**: Interactive Web UI viewer displaying real-time defensive coverage across all 14 tactics, monitored technique IDs, rule mappings, and live incident attribution.
  - **Complete Technical Architecture Documentation**: Published detailed `docs/ARCHITECTURE.md` and `docs/MITRE_ATTACK_GUIDE.md`.
- **v1.3.0** (Phase 5 - Enterprise SIEM Evolution):
  - **SIEM Normalization Engine**: Universal standardizer normalizing Fortinet FortiGate, WatchGuard Firebox, Cisco ASA/IOS, Linux Auth/SSH/Sudo, and Windows Syslog into Common Event Model (`event.category`, `event.action`, `source.ip`, `destination.ip`, `user.name`, `severity`, `risk_score`, MITRE ATT&CK mapping).
  - **Real-Time Correlation & Detection Engine**: Sliding window bucket evaluator with out-of-the-box detection rules (Brute Force `AUTH-001`, Password Spraying `AUTH-002`, Port Scan `NET-001`, Firewall Denial Flood `NET-002`, Privilege Escalation `SYS-001`, Persistence Account Creation `SYS-002`, Threat/Malware Exploit Blocked `THREAT-001`).
  - **Security Operations Center (SOC) Web Dashboard**: Dedicated SOC navigation pane with Threat Scoreboard, Threat Risk Index, Top Attacker IPs, Top Targeted Users & Assets, and MITRE ATT&CK matrix tactics breakdown.
  - **Incident Case Management & Forensic Evidence**: Incident triage workflow (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`), assignment tracking, analyst case notes history, and raw forensic log evidence viewer.
  - **Interactive Rule Management & Simulation Engine**: Dynamic rule toggling and 1-click test simulation triggers for rapid SOC validation.
  - **Live WebSocket Alert Stream**: Real-time push notifications of critical security incidents to connected SOC analysts.
- **v1.2.4**:
  - Web UI system upgrade live progress modal with real-time SSE event streaming, percentage progress bar, and terminal activity console.
  - Automatic countdown dashboard reloader upon upgrade completion.
- **v1.2.3**:
  - Full Turkish documentation (`README.tr.md`) synchronized with all telemetry, host networking, dynamic CPU scaling, and upgrade features.
- **v1.2.2**:
  - Dynamic kernel CPU core detection (`/sys/devices/system/cpu/online` and `/proc/stat`) supporting live CPU hot-plugging without process restart.
  - Automatic `GOMAXPROCS` runtime auto-tuning upon CPU allocation expansion.
- **v1.2.1**:
  - Real-time CPU, RAM, EPS, and Network throughput 2x2 telemetry graphs with stable non-collapsing scaling.
  - Container host networking mode with dual-port listening (514 & 5514) to preserve authentic device client IPs.
  - Super Admin web-based system upgrade and Git synchronization manager with automated CLI upgrade script (`upgrade.sh`).
  - Dynamic runtime version detection and synchronization across dashboard and API.
- **v1.1.0**:
  - Admin password reset modal and API endpoint (`POST /api/v1/users/reset-password`).
  - Direct download links for archive bundles (`.zip`), compressed logs (`.gz`), and evidence tokens (`.zd`).
  - Purged unknown sources immediately upon device onboarding and fixed group tier persistence.
  - Added Zero-Trust syslog ingestion security policy (Permissive vs Strict Authorized Devices Only) with dropped packet telemetry.
- **v1.0.1**: Initial release with TÜBİTAK KamuSM / Internal dual timestamping engine, WatchGuard parser, and ClickHouse vectorized store.

