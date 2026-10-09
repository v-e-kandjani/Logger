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
- 📖 **[Installation Guide (HOW_TO_INSTALL.md)](HOW_TO_INSTALL.md)**
- ⚡ **[Ubuntu Installer Script (install.sh)](install.sh)**

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

---

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

