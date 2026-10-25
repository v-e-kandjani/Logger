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
- ⚙️ [**Production Resource Profiles & Sizing Guide**](docs/operations/resource-profiles.md) — Hardware profiles (500 to 20,000 EPS), memory ledgers, cgroup slicing, and capacity worksheets.
- 📋 [**Operations & Disaster Recovery Runbook**](docs/operations/recovery-runbook.md) — Incident escalation matrix, node failure recovery, WAN spool replay, and offline RFC 3161 audit verification.
- 🧪 [**Acceptance Test Results & Certification**](docs/validation/acceptance-results.md) — 10 validation scenarios, SLO benchmark results, and production sign-off.
- 🛡️ [**MITRE ATT&CK® Integration & Synchronization Guide**](docs/MITRE_ATTACK_GUIDE.md) — Adversary tactic taxonomy, multi-vendor log normalization, and online/air-gapped STIX 2.1 synchronization.
- 🌐 [**Network Architecture & Port Specifications**](docs/PORT_SPECIFICATIONS.md) — Complete port matrix, database loopback isolation (PostgreSQL 5432 & ClickHouse 8123/9000), edge proxy daemon WAN egress, and firewall setup.
- 🚀 [**Upgrade & Zero-Data-Loss Maintenance Guide**](UPGRADE.md) — 1-click web upgrades, automated pre-upgrade database snapshots, and rollback instructions.

- **v1.9.16** (2 New Theme Palettes - Solar Amber & Deep Nebula with Full Dark & Light Modes):
  - **Solar Amber (Cyber Gold) Theme Palette (`amber`)**:
    - High-visibility warm amber-gold theme inspired by classic CRT security monitors and aerospace cyber telemetry.
    - Dark mode: deep obsidian charcoal (`#0c0d12`), slate cards (`#141721`), and glowing golden amber accents (`#f59e0b`).
    - Light mode: crisp warm ivory (`#fffdf5`), clean cards (`#ffffff`), soft amber tints (`#fef3c7`), and deep espresso-sepia typography (`#451a03`).
  - **Deep Nebula (Velvet Violet) Theme Palette (`nebula`)**:
    - Futuristic interstellar purple-indigo theme designed for next-generation threat intelligence and SOC monitoring.
    - Dark mode: abyssal violet midnight (`#090814`), velvet indigo cards (`#121026`), and electric neon amethyst accents (`#a855f7`).
    - Light mode: porcelain lavender (`#faf5ff`), clean white cards (`#ffffff`), and rich royal violet typography (`#2e1065`).
  - **Theme System Integration**:
    - Added dedicated theme cards and swatch previews to the `#pane-appearance` theme selector.
    - Registered palettes in `tokens.css`, `dashboard.css`, `app.js`, and multi-lingual dictionary tables.

- **v1.9.15** (Law 5651 Single-Archive On-Demand Sealing & Robust API Error Handling, EDR Netmon Browser False-Positive Prevention):
  - **Single-Archive On-Demand Reconcile (`POST /api/v1/archives/reconcile?id=<uuid>`)**:
    - Enhanced `ReconcileArchiveByID` to target individual pending log archives directly from the table row action button (`🔄 Seal Now`), providing instant feedback without triggering timeouts or processing the entire pending batch.
    - Updated `handleReconcileArchives` to strictly return JSON in all error and success states (`Content-Type: application/json`), eliminating plain-text responses.
    - Hardened UI `reconcileArchives(archiveId)` in `app.js` with content-type sniffing and fallback HTTP error extraction to prevent `JSON.parse: unexpected character at line 1 column 1` exceptions.
  - **EDR Network Threat Engine False-Positive Refinement (`agent/internal/netmon/netmon.go`)**:
    - Refined periodic C2 beaconing detection heuristic to exempt persistent TCP keep-alive sockets established by standard web browsers (`chrome.exe`, `msedge.exe`, `firefox.exe`, `brave.exe`, `opera.exe`) and OS system services (`svchost.exe`, `system`) communicating over standard web/push notification ports (`80`, `443`, `5228`, `8443`).

- **v1.9.14** (Law 5651 Forensic Archive Pending Resolution, Distributed Lease Recovery & Adaptive Auto-Fallback):
  - **Archive Lease Recovery & Resilience Engine (`ClaimNextArchiveJob` / `internal/database/postgres/postgres.go`)**:
    - Expanded distributed job lease recovery predicate to automatically reclaim orphaned jobs in `TSA_PENDING` and `SEALED` states when lease expires (`lease_until < NOW()`), preventing background sealing tasks from remaining stuck after service restarts or network timeouts.
    - Added retry safety bounds (`attempts < 5`) to prevent poisoned jobs from perpetually re-executing.
  - **Deterministic Evidence Sealer Graceful Fallback (`internal/archive/sealer.go`)**:
    - Integrated automatic fallback to `AdaptiveTimestampProvider` (Internal Cryptographic HMAC-SHA256 Authority) when TÜBİTAK Zamane KS encounters network timeouts, missing credentials, or subprocess failures.
    - Ensured `UpdateArchiveTimestamp` explicitly writes `timestamp_evidence_path` and `timestamp_status = 'VERIFIED'` to PostgreSQL, resolving the blank evidence token path that caused archives to display as "Pending".
  - **Automated Pending Reconciliation & On-Demand Re-stamping (`POST /api/v1/archives/reconcile` / `#pane-archives`)**:
    - Added `ReconcilePendingArchives` background worker in `ArchiveEngine` scanning for and stamping any unfinalized archives older than 1 minute.
    - Added **🔄 Bekleyenleri Mühürle / Reconcile Pending** action button to the Archives table header and per-row re-stamp buttons for immediate self-service administrative remediation.

- **v1.9.13** (Theme & Appearance Selector, 2 New Simple & Modern Palettes - Obsidian Mint & Nordic Frost, Agent Upgrade Fix & In-Place Replacement) / **Agent v0.1.12**:
  - **System & Administration Theme Selector (`#nav-tab-appearance` / `#pane-appearance`)**:
    - Added dedicated **Theme & Appearance** menu item under the System & Administration sidebar navigation group.
    - Integrated visual Theme Palette cards with live swatches and instant zero-reload theme switching.
    - Added Display Mode selector: Dark Mode (🌙), Light Mode (☀️), and System Auto Mode (💻) tracking OS `prefers-color-scheme` changes.
    - Added live interactive Component Preview sandbox demonstrating real-time metric tiles, status badges, and sample buttons.
  - **2 New Simple & Modern Themes**:
    - **Obsidian Mint (Cyber Emerald)**: Pitch obsidian background (`#090d16`), dark slate cards (`#0f1624`), electric emerald green accents (`#10b981`), and high-clarity mint typography.
    - **Nordic Frost (Polar Sky)**: Cool Scandinavian polar slate (`#111827`), icy glacier surfaces (`#1e293b`), and vibrant sky blue accents (`#38bdf8`) for an airy, hyper-legible modern cloud aesthetic.
  - **Agent Auto-Upgrade & In-Place Binary Replacement Fix (`v0.1.12`)**:
    - Resolved `ETXTBSY (Text file busy)` error on Linux/Unix by safely unlinking/renaming executing binary to `.old` before atomic replacement across filesystems and mounts.
    - Replaced hardcoded `"v0.1.4"` target version in `endpoint.go` and `endpoint_routes.go` with dynamic `version.LatestAgentVersion` and semantic `IsAgentVersionNewer` validation, preventing downgrade loops.
    - Added dual service & standalone daemon restart fallbacks across Linux (`systemctl` / direct respawn), macOS (`launchctl` / respawn), and Windows (`net stop/start` / launch).
    - Recompiled and published native agent standalone binaries (`linux-amd64`, `linux-arm64`, `windows-amd64.exe`, `darwin-universal`) to `web/static/bin/`.

- **v1.9.12** (Honeypot Decoy Shield Configuration, Anti-Ransomware Tuning, Fleet-Wide Canary Re-arming & Clean Menu UI):
  - **Honeypot & Anti-Ransomware Shield Configuration (`#modal-honeypot-config`)**:
    - Added dedicated administrator configuration modal and REST endpoints (`GET` and `POST` on `/api/v1/endpoint/ransomware/config`).
    - Configurable tripwire protection: Canary Files Decoy Plugin toggle, Shannon Entropy Anomaly Plugin toggle, and Autonomous Rogue Process Containment toggle.
    - Mathematical Shannon entropy sensitivity slider (`5.0` to `8.0` bits/byte, default `7.20`) for granular precision against modern ransomware encryption ciphers.
    - Proactive Containment Action Modes: Proactive Kill & Isolate, Alert & Quarantine Binary Only, or Monitor & Audit Only (Dry-Run).
    - Decoy formats selection (`.docx`, `.xlsx`, `.pdf`, `.sql`, `.key`), custom canary directory override, and automatic re-arm interval scheduling (`10m`, `30m`, `1h`, `4h`, `24h`).
    - Fleet-Wide Immediate Arming (`POST /api/v1/endpoint/ransomware/arm`): Triggers canary file planting and tripwire sensor synchronizations across all registered endpoint agents.
  - **Streamlined Navigation**:
    - Omitted leading icon before the "Ransomware & Canaries" sidebar menu item for visual simplicity and clean aesthetics across both English and Turkish interfaces.
  - **Database Persistence**:
    - Created `endpoint_honeypot_config` table in PostgreSQL with multi-tenant isolation, default configuration seeding, and atomic UPSERT queries.

- **v1.9.11** (LogSeal SIEM Design Tokens, Dark & Light Mode Theme Engine & Offline Component Demo):
  - **Reusable SIEM Design Tokens (`tokens.css`)**:
    - Established core design token system (`--ls-font`, `--ls-mono`, `--ls-space-1` to `--ls-space-6`, `--ls-radius`, `--ls-shadow`, `--ls-sidebar-width`).
    - Configured professional security color palettes for both `[data-theme="dark"]` and `[data-theme="light"]`: deep navy (`#0f172a`), slate (`#1e293b`), teal (`#42c5d2` / `#087f8c`), crisp text (`#f1f5f9` / `#1e293b`), and accessible semantic severity accents.
  - **Dynamic Theme Engine & Guarded Storage**:
    - Implemented guarded persistent storage (`logseal-theme`) with automatic OS system preference fallback (`prefers-color-scheme: dark`).
    - Added interactive Dark / Light Mode toggle in the top-bar (`#theme-toggle`) with animated SVG moon/sun indicators.
    - Integrated early document bootstrap avoiding flash of unstyled content (FOUC) and dynamic system theme change listeners.
  - **Standalone Offline SIEM Theme Demo (`/static/theme-demo/`)**:
    - Created four standalone files: `tokens.css`, `theme.css`, `index.html`, and `demo.js`.
    - Features responsive mobile navigation at 900px, single-column metrics at 560px, combined event search & severity filtering, empty state with filter reset, severity badges, and dismissible alert banners.
    - Added direct navigation link in sidebar under Support & Help (`#nav-tab-theme-demo`).

- **v1.9.10** (Collapsible & Foldable Sidebar Navigation Groups, Persistent State & Accessibility):
  - **Accordion Foldable Sidebar Navigation Groups**:
    - Converted all 6 primary navigation groups into independently collapsible accordion sections:
      1. **Monitoring & Logs** (`#nav-sec-monitoring`: Dashboard, Live Stream, Log Search)
      2. **Security & Threats** (`#nav-sec-security`: SIEM & SOC, Endpoint Security, SIEM & SOC Reports)
      3. **Asset Inventory** (`#nav-sec-assets`: Registered Devices, Unknown Sources)
      4. **Compliance & Legal** (`#nav-sec-compliance`: Archives & Legal Evidence - 5651)
      5. **System & Administration** (`#nav-sec-system`: System Health, Users & Access, Settings & KamuSM, System Upgrade)
      6. **Support & Help** (`#nav-sec-support`: Help & Guides, Support & Diagnostics)
    - Integrated smooth CSS height & opacity transitions (`cubic-bezier(0.4, 0, 0.2, 1)`) with interactive rotating chevrons.
    - **Local State Persistence**: Folded/unfolded states are saved in `localStorage` (`sidebar_foldable_sections`) across page reloads.
    - **Context-Aware Auto-Expansion**: Navigating to any tab (via URL hash, direct link, or programmatic switch) automatically expands its parent section group so the active tab is never hidden.
    - **Keyboard & Accessibility Support**: Full `role="button"`, `tabindex="0"`, `aria-expanded`, and keyboard Enter/Space activation support.
    - **Localization-Safe DOM Structure**: Isolated title text in dedicated `<span class="nav-section-title">` to ensure dynamic i18n switches preserve chevron SVGs.

- **v1.9.9** (Anti-Ransomware Shield, Decoy Canary Defense, Reports Tenant Isolation & Web Asset Optimization) / **Agent v0.1.11**:
  - **Phase P: Anti-Ransomware Shield & Decoy Honeypot Defense**:
    - **Shannon Entropy Engine**: Implemented mathematical entropy analyzer ($H(X) = -\sum P(x) \log_2 P(x)$) calculating random byte dispersion to identify rapid ransomware encryption patterns (LockBit, BlackCat, Akira) in real-time.
    - **Canary Honeypot Tripwires**: Deployed hidden decoy office documents (`.docx`, `.xlsx`, `.pdf`) across user directories with cryptographic SHA-256 baseline verification, triggering high-priority tripwires upon unauthorized modification or overwrite attempts.
    - **Autonomous Rogue Process Termination**: Added proactive containment terminating malicious ransomware process trees and PIDs (`taskkill` / `kill -9`) upon honeypot tripping or entropy spikes, paired with secure quarantine isolation vaults (`/var/logseal/quarantine`).
    - **SIEM & SOC Ingestion Pipeline**: Created `/api/agent/v1/ransomware` ingestion with automated `EDR-RANSOMWARE-DETECTED` SIEM correlation alert generation, alongside operator query APIs and simulation test harnesses.
    - **Ransomware UI Dashboard**: Integrated dedicated subtab `#endpoint-sec-ransomware` with 4 KPI metrics (Incidents, Armed Canaries, Tripwires Triggered, Terminated Processes), real-time active decoy table, and ransomware incident audit ledger.
  - **Reports Scope Lock & Tenant Isolation**:
    - Strictly decoupled SIEM & SOC Report generation from dynamic sidebar tenant switching, enforcing immutable root `Default` tenant scoping across telemetry and PDF/Excel exports.
    - Added dedicated Report Language Override selector (`report-language-select`) and comprehensive bilingual dictionaries in `translations.js` (`reports_*`).
  - **Web Performance & Asset Modularization**:
    - Integrated gzip response compression middleware (`gzipMiddleware`) with public asset caching headers (`Cache-Control: public, max-age=86400`), reducing dashboard wire transfer sizes from ~1.4 MB to ~200 KB (~7x speedup).
    - Modularized core styles into componentized stylesheets (`components.css`, `endpoint.css`, `reports.css`) with font preloading tags in HTML `<head>`.

- **v1.9.8** (Remote Microsoft Patching Orchestration, Fleet-Wide Remote Patch Console & Structured Sidebar Navigation):
  - **Microsoft Remote Patch Deployment & Seeding**:
    - Seeded real-world critical Microsoft security updates (`KB5034441` BitLocker/WinRE Bypass, `KB5035853` Kerberos/Hyper-V RCE, `KB5036893` Security Rollup, `KB5037768` DWM Privilege Escalation) for Windows endpoints with CVE correlation (`CVE-2024-20666`, `CVE-2024-21408`, etc.) as remediable missing patches.
    - Enhanced agent `executePatchInstall` with native Windows Update Agent (WUA) COM session automation (`Microsoft.Update.Session`), downloading and installing updates via the OS update engine with fallback to `Install-WindowsUpdate` and `winget`.
    - Added dedicated **Remote Patch Modal** (`#modal-remote-patch`) and **Remote Patch Button** (`⚡ Uzaktan Yama Yükle`) in the patch toolbar and table rows, enabling administrators to remotely deploy Microsoft security KBs to any connected endpoint with optional reboot scheduling.
    - Updated patch inventory ingestion (`SaveAgentInventory`) with conflict resolution preserving missing updates while transitioning completed remediations to installed.
  - **Structured & Ordered Sidebar Navigation**:
    - Reorganized the navigation menu into 6 intuitive, role-based categories:
      1. **Monitoring & Logs** (Dashboard, Live Stream, Log Search)
      2. **Security & Threats** (SIEM & SOC, Endpoint Security, SIEM & SOC Reports)
      3. **Asset Inventory** (Registered Devices, Unknown Sources)
      4. **Compliance & Legal** (Archives & Legal Evidence - 5651)
      5. **System & Administration** (System Health, Users & Access, Settings & KamuSM, System Upgrade)
      6. **Support & Help** (Help & Guides, Support & Diagnostics)
    - Added clean uppercase section titles (`.nav-section-title`) with full bilingual localization (`nav_sec_*`).

- **v1.9.7** (Universal Modal Architecture Repair, EDR Behavioral Tree Inspection & Cross-Module UI Hardening):
  - **Modal DOM Hierarchy & Visibility Bugfix**:
    - Fixed unclosed modal div tags in `index.html` that previously trapped all subsequent modals (`#modal-edr-detail`, `#modal-fim-detail`, `#modal-soar-exec-detail`, `#modal-network-simulate`, `#modal-network-firewall-rules`) inside `#modal-endpoint-active-response` which had `display: none;`, preventing "Inspect" and detail buttons from opening modals.
    - Synchronized all modal open/close functions in `app.js` to toggle both `.classList.add('active')` / `.classList.remove('active')` and `style.display = 'flex'` / `style.display = 'none'`, honoring `.modal-backdrop.active { display: flex !important; }`.
    - Implemented universal backdrop click dismissal across all `.modal-backdrop` containers.
  - **EDR & Security Inspection Hardening**:
    - Added dedicated single-anomaly REST endpoint `GET /api/v1/endpoint/edr/anomalies/{id}` and Postgres database method `GetProcessAnomaly`.
    - Hardened `openEDRDetail` with case-insensitive ID lookup, API fallback query, safe string method callers (`(a.severity || 'medium').toUpperCase()`), and comprehensive `try...catch` error handling with user toasts.
    - Localized all Inspect button labels across EDR, FIM, SOAR, and Endpoint views (`btn_inspect`, `btn_inspect_detail`).

- **v1.9.6** (Endpoint Patch Management Metadata Enrichment & UI Translation Scope Hardening) / **Agent v0.1.10**:
  - **Patch Metadata & Title/Vendor Population**:
    - Enhanced Windows patch collector (`collect_windows.go`) to query `Description`, `HotFixID`, and `InstalledOn` via WMIC and PowerShell `Get-HotFix`.
    - Added automated server-side title and vendor inference in `endpoint_cve.go` (`Security & Quality Update (KB...)` and `Microsoft Corporation`).
    - Added database backfill migration for existing patch records in `endpoint_patches_current`.
    - Enhanced patch UI table in `app.js` with fallback logic preventing empty title and vendor columns.
  - **Web Dashboard & Network Security Stability**:
    - Fixed `ReferenceError: t is not defined` in Network & DNS Security views by declaring global and scoped translation helpers `window.t`.

- **v1.9.5** (Endpoint Network Traffic, DNS Exfiltration Protection & Micro-Segmentation - Phase O) / **Agent v0.1.9**:
  - **Native Cross-Platform Network Telemetry & DNS Auditing (Agent v0.1.9)**:
    - High-performance socket enumeration and process PID correlation across Linux (`ss -tuanp`), macOS (`lsof -i -P -n`), and Windows (`netstat -ano`).
    - Algorithmic C2 Beaconing Detection: Outbound connection timing and interval jitter analysis (standard deviation thresholding) detecting regular heartbeats to external destinations.
    - Suspicious Ports & LOLBin Outbound Blocking: Detects scripts/binaries (`powershell.exe`, `cmd.exe`, `bash`, `python`) connecting to non-standard or prohibited ports (`4444`, `1337`, `6667`, `8888`, `31337`).
    - DNS Query Auditing & Shannon Entropy DGA Engine: Evaluates domain information entropy ($H(X) \ge 3.75$ / consonant density $\ge 0.80$) to detect algorithmic DGA domains and DNS exfiltration tunnels.
    - Autonomous Host Firewall Enforcement: Local micro-isolation and packet dropping via native OS firewall commands (Windows `netsh advfirewall`, Linux `iptables`, macOS `pfctl`).
  - **PostgreSQL Relational Schema & SIEM Correlation**:
    - Relational tables `endpoint_network_connections`, `endpoint_dns_queries`, and `endpoint_firewall_rules` with multi-tenant isolation.
    - SIEM alert dispatch for `EDR-NET-THREAT` (MITRE `T1071.001`) and `EDR-DGA-DNS` (MITRE `T1568.002`).
  - **Web Operations Dashboard & Host Micro-Isolation**:
    - Dedicated view (`#endpoint-sec-network`) with 5 KPI summary cards, socket connection stream, DNS queries log, 1-click IP isolation action, active firewall rules modal, and interactive attack simulator.

- **v1.9.4** (Behavioral Anomaly Detection & Malicious Script EDR - Phase N) / **Agent v0.1.8**:
  - **Native Cross-Platform EDR Subsystem (Agent v0.1.8)**:
    - High-performance, zero-fork process hierarchy tree discovery across Linux (`/proc`), macOS (`ps -A`), and Windows (`wmic` / `Get-CimInstance`).
    - Heuristic detection rules covering:
      - Office application child process spawning (`WINWORD`, `EXCEL`, `POWERPNT` launching `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe` - MITRE `T1204.002`).
      - Web server / Database server interactive shell execution (`w3wp`, `nginx`, `httpd`, `sqlservr`, `mysqld` spawning `/bin/sh`, `/bin/bash`, `powershell.exe` - MITRE `T1505.003`, `T1059.004`).
      - Living-off-the-Land Binaries (LOLBins) weaponization (`certutil -urlcache`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe /s /i:http` Squiblydoo, `bitsadmin.exe /transfer`).
      - Ransomware backup and recovery invalidation (`vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit ignoreallfailures` - MITRE `T1490`).
      - Obfuscated base64 PowerShell scripts (`-enc`, `FromBase64String`, `-w hidden`, `-ep bypass` - MITRE `T1027`, `T1059.001`).
      - In-memory download cradles (`Invoke-Expression` / `IEX` with `DownloadString`, Unix `curl | bash` / `wget | sh` pipes).
    - Autonomous Threat Neutralization: Agent immediately kills anomalous process trees when critical-severity threats are detected (`EDRKillOnCritical`).
  - **PostgreSQL EDR Relational Store & Deduplication**:
    - Relational table `endpoint_process_anomalies` with multi-tenant and agent time-indexed lookups.
    - Cascading deduplication integration in `MergeDuplicateAgents`.
  - **SIEM & MITRE ATT&CK Correlation**:
    - Direct alert ingestion dispatching `EDR-RULE-*` events with MITRE tactics and techniques to the real-time SIEM correlation engine.
  - **Web Operations Dashboard & Process Tree Visualizer**:
    - Dedicated EDR dashboard view (`#endpoint-sec-edr`) with 5 KPI summary cards, filter bar, interactive process tree modal (`#modal-edr-detail`), 1-click remote process kill action, and synthetic attack simulation button (`/api/v1/endpoint/edr/simulate`).
    - Full English & Turkish localization with dynamic language switching support.

- **v1.9.3** (USB & Peripheral Storage DLP - Phase M) / **Agent v0.1.7**:
  - **Native Cross-Platform USB DLP Engine (Agent v0.1.7)**:
    - Real-time hardware discovery and differential event monitoring across Windows (`Win32_DiskDrive` / `Win32_PnPEntity`), Linux (`/sys/bus/usb/devices`), and macOS (`system_profiler SPUSBDataType`).
    - Tracks Vendor ID (VID), Product ID (PID), device manufacturer, product name, serial number, volume labels, mount points / drive letters, and disk capacity.
    - Differential event engine detecting `inserted`, `removed`, `blocked`, `write_denied`, and `unauthorized_whitelist` operations.
    - Enforces OS-level granular access policies:
      - `allow`: Audit and log storage connection and removal lifecycles.
      - `read_only`: Prohibits writes and exfiltration (Windows `StorageDevicePolicies` WriteProtect / Linux `mount -o remount,ro`).
      - `block`: Complete device suspension and dismount (Windows `USBSTOR` disablement / Linux sysfs `/authorized` revocation).
  - **Corporate Hardware Whitelist Management**:
    - Centralized hardware whitelist (`endpoint_usb_whitelist`) supporting VID:PID matching, individual Serial Number authorization, and approval justification notes.
    - Whitelist enforcement policy flag instantly blocking or alerting on unauthorized flash drives and external storage media.
  - **SIEM & MITRE ATT&CK Correlation**:
    - High-severity DLP alerts (`DLP-USB-VIOLATION`) automatically dispatched to the SIEM correlation engine, mapped to MITRE ATT&CK techniques `T1052.001` (Exfiltration Over Physical Medium) and `T1200` (Hardware Additions).
  - **Centralized DLP Operations Dashboard**:
    - Dedicated USB & Peripheral Control dashboard view (`#endpoint-sec-usb`) with 4 KPI summary cards (Total Discovered USB, Active Connected, Blocked Violations, Total DLP Events).
    - Subtabbed views for Connected & Historical Devices vs DLP Security Event Stream with quick 1-click whitelist authorization action.
    - Built-in simulation tool (`/api/v1/endpoint/usb/simulate`) for end-to-end audit validation.

- **v1.9.2** (Automated Duplicate Agent Consolidation & Inactive Instance Pruning):
  - **Automated Duplicate Agent De-Duplication & Data Merge Engine**:
    - Introduced `MergeDuplicateAgents` consolidating multiple agent records registered from the same physical/virtual host (`tenant_slug`, `hostname`, `ip_address`) due to agent reinstallations or UUID resets.
    - Seamlessly migrates all child records to the active agent: current inventory, installed software packages, vulnerability findings, missing OS patches, FIM cryptographic baselines, FIM tampering events, remote deployment tasks, and SOAR active mitigation executions.
    - Preserves historical fleet telemetry, earliest initial host enrollment timestamps (`created_at`), and lowest security health scores.
    - Automatically purges stale, disconnected, and orphaned agent records from the database.
  - **Proactive Re-Enrollment Deduplication Guard**:
    - Enhanced `UpsertEnrolledAgent` to detect existing hosts on re-enrollment, preventing the creation of duplicate rows and keeping the fleet inventory clean.
  - **Operational Web UI & REST API Controls**:
    - Added dedicated toolbar action button ("🧹 Mükerrer Ajanları Birleştir / Merge Duplicate Agents") in the Endpoint Agents management view.
    - Added `/api/v1/endpoint/agents/cleanup-duplicates` endpoint with comprehensive audit logging.

- **v1.9.1** (Windows Agent Service Resilience & FIM Event Simulation):
  - **Windows Service Registration Resilience (Fix for "The parameter is incorrect" / Error 87)**:
    - Updated Windows agent installation script (`install-agent.ps1`) and standalone setup wizard (`logger-agent-setup.exe`) to register services via native PowerShell `New-Service` and properly escaped `sc.exe` fallbacks, eliminating SCM command-line argument parsing and quote breakage.
    - Updated documentation and UI code snippets for manual service installation with foolproof commands for PowerShell and Command Prompt.
    - Added backwards-compatible JSON support for both `heartbeat_sec` and `heartbeat_interval_sec` in `config.json`.
  - **FIM Operational Simulation & Live Validation**:
    - Added `/api/v1/endpoint/fim/simulate` and UI action button allowing security operators to generate verifiable file tampering events and trace them across FIM, SIEM alerts, and SOAR mitigation playbooks.

- **v1.9.0** (File & Registry Integrity Monitoring - FIM - Phase L & Endpoint Data Enrichment) / **Agent v0.1.6**:
  - **Native Cross-Platform Cryptographic FIM Scanner (Phase L - Agent v0.1.6)**:
    - Integrated native Go cryptographic scanner calculating SHA-256 digests across critical operating system binaries (`/bin`, `/sbin`, `/usr/bin`, `C:\Windows\System32`), configurations (`/etc`, `/etc/pam.d`, `/etc/ssh`), and Windows Registry hives (`Run`, `RunOnce`, `Services`, `Image File Execution Options`).
    - Autonomous detection of `created`, `modified`, and `deleted` system files and registry keys with permission, owner, and file size delta tracking.
    - Automatic baseline tracking (`endpoint_fim_baselines`) and cryptographic deviation calculation submitted securely via `/api/agent/v1/fim`.
  - **SIEM & SOAR Threat Synergy (Zero-Day & Persistence Mitigation)**:
    - High & critical integrity deviations automatically enriched with MITRE ATT&CK techniques (`Persistence`, `Privilege Escalation`, `Defense Evasion`, `Impact`).
    - Direct dispatch to SIEM correlation engine creating instantaneous `endpoint_fim` security alerts.
    - Immediate SOAR automated playbook trigger capability: 1-click or autonomous host network isolation and forensics snapshot upon unauthorized binary modification or ransomware indicators.
  - **Centralized FIM Operations Dashboard**:
    - Dedicated FIM navigation view with KPI stat cards (Total Events, Critical Deviations, Monitored Baselines, Affected Endpoints).
    - Real-time deviation event stream with SHA-256 hash comparison (Old vs New), MITRE badges, and deep inspection modal.
    - Endpoint Cryptographic Baselines viewer displaying tracked file paths, verified hashes, sizes, and timestamps.
  - **Endpoint Security Table & Data Enrichment**:
    - Enriched Software Inventory, Vulnerabilities, and Patch Compliance tables to consistently display true Endpoint Hostname, IP address, and OS metadata.
    - Updated Endpoint Security Dashboard with live Top Vulnerable Endpoints and Top CVEs ranked by critical risk.
    - Real-time dynamic agent health status calculation derived from actual heartbeat staleness.

- **v1.8.9** (Automated SOAR Incident Response Playbooks & EDR Active Mitigation Suite - Phase K):
  - **Automated SIEM-to-EDR Playbook Engine (Phase K.1 & K.2)**:
    - Real-time event-driven incident mitigation engine bridging SIEM detection rules directly with cross-platform endpoint active response tasks.
    - Decoupled alert listener evaluating incoming correlation alerts against playbook trigger conditions (Severities, Minimum Risk Score, MITRE ATT&CK Tactics, and SIEM Categories).
    - Intelligent target endpoint resolution mapping syslog alerts to registered hostnames and IP addresses (`ip_address`).
    - Flapping and alert storm mitigation with configurable cooldown guards (e.g. 15-minute suppression window per host/playbook).
  - **Dual Autonomous & Analyst Approval Workflows**:
    - **Autonomous Mode**: Zero-touch, sub-second execution of containment actions upon critical threats (e.g. automated host isolation and process tree snapshots on ransomware behavior).
    - **Manual Approval Mode**: Suspicious activity stages a `PENDING_APPROVAL` case, notifying analysts within the incident triage view with 1-click "Approve & Execute" or "Reject".
  - **Out-of-the-Box Default Playbook Catalog**:
    - *Ransomware Rapid Network Containment*: Autonomous network isolation and forensic process snapshot upon detection of mass file encryption or defense evasion.
    - *Critical Brute-Force & Sockets Forensic Snapshot*: Automated live OSQuery probing of active listening sockets (`listening_ports`) and logged-in user sessions (`logged_in_users`).
    - *Suspicious Lateral Movement Host Containment*: Analyst-approved isolation and process inspection upon detection of lateral movement tools (PsExec, WMI, WinRM).
  - **SOAR Console & Forensic Step Inspector (Phase K.4)**:
    - Dedicated SOAR Playbooks console modal featuring an interactive playbook catalog, status toggles, visual playbook editor, and manual run dispatcher.
    - Step-by-step execution pipeline inspector displaying individual action durations (ms), command outputs, and step telemetry.
    - Deep SIEM incident investigation synergy: Matched endpoint badge, current isolation status, and 1-click active response directly from the incident investigation dialog.

- **v1.8.8** (Active Response, EDR Host Isolation & Live Forensic SQL / OSQuery) / **Agent v0.1.5**:
  - **EDR Network Containment & Host Isolation (Phase J.3)**:
    - Dynamic host containment cutting off all inbound and outbound network traffic while strictly preserving the secure LogSeal telemetry channel and loopback.
    - Native cross-platform firewall rule injection via `iptables` (Linux), `netsh advfirewall` (Windows), and `pfctl` (macOS).
    - Real-time containment indicators with pulsing amber/red `ISOLATED` badges across the fleet table and endpoint details modal.
    - Interactive "Isolate Host" and "Lift Isolation" actions with operator audit logging and reason tracking.
  - **Remote Process Termination & File Quarantine (Phase J.3)**:
    - Forceful remote process termination by PID or process name (`taskkill /F` on Windows, `kill -9` / `pkill -9` on Linux/macOS).
    - Suspicious file quarantine safely relocating malicious artifacts to isolated directories, calculating cryptographic SHA-256 digests, and stripping all execution rights (`chmod 000`).
    - Centralized Quarantined Files table tracking quarantined paths, hashes, file sizes, and containment timestamps.
  - **Live Forensic SQL & OSQuery Console (Phase J.4)**:
    - Real-time forensic SQL console allowing operators to query connected endpoints on-demand.
    - Dual-mode execution engine: utilizes native `osqueryi` when available, with built-in cross-platform probers for key tables (`listening_ports`, `processes`, `logged_in_users`, `system_info`).
    - Interactive query templates with configurable timeout guards (15s, 30s, 60s) and structured JSON/table result inspection.
  - **SIEM Alert Quick-Response Synergy**:
    - Direct containment integration from SIEM alert investigations, allowing analysts to instantly isolate compromised hosts during active incident triage.

- **v1.8.7** (Remote Patch Remediation & Fleet Action Dispatcher) / **Agent v0.1.4**:
  - **Automated Remote Patch Remediation (Phase J.2)**:
    - Interactive "Deploy Patch" actions added directly to the Patch Management console table for missing security updates.
    - Single patch deployment modal with target host telemetry, KB/Package ID preview, and optional automated reboot execution.
    - Fleet-Wide Batch Patch Remediation modal to deploy missing updates across hosts based on severity filters (Critical, High, or All).
  - **Asynchronous Task Queue & Execution Engine**:
    - Centralized `endpoint_tasks` and `endpoint_task_results` tracking for remote commands (patch install, system reboot, instant inventory scan).
    - Real-time task dispatching embedded directly in agent heartbeat responses (`resp.PendingTasks`), eliminating polling latency.
    - Native cross-platform execution handlers supporting Windows Update / PowerShell, Debian/Ubuntu `apt-get`, RHEL/CentOS/Rocky `dnf`/`yum`, SUSE `zypper`, and macOS `softwareupdate`.
  - **Remote Action History & Terminal Execution Log Viewer**:
    - Interactive "Deployment Tasks" modal allowing operators to monitor pending, running, completed, and failed remediation tasks across the fleet.
    - Built-in terminal log viewer inspecting real-time `stdout`, `stderr`, exit codes, and execution durations (ms).
  - **Safe Remote Host Reboot**:
    - Safe remote reboot actions with 30-second system warning notices for endpoints pending post-patch reboot.

- **v1.8.6** (Centralized Endpoint Policies & Real-Time Dynamic Heartbeat Push) / **Agent v0.1.3**:
  - **Centralized Endpoint Policies Console (Phase J.1)**:
    - Interactive policy management console (`#endpoint-sec-policies`) allowing administrators to define, edit, assign, and delete endpoint policies.
    - Summary telemetry cards tracking total policies, active default policies, governed fleet counts, and live zero-downtime push synchronization.
    - Granular controls over heartbeat intervals (5s - 3600s), software inventory frequencies, patch/vulnerability scan schedules, and update channels (`stable`, `beta`, `development`).
  - **Hardware Resource Throttling & Spool Queue Management**:
    - Centralized controls over maximum agent CPU utilization % and RAM memory ceiling (MB).
    - Configurable offline spool disk buffer limits (MB) and retention age (hours) to protect host storage during network disconnections.
    - Dynamic event log channel filtering (e.g. `System`, `Application`, `Security` on Windows; `syslog`, `auth`, `kern` on Linux).
  - **Real-Time Dynamic Heartbeat Push**:
    - The server calculates policy revision differentials during agent heartbeats and injects updated configurations directly into the response payload (`AgentHeartbeatResponse.Policy`).
    - The native agent daemon dynamically updates its operational parameters and resets internal tickers on-the-fly (`ticker.Reset`), achieving instant policy application without service restarts.
  - **One-Click Fleet Policy Assignment**:
    - Quick "📋 Assign Policy" action directly in the Agents table to quickly switch policies for individual endpoints or entire fleets.
    - Multi-tenant MSSP data isolation preserving strict tenant security perimeters.

- **v1.8.5** (Endpoint Hardware Telemetry, Dynamic Health Scoring, Patch Management & Seamless In-Place Auto-Updater) / **Agent v0.1.3** (Kernel Hardware Probers & Windows Service In-Place Upgrade Engine):
  - **Endpoint Hardware Utilization & Dynamic Health Scoring**:
    - Native kernel-level hardware telemetry probers across Windows (`GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW`, `GetSystemTimes`), Linux (`/proc/meminfo`, `/proc/stat`, `Statfs`), and macOS (`sysctl`, `Statfs`).
    - Gathers real-time CPU %, RAM usage (used/total/percent), Disk usage (used/total/percent), system uptime, and pending reboot status.
    - Dynamic host health score calculation (0-100) factoring in CPU/RAM/Disk saturation, reboot requirements, and unpatched critical CVE findings.
    - Visual utilization gauges and health badges (`🟢 Sağlıklı / 🟡 Dikkat / 🔴 Kritik`) in the Agents table and Agent Detail inspector modal.
  - **Full Patch Management Suite (Phase G)**:
    - Dedicated Patch Management UI (`#endpoint-sec-patches`) featuring patch compliance percentages, installed vs missing patch metrics, and pending reboot counters.
    - Host-level patch table with OS advisory identifiers, KB numbers, installation dates, and severity tags.
    - On-demand patch scan triggers via Web UI and REST API (`POST /api/v1/endpoint/patches/scan`).
  - **Connected Server In-Place Auto-Update (Phase H)**:
    - Native self-upgrade engine inside the agent daemon: heartbeat compares agent version with target version offered by the server.
    - Windows running binary replacement mechanism (atomic `.old` renaming and service restart via SCM).
    - Remote mass agent upgrade trigger via Web UI ("🚀 Tüm Ajanları Otomatik Güncelle") and REST API (`POST /api/v1/endpoint/agents/upgrade-all`).

- **v1.8.4** (Endpoint Software Inventory, Automated CVE Sync Scheduler & Vulnerability Correlation) / **Agent v0.1.2** (Registry/Package Scanner & Auto Inventory Telemetry):
  - **Endpoint Software & Hotfix Inventory Collection**:
    - Native cross-platform collector scanning installed software: Windows 64-bit and 32-bit registry uninstall keys, Linux package managers (`dpkg-query`, `rpm`), and macOS application bundles (`/Applications`).
    - Hotfix and patch enumeration (`wmic qfe` / `Get-HotFix`) capturing Windows KB patches, descriptions, and install timestamps.
    - Automated background transmission to `/api/agent/v1/inventory` on agent startup and recurring hourly interval.
  - **Automated CVE Database Intelligence & Scheduler**:
    - Built-in CISA KEV (Known Exploited Vulnerabilities) syncer fetching actively exploited CVEs + NIST enterprise security vulnerability feeds.
    - Configurable automated synchronization scheduler with 4 operational modes: **Every Day (`daily`)**, **Every Week (`weekly`)**, **Every Month (`monthly`)**, and **Manual (`manual`)**.
    - On-demand manual sync trigger via Web UI ("Şimdi Güncelle") and REST API (`POST /api/v1/endpoint/cve/sync`).
  - **Host Vulnerability Correlation Motor**:
    - Automatic correlation engine analyzing installed endpoint software against the CVE database.
    - Records detections into `endpoint_vulnerability_findings` with CVSS scoring, severity ranking (CRITICAL, HIGH, MEDIUM, LOW), and CISA KEV exploit tags.
    - Automatically refreshes host risk scores and dashboard security telemetry.
  - **Interactive Endpoint Security Web UI**:
    - **Vulnerabilities Tab (`#endpoint-sec-vulnerabilities`)**: Displays CVE catalog intelligence status (total CVEs, KEV count, last sync, next scheduled run), automated update schedule dropdown selector, manual sync trigger, severity filters, and real-time vulnerability table linking directly to NIST NVD.
    - **Software Inventory Tab (`#endpoint-sec-inventory`)**: Searchable host software inventory view with host filtering, publisher details, version tags, and package locations.

- **v1.8.3** (Endpoint Security Modal Dialog Visibility, Sub-Navigation Sync & pgx ErrNoRows Fixes) / **Agent v0.1.1** (Windows SCM Dispatcher & Comprehensive Uninstaller):
  - **LOGGER Agent v0.1.1 Hardening**:
    - **Windows Service Dispatcher (`golang.org/x/sys/windows/svc`)**: Native integration with Windows Service Control Manager (SCM), preventing service start timeouts and error 1053.
    - **Zero-Args Service Execution & Config Discovery**: The service starts cleanly without relying on fragile CLI arguments; automatically detects `config.json` next to the binary.
    - **Resilient Enrollment Retry Loop**: If initial network connectivity fails or the token is pending, the agent retries enrollment every 15s instead of terminating the Windows service.
    - **Multi-Mode Windows Uninstaller**:
      - One-click `uninstall.bat` generated directly inside `C:\Program Files\LOGGER Agent`.
      - Integrated silent/interactive uninstaller in `logger-agent-setup.exe -uninstall`.
      - Standalone remote PowerShell uninstaller (`uninstall-agent.ps1`) for remote IT management.
      - Full registration in Windows Add/Remove Programs (Registry).
  - **Endpoint Enrollment Token Modal & Dialog Fixes**:
    - Restored full modal dialog visibility for New Enrollment Token (`#modal-endpoint-new-token`), Agent Inspection (`#modal-endpoint-agent-detail`), and Token Quick Commands (`#modal-endpoint-token-install`) by standardizing on `.modal-backdrop` and explicit display flex/none management.
    - Added CSS fallback rules in `dashboard.css` for `.modal-overlay` and `.modal-backdrop.active` / `.modal-overlay.active`.
    - Implemented backdrop click auto-dismissal for all endpoint security modals.
  - **Sidebar Submenu & Sub-Section Navigation**:
    - Fixed sub-section synchronization when opening the Endpoint Security tab (`switchTab('endpoint')`) so active panes and subitems consistently sync.
    - Added missing global function alias `switchEndpointSubnav = switchEndpointSubSection`.
  - **Database Error Handling Hardening**:
    - Resolved pgx v5 `pgx.ErrNoRows` handling in `internal/database/postgres/endpoint.go` across token consumption, agent heartbeats, and agent detail lookups.

- **v1.8.2** (Native Windows .exe & macOS .dmg Standalone Agent Installers):
  - **Standalone Windows Installer (`logger-agent-setup.exe`)**:
    - Embedded native Go installer (`agent/cmd/installer-windows`) packaging `logger-agent.exe` into a single standalone executable.
    - Supports interactive prompts for Server URL & Token or headless silent switches (`-server`, `-token`, `-dir`, `-insecure`, `-silent`, `-uninstall`).
    - Creates `C:\Program Files\LOGGER Agent`, writes `config.json`, registers and starts the `LoggerAgent` Windows Service via Service Control Manager, configures automatic restart recovery, and registers into Windows Add/Remove Programs.
  - **Native macOS Disk Image (`LOGGER-Agent-Installer.dmg`) & Package (`.pkg`)**:
    - Universal binary compilation (`arm64` Apple Silicon M1-M4 + `x86_64` Intel) packaged into an official Apple disk image via `hdiutil`.
    - Includes `Install LOGGER Agent.pkg` (Apple Installer package), `Install LOGGER Agent.command` (interactive Terminal wizard), `Uninstall LOGGER Agent.command`, and launchd daemon configuration.
  - **Dashboard 1-Click Installer Downloads**:
    - Integrated direct download buttons into the quick 3-step setup card, the full installation guide, and the token creation modal.
    - Automated multi-platform build pipeline (`scripts/build-agent-installers.sh`) for reproducing installers and binaries.

- **v1.8.1** (Interactive 3-Step Endpoint Installation Guide & Decoupled Native Agent Versioning):
  - **Quick Step-by-Step Installation UI**:
    - Added interactive 3-step setup banner (`#ep-quick-step-card`) directly above the Agents table with live platform toggles for Windows, macOS, and Linux.
    - Dynamically generates one-liner deployment commands injected with the active enrollment token and central server address.
    - Provides instant terminal copy shortcuts, privilege prerequisites (Admin/Root), and endpoint verification commands (`Get-Service LoggerAgent`, `launchctl`, `systemctl`).
  - **Standalone Native Agent Versioning**:
    - Decoupled `logger-agent` semantic versioning (`v0.1.0`) with independent build date and commit SHA tracking under `agent/internal/version/version.go`.
    - Added CLI version inspection flags (`-version`, `-v`) and User-Agent telemetry (`LOGGER-Agent/vX.Y.Z`).
  - **Production Endpoint Installers & Manuals**:
    - Released official bash installer `install-agent.sh` for Linux (systemd) / macOS (launchd) and PowerShell installer `install-agent.ps1` for Windows services.
    - Published official documentation manuals `docs/AGENT_INSTALLATION.md` and `docs/AGENT_INSTALLATION.tr.md`.

- **v1.8.0** (Endpoint Security Subsystem & Cross-Platform LOGGER Agent - Phase A):
  - **Cross-Platform LOGGER Agent Daemon**:
    - Introduced standalone, lightweight native agent daemon (`agent/cmd/logger-agent`) with stable UUID generation, persistent host fingerprinting, outbound HTTPS/HTTP2 transport, and jittered heartbeat scheduling.
  - **Secure Self-Enrollment & Token Engine**:
    - Designed `endpoint_enrollment_tokens` with cryptographic SHA-256 token hashing (`lp_ea_...`), maximum usage limits, single-use enforcement, platform restrictions (Linux, Windows, macOS), and TTL expiration.
  - **Dual-Engine Schema Migrations**:
    - Implemented PostgreSQL migration `003_endpoint_security.sql` with auto-migration (`EnsureEndpointSchema`) covering agents, groups, policies, inventory, software, CVE intelligence, active findings, patches, and tasks.
    - Implemented ClickHouse migration `004_endpoint_telemetry.sql` for high-throughput time-series endpoint events and agent resource metrics.
  - **Unified "Endpoint Security" UI & Dashboard**:
    - Built dedicated top-level sidebar module with submenus for Overview Dashboard, Agents, Asset Inventory, Vulnerability CVEs, Patches, Policies, and Deployment Tokens.
    - Added interactive stat cards, high-risk host matrices, agent inspection drawer, quick deployment one-liners, and bilingual localization (TR/EN).

- **v1.7.9** (CLI Automated Upgrade Build-Arg Sanitization & Dockerfile Hardening):
  - **Single-Line Version Extraction Fix in `upgrade.sh`**:
    - Resolved a critical bug where multi-line `grep` output from `internal/version/version.go` injected trailing newlines into `--build-arg VERSION=...`, causing `/bin/sh` syntax parsing failures (exit code 1) in Dockerfile line 21 during CLI updates.
    - Added resilient single-line string sanitization (`head -n1 | tr -d '\r\n'`) across `upgrade.sh`, `install_standalone.sh`, and `scripts/install_standalone.sh`.
  - **Dockerfile Build-Arg Hardening**:
    - Hardened `Dockerfile` stage 1 build step to sanitize all incoming build args (`COMMIT_SHA`, `VERSION`, `BUILD_DATE`) prior to evaluating shell conditionals and compiling Go binaries.

- **v1.7.8** (Rich Markdown Documentation Viewer & Table Rendering Engine):
  - **Offline-First Markdown Parser & Typography Engine**:
    - Vendored lightweight, offline-compatible `marked.min.js` (v15.0.12) to ensure 100% air-gapped on-premise SIEM documentation rendering without external CDN dependencies.
    - Designed full Markdown typography system featuring `Plus Jakarta Sans` for body text, `JetBrains Mono` for code blocks, optimized line heights (`line-height: 1.75`), paragraph margins, blockquotes, and hierarchical heading border accents.
  - **Pixel-Perfect Responsive Table Rendering**:
    - Added automated `.table-responsive` wrapping for all Markdown tables with horizontal scrolling, elevated dark headers (`#111827`), cyan border dividers, zebra row striping (`rgba(255, 255, 255, 0.02)`), and hover highlights (`rgba(59, 130, 246, 0.08)`).
  - **Dual Document Viewing Experience (Modal & Standalone)**:
    - Integrated in-app `#modal-doc-viewer` allowing immediate in-dashboard documentation reading, one-click code copying, direct `.md` downloading, and "Open in New Tab" navigation.
    - Upgraded `/api/v1/docs/view` into a rich standalone document page complete with dark/light theme switching, print media styling (`window.print()`), and raw fallback (`?raw=true`).

- **v1.7.7** (Sidebar-Only Help Navigation, Direct Markdown Document Downloads & Multi-Tenant Branding Logo Customization):
  - **Direct Markdown Documentation Download & Inline View Endpoints**:
    - Implemented secure documentation endpoints (`/api/v1/docs/download` and `/api/v1/docs/view`) with sanitized filename resolution to reliably serve and download Markdown guides (`STANDALONE_INSTALL.md`, `PORT_SPECIFICATIONS.md`, `HELP.md`, `MITRE_ATTACK_GUIDE.md`, etc.) with `Content-Disposition: attachment`.
  - **Dedicated Sidebar Help Navigation Pane**:
    - Relocated the Help section exclusively into the primary sidebar menu (`#nav-tab-help`), eliminating redundant top-bar header buttons.
    - Added dedicated `#pane-help` view featuring direct Markdown download cards, full dual-engine network port matrices, database loopback isolation specs, edge proxy NAT traversal guides, and one-click firewall commands.
  - **Multi-Tenant & Root Organization Branding Logo Upload**:
    - Added full branding logo customization in Settings > Tenants for all organizations, explicitly including the Root (`default`) tenant.
    - Built multipart logo upload API (`POST /api/v1/tenants/logo`), serving endpoint (`GET /api/v1/tenants/logo`), and default reset (`DELETE /api/v1/tenants/logo`).
    - Stored logos in persistent `data/branding/{slug}/` (backed by Docker volume `syslog_branding`) and updated database `tenants.logo_url`.
    - Integrated live logo preview modal, tenant table logo thumbnails, and dynamic sidebar branding logo synchronization upon active tenant switching.

- **v1.7.6** (Network Ports Modal Visibility Bugfix & Complete Bilingual Localization):
  - **Fixed Collapsed Section 1 & Section 2 Ingestion/Database Port Tables**:
    - Resolved WebKit/Chromium flex column layout bug where `.table-container` and `<pre>` elements with `overflow-x: auto` collapsed to 0 height inside `.modal-body` flexbox.
    - Set `#ports-help-modal .modal-body` to explicit `display: block`, ensuring standard block formatting context, full table visibility, explicit cell padding, responsive width (`min-width: 680px`), and clean scrollable tables.
    - Added multiline word-wrap to Section 4 firewall/service commands code block (`#ports-firewall-code-block`).
  - **Comprehensive Bilingual Localization (TR & EN) for Network Ports Guide**:
    - Added complete English and Turkish translation keys across the entire modal: subtitle, dual-engine security architecture alert, section titles, table column headers, port service descriptions, direction badges, proxy node ingress/egress cards, firewall action buttons, and documentation links.
    - Connected `openPortsHelpModal()` with `window.i18n.applyTranslations()` to guarantee instant reactive translation when switching between English (`🇬🇧 EN`) and Turkish (`🇹🇷 TR`).
  - **Updated Installers & Scripts Version References**:
    - Synced version strings to `v1.7.6` across `internal/version/version.go`, `upgrade.sh`, `install_standalone.sh`, and `scripts/install_standalone.sh`.

- **v1.7.5** (Unified Bare-Metal & Docker Support, Native Systemd Auto-Detection, Standalone Port Isolation & In-Place Self-Updates):
  - **Unified Dual-Architecture CLI Upgrade Engine (`upgrade.sh`)**:
    - Automatically detects whether the deployment is running under Docker Compose or Bare-Metal Linux (`syslog-platform.service` under systemd).
    - *Bare-Metal Upgrade Pipeline*: Automatically takes pre-upgrade native PostgreSQL backups (`pg_dump`), fetches latest code (`git pull origin main`), applies SQL migrations to native PostgreSQL & ClickHouse instances, writes runtime version metadata, runs `go mod download`, recompiles native Go binaries (`/opt/syslog-platform/bin/syslog-platform` and `logseal-proxy`) with embedded version ldflags, synchronizes assets and source files, and restarts `syslog-platform.service` with automated health check verification.
    - Supports manual override flags: `sudo bash upgrade.sh --baremetal` or `sudo bash upgrade.sh --docker`.
  - **Bare-Metal Web 1-Click Upgrade & Seamless Process Reload**:
    - Enhanced `handleSystemUpdateApply` in `internal/api/upgrade.go` to restart both `syslog-platform` (native systemd) and `syslog-app` (container) services, falling back to in-place `syscall.Exec` binary replacement.
  - **Enhanced Standalone Installer (`install_standalone.sh` & `scripts/install_standalone.sh`)**:
    - Generates and writes `config/.version_info` upon installation.
    - Copies source trees (`cmd/`, `internal/`, `migrations/`, `docs/`, `go.mod`, `go.sum`) into `/opt/syslog-platform/`, enabling seamless in-place `go build` and `go mod download` updates directly on bare-metal systems.
    - Compiles static binaries with embedded version tags and commit hashes.
  - **Bare-Metal Port Specifications & Security Documentation**:
    - Added comprehensive Bare-Metal sections to `docs/PORT_SPECIFICATIONS.md` and `docs/PORT_SPECIFICATIONS.tr.md`, detailing native PostgreSQL (`127.0.0.1:5432`) and ClickHouse (`127.0.0.1:9000/8123`) loopback binding configurations, UFW shielding, Linux `AmbientCapabilities=CAP_NET_BIND_SERVICE` for privileged port 514 binding without root, and dual `ss -tulpn` verification outputs.
    - Added Bare-Metal service management and troubleshooting guide to `docs/HELP.md` and `docs/HELP.tr.md`.
    - Added Bare-Metal systemd commands button and direct documentation links into the Web UI "Ports & Architecture Help" modal.

- **v1.7.4** (Update Parity Bug Fix, Dynamic Go Module Sync & Reload, UI Button Positioning & Port Specifications):
  - **Full Parity Between CLI and Web Upgrades**:
    - *CLI Update State Persistence*: Fixed issue where CLI upgrade (`upgrade.sh`) left the Web UI indicating an update was still required. `upgrade.sh` now synchronizes `config/.version_info` with the exact Git commit SHA, passes build args to Docker build, and injects runtime metadata.
    - *Web Update Dynamic Go Dependency & Binary Compilation*: Fixed issue where Web UI upgrades did not download updated Go modules or reload the application. Web upgrade engine now queries GitHub compare API for all modified files (including `go.mod`, `go.sum`, and Go source files), executes `go mod download`, recompiles the Go platform binary, and triggers graceful background application reload (`syscall.Exec` / Docker respawn) with automatic dashboard reconnection.
    - *Zero Discrepancy*: Standardized both upgrade workflows so both download Go libraries, compile binaries, and reload processes identically.
  - **System Upgrade UI Button Overlap Correction**:
    - Re-architected `.section-actions` in `dashboard.css` and `index.html` with responsive flexbox layout (`justify-content: space-between`, `flex-wrap: wrap`, `gap: 16px`), preventing the upgrade action buttons (`#btn-check-updates` and `#btn-apply-updates`) from overlapping title and subtitle text across all screen sizes.
  - **Network Architecture & Port Specifications Documentation**:
    - Created comprehensive documentation in `docs/PORT_SPECIFICATIONS.md` (and `docs/PORT_SPECIFICATIONS.tr.md`) covering Web UI (8080/8443), Syslog ingestion (514/5514/6514), PostgreSQL (5432 loopback), ClickHouse (8123/9000 loopback), and Edge Proxy egress (8443 HTTPS).
    - Created comprehensive Operations Help Guide in `docs/HELP.md` (and `docs/HELP.tr.md`).
    - Added interactive "Network Ports & Architecture Guide" modal in the Web UI accessible from the top bar.

- **v1.7.3** (Application-Selected Multi-Language Support for SIEM & SOC Reports):
  - **Dynamic Language Selection Synchronization**: Automatically detects and passes the active application language (`localStorage.getItem('logseal_lang')` / `window.i18n.currentLang`) to report generation endpoints (`/api/v1/reports/preview` & `/api/v1/reports/export?lang=...`).
  - **Full Bilingual Report Synthesis**:
    - Generates report titles, executive summaries, tactical MITRE defense mappings, threat intelligence IOC classifications, Law 5651 cryptographic evidence records, root cause findings, and remediation action plans in Turkish (`tr`) or English (`en`).
  - **Multi-Format Bilingual Exporters**:
    - *Forensic PDF*: Section headers, table columns, operational KPI labels ("MTTD (Tespit Süresi)", "5651 Mühürlendi"), classification notices, and pagination footers dynamically rendered with safe Unicode handling for standard PDF fonts.
    - *RFC 4180 CSV*: Metadata header comments, section blocks (`[YÖNETİCİ ÖZETİ...]`), and column labels localized.
    - *DOCX OpenXML*: Headings, table cells, and document properties fully localized.
    - *Plain-Text / Markdown*: Specialized English and Turkish templates for all 5 SOC report types.
    - *Live Web Preview*: Real-time UI inspection reflecting the selected platform language.

- **v1.7.2** (Root Global Update Access Control, 1st-Week Baseline Storage Runway & TÜBİTAK KamuSM Upstream Sync):
  - **Root Global Administrator Upgrade Restriction**: Restricted system update checks, git synchronization, and 1-click upgrades strictly to Root Super Administrators (`default` organization). Tenant users are barred with HTTP 403 Forbidden on the API layer and presented with an access restricted banner in the UI.
  - **Empirical 1st-Week Baseline Storage Runway Recalculation**:
    - Evaluates the earliest log timestamp across ClickHouse tables. If less than 7 days (1st week) have elapsed, reliably reports `"Estimated 365 Days (based on Archival & Retention Policies)"`.
    - Once >= 1 week of continuous telemetry is established, dynamically calculates the exact remaining days of storage by projecting the 1st week's average EPS, daily log count, compression ratio, and available disk headroom up to the FIFO threshold.
  - **Automated TÜBİTAK KamuSM TSS Client Version Check & Retrieval**:
    - Integrated upstream version checks against official TÜBİTAK KamuSM repository endpoints during the platform update workflow.
    - Automatically discovers newer `tss-client-console-*.jar` versions, safely downloads and verifies binary archives to `timestamp-client/`, and displays verified timestamp client status in the System Upgrade dashboard.

- **v1.7.1** (Forensic PDF A4 Landscape Layout & Column Alignment Optimization):
  - **A4 Landscape Re-Engineering (`pdf_exporter.go`)**: Switched PDF page orientation to A4 Landscape (297mm × 210mm) providing an expansive 269mm printable width for wide multi-column tables.
  - **Optimally Seated Forensic Tables**:
    - *MITRE ATT&CK & D3FEND Threat Matrix*: Expanded widths (Tactic 34mm, Technique 36mm, Technique Name 62mm, SIEM Detection Rule 92mm, D3FEND Counter 45mm), eliminating cramped column text truncation.
    - *Threat Intelligence & IOC Ledger*: Expanded indicator value column to 105mm, comfortably accommodating long URLs, SHA-256 hashes, and fully qualified domain names without overflow.
    - *Law 5651 Chain of Custody & Evidence Ledger*: Expanded SHA-256 digest column to 75mm and added full ISO timestamp formatting, providing audit-grade legibility for judicial review.
  - **Balanced Metric Alignment**: Re-proportioned Executive KPI cards across 269mm line width (65mm per card with 3mm gaps) with unified landscape page boundary checks (`ensurePageSpace`).

- **v1.7.0** (Multi-Tenant SIEM & SOC Reporting Engine & Dedicated Sidebar Workspace):
  - **Separated Sidebar Menu & Workspace (`#nav-tab-reports`)**: Dedicated reports module with interactive report template selector, live visual preview canvas, customizable timeframes, classification tags, and generation history ledger.
  - **5 Industry-Standard SOC & SIEM Templates**:
    1. *Executive Threat Landscape & Security Posture*: High-level CISO metrics, MTTD/MTTR KPIs, top targeted assets, and risk reduction posture.
    2. *Critical Incident Forensics & Root Cause Analysis (RCA)*: Deep-dive attack lifecycle, MITRE ATT&CK & D3FEND mappings, IOC intelligence, and corrective engineering directives.
    3. *SOC Operational & Shift Handover*: Analyst context continuity across shifts, sensor ingestion EPS health, and detection tuning notes.
    4. *Regulatory Compliance & Privileged Access Audit*: PCI-DSS v4.0, HIPAA, SOC 2, and Turkish Law No. 5651 compliance validation with privileged PAM inspection and KamuSM timestamp status.
    5. *Vulnerability & Attack Surface Exposure*: Active SIEM correlation against known CVEs and high-priority mitigation guidance.
  - **High-Fidelity Multi-Format Exporters**:
    - *Forensic PDF*: Vectorized A4 layout via `gofpdf`, custom tenant logo embedding with fallback protocol, KPI stat cards, and cryptographic chain-of-custody table.
    - *OpenXML DOCX*: Native ZIP archive builder injecting media assets and dynamic variable substitutions into `word/document.xml`.
    - *RFC 4180 CSV*: Streaming export with structured audit comment headers (`#`), IOCs, and Law No. 5651 evidence verification details.
    - *JSON & Plaintext*: Streamed structured JSON and pre-formatted text preview via Go `text/template`.
  - **Multi-Tenant White-Labeling & Governor Protection**: Per-tenant logo resolution with graceful system fallback, strict tenant scoping across PostgreSQL and ClickHouse, and integration with `Governor.CanAdmitReport()` to prevent OOM under memory pressure.

- **v1.6.9** (Phase 10 Sizing Profiles, Operational Runbooks & Acceptance Certification):
  - **Certified Sizing Profiles (`docs/operations/resource-profiles.md`)**: Formally certified 3 standalone hardware candidates (4 vCPU / 16 GiB @ 500 EPS, 16 vCPU / 64 GiB @ 5,000 EPS, 32 vCPU / 128 GiB @ 20,000 EPS) with complete whole-host memory ledgers ($R = O + C + E + D$), cgroups v2 slice templates (`siem-control.slice`, `siem-data.slice`), and storage sizing formulas.
  - **Disaster Recovery & Operations Runbook (`docs/operations/recovery-runbook.md`)**: Published step-by-step operational runbooks for sudden node/container crashes, WAN edge spool replay, TÜBİTAK KamuSM TSA outages, ClickHouse storage exhaustion, and offline Law 5651 bundle verification drills (`sha256sum` + `openssl ts -verify`).
  - **Acceptance Certification & SLO Compliance (`docs/validation/acceptance-results.md`)**: Documented passing results across all 10 required acceptance scenarios; verified local management API p95 < 250ms (measured 18ms), external SSH access under saturation < 2s (measured 1.1s), and hourly archive sealing window completion within 2 minutes.
  - **Comprehensive Development Gap Analysis & Progress Ledger**: Published `docs/development/logseal-gap-analysis.md` and `docs/development/logseal-progress.md` covering all 10 completed development phases.

- **v1.6.8** (Phase 9 Edge Proxy Hardening, Durable Replay & SaaS Scale-Out):
  - **Edge Forwarder Disk Spool Durability (`logseal-proxy v1.6.8`)**: Implemented periodic physical fsync commits (`Sync()`), total spool directory bounding (`max_spool_mb`), and crash recovery automatically scanning and draining pending offline spools upon startup.
  - **Paced WAN Replay with Jitter & Non-Destructive Failure Backoff**: Prevented thundering-herd spikes after WAN link recovery by introducing batch rate-limiting with randomized sleep jitter (50–150ms). Preserves spooled files on transmission errors to guarantee zero data loss.
  - **Distributed PostgreSQL Job Leases (`ClaimNextArchiveJob`)**: Implemented `FOR UPDATE SKIP LOCKED` distributed worker queue semantics with expiring leases (`lease_until`), enabling horizontal SaaS replicas to execute 5651 evidence sealing and maintenance without contention or duplicates.
  - **Multi-Tenant Hourly Evidence Sealing**: Expanded the hourly reconciliation engine to enumerate and schedule missing sealing windows for all active customer organizations (`ListTenants`).
  - **Overlapping Private IP Subnet Validation**: Verified multi-tenant lock-free `DeviceCache` composite lookups (`LookupIPAndTenant`), ensuring identical private customer subnets (e.g. `192.168.1.1` in Tenant A vs Tenant B) never cross-pollinate device records or correlation state.
  - **ClickHouse Cluster High-Availability Migration**: Introduced `003_replicated_cluster_template.sql` specifying `ReplicatedMergeTree` with ZooKeeper/Keeper cluster sharding and `Distributed` table routing templates.

- **v1.6.7** (Phase 8 Combined Resource Governor, Operator Views & Threat Simulation Access Control):
  - **Simulate Threat Root Super-Admin Role Restriction**: Restricted SOC threat attack simulation triggers exclusively to the Super Administrator of the root tenant (`default` organization). Enforced across backend (`handleSIEMSimulate` returns `403 Forbidden` for non-root or non-super-admin users) and UI (Simulate Threat button `#btn-open-siem-simulate` is hidden for all other users).
  - **Memory Token Semaphores & Cold Query Admission**: Implemented conservative 128 MB query memory tokens per query against a dedicated query token pool (25% of data plane memory) and `MemoryHigh` headroom, preventing cold-cache query spikes from provoking out-of-memory crashes.
  - **Aggressive Result Cache Eviction Under Resource Pressure**: Integrated automatic cache eviction (`cache.GetResultCache().EvictUnderPressure()`) triggered during `PRESSURE` and `CRITICAL` governor states to immediately reclaim memory and release heap pages back to the OS via `debug.FreeOSMemory()`.
  - **Step-by-Step Recovery Slot Restoration**: Enhanced governor recovery state machine with hysteresis to ramp up allowed search concurrency one slot at a time rather than sudden concurrency shocks.
  - **Holistic Operator Views Telemetry**: Exposed comprehensive operator view telemetry (`/api/v1/governor/status`) displaying physical memory ledger (Control Plane 2 GB, Data Plane current/max, Emergency reserve 1 GB, Query tokens in-use), ingestion queue runway time, loss packet counters, SIEM detection lag, TSA verification status, and RAM cache freshness.
  - **Unified Operations Dashboard Banner**: Upgraded the Cgroups v2 Resource Governor banner with a live Memory Ledger and Operator View telemetry strip in pure CSS3/HTML5.

- **v1.6.6** (Dynamic Tenant Data Retention & Storage Quotas with Automated ClickHouse Partition Dropping):
  - **Configurable Multi-Tenant Data Retention (`retention_days`)**: Granular per-tenant log retention policies allowing finite log life cycles (e.g. 30, 90, 180 days) while preserving indefinite storage (`retention_days = 0`) for root or compliance-mandated organizations.
  - **Storage Quota Enforcement (`max_storage_gb`)**: Real-time ClickHouse physical log volume tracking per tenant; automatically alerts on quota overflow and purges the oldest 24-hour log batch when customer tenants exceed designated storage limits.
  - **Automated ClickHouse Partition Dropping**: Zero-mutation, instant partition reclamation (`ALTER TABLE syslog_events DROP PARTITION 'YYYYMM'`) executed during retention pruning cycles when all active tenants allow pruning older historical months.
  - **Background Retention Worker (`StartTenantRetentionWorker`)**: Automated hourly lifecycle cleaner that evaluates per-tenant retention days, verifies storage limits, reclaims disk space, and records structured audit events (`TENANT_RETENTION_PRUNE`).
  - **Tenant Quotas & Retention Management UI**: Added `#modal-edit-tenant-quotas` modal for editing proxy nodes, EPS, retention, and storage limits anytime; enhanced Tenants table with storage utilization bars, retention badges, date boundaries, and on-demand manual pruning triggers (`/api/v1/tenants/prune`).

- **v1.6.5** (Zero-Trust API Key Authentication for Distributed Forwarders & Granular Audit Logging):
  - **Zero-Trust Edge Proxy Authentication**: Replaced plaintext token evaluation with cryptographically secure SHA-256 hashed lookups (`token_hash`) and masked prefix tracking (`token_prefix`), maintaining seamless backward compatibility with existing forwarders.
  - **Granular Source IP / CIDR Whitelisting**: Added per-node Zero-Trust network boundary verification (`AllowedCIDRs`), restricting proxy heartbeats and log batches strictly to authorized corporate IP subnets (e.g., `10.0.0.0/8, 192.168.1.50`) and dropping unauthorized attempts with `403 Forbidden`.
  - **Automated Key Expiration & Dynamic Key Rotation**: Introduced configurable API key lifetimes (`30d`, `90d`, `180d`, `365d`, or permanent) and dedicated 1-click token rotation endpoints (`/api/v1/settings/edge/nodes/rotate-key`) with instant revocation of compromised credentials.
  - **Comprehensive Security Audit Trail**: Enriched security event auditing with dedicated actions (`EDGE_NODE_CREATED`, `EDGE_NODE_ACTIVATED`, `EDGE_NODE_DELETED`, `EDGE_KEY_ROTATED`, `EDGE_INTERVAL_UPDATED`, `EDGE_CIDR_UPDATED`, `EDGE_AUTH_FAILURE`, `EDGE_AUTH_EXPIRED`, `EDGE_IP_BLOCKED`) fully indexed and searchable in the Audit Trail panel.
  - **Hardened Edge Forwarder Daemon & Management UI**: Upgraded `logseal-proxy` to v1.6.5; refreshed Settings Edge table with token security badges, key expiration countdowns, CIDR tags, and modal key rotation workflows.

- **v1.6.4** (Tenant-Scoped Ingestion Auto-Discovery & Network Device Category Enrichment):
  - **Per-Tenant Ingestion Policy (`permissive` vs `strict`)**: Configurable ingestion policy per tenant allowing either automated discovery of unknown senders or strict whitelist-only drop enforcement with zero lock-in for the `default` root organization.
  - **Lock-Free Multi-Tenant Device Resolution**: Enhanced in-memory `DeviceCache` with composite `(IP, TenantSlug)` routing and atomic policy retrieval, preventing cross-tenant IP collisions and unauthorized sender spoofing.
  - **Network Device Vendor & Category Enrichment**: Expanded automated fingerprinting with Huawei (VRP, CloudEngine, USG) and F5 Networks (BIG-IP ADC), auto-classifying assets across 5 distinct operational categories (`Perimeter Defense`, `Core & Distribution`, `Application Delivery & ADC`, `Access & Wireless`, `Datacenter Compute`).
  - **Auto-Discovered Senders UI & Policy Governance**: Upgraded `#pane-unregistered` and `#setting-section-tenants` with tenant badges, inline policy toggle switching, and tenant-aware 1-click batch onboarding.

- **v1.6.3** (Edge Node Heartbeats, Health Checks, Dead Man's Switch & Active Tenant-Level Quota Enforcer):
  - **Dynamic Edge Node Heartbeat Health Checks**: Replaced rigid timeouts with adaptive status calculation (`online` 🟢, `degraded` 🟡, `offline` 🔴, `pending` ⏳) keyed to configured sync intervals (`online`/30s, 60s, 5m, 15m, 30m, 1h).
  - **Dead Man's Switch Background Monitor**: Added automated edge forwarder health supervisor (`StartEdgeHealthMonitor`) executing every 30 seconds; automatically records audit trails and fires high-severity SIEM security alerts (`EDG-DEAD-MAN-001`) whenever an active node stops reporting.
  - **Real-Time Sliding Window Quota Enforcer (`internal/quota/enforcer.go`)**: Built dynamic tenant-level quota enforcement tracking rolling per-second ingestion rates (`MaxEPS`), verifying tenant status (`active` vs `suspended`), and maintaining fail-open DB resiliency while granting unlimited quota (`0 = ∞`) to the root `default` tenant.
  - **Hardened Edge Ingestion Pipeline**: Integrated quota checks into `/api/v1/edge/ingest` with `429 Too Many Requests` (burst limit exceeded) and `403 Forbidden` (suspended tenant/inactive node); enriched tenant settings with real-time quota utilization badges.

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

