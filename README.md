# Valtrivo LogSeal
### Merkezi Log Yönetimi ve Zaman Damgalama
> **“Her kayıt, zamanıyla kanıt.”**  
> Developed by **Valtrivo**

An enterprise-grade, high-throughput centralized log management, analytics, and cryptographic evidence retention platform built with **Go**, **ClickHouse**, **PostgreSQL**, and **Vanilla HTML5/CSS/JavaScript**.

Engineered specifically for network and enterprise security infrastructure, high-volume log aggregation, and compliance workflows including **Turkish Law No. 5651**, **Law No. 5070**, and **TÜBİTAK KamuSM Zaman Damgası** requirements.

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

## Quickstart with Docker Desktop

### 1. Start the Platform
```bash
docker compose up -d
```
This boots ClickHouse, PostgreSQL, and the Go application.
- **Strict Network Isolation**: ClickHouse (ports `8123`/`9000`) and PostgreSQL (port `5432`) have **no published host ports** and can only be accessed internally by `syslog-app`.
- **Public Entrypoints**: Only `syslog-app` exposes ports to the host:
  - Port `8080`: Web Dashboard & REST API
  - Port `514` & `5514`: Syslog UDP/TCP listeners

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

## Release History

- **v1.1.0**:
  - Admin password reset modal and API endpoint (`POST /api/v1/users/reset-password`).
  - Direct download links for archive bundles (`.zip`), compressed logs (`.gz`), and evidence tokens (`.zd`).
  - Purged unknown sources immediately upon device onboarding and fixed group tier persistence.
  - Added Zero-Trust syslog ingestion security policy (Permissive vs Strict Authorized Devices Only) with dropped packet telemetry.
- **v1.0.1**: Initial release with TÜBİTAK KamuSM / Internal dual timestamping engine, WatchGuard parser, and ClickHouse vectorized store.

