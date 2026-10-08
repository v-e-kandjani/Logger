# Valtrivo LogSeal SIEM — System Architecture Specification
### Enterprise Log Management, Law No. 5651 Sealing & Security Operations Center (SOC) Platform

---

## 1. Executive Summary & Design Principles

**Valtrivo LogSeal** is an enterprise-grade platform uniting two mission-critical cybersecurity domains:
1. **Regulatory Compliance & Evidential Log Sealing:** Turnkey compliance with Turkish **Law No. 5651**, generating verifiable SHA-256 hash trees sealed with **TÜBİTAK KamuSM** (or internal RFC 3161) trusted timestamps.
2. **Real-Time SIEM & Security Operations Center (SOC):** In-memory multi-vendor normalization, sliding-window correlation, out-of-the-box detection rules, **MITRE ATT&CK®** mapping, and an analyst triage console with live incident streaming.

### Core Architectural Principles
* **Zero Log Loss:** Non-blocking ring buffer architecture, atomic buffer tracking, and graceful flush drains ensure zero dropped logs under burst conditions.
* **Separation of Concerns (Dual-Database):** 
  * **ClickHouse** handles extreme-scale, append-only analytical log queries (100,000+ EPS with ZSTD compression).
  * **PostgreSQL** handles ACID-compliant relational metadata: device inventory, user RBAC, SIEM detection rules, incident alerts, analyst case notes, and tamper-evident audit logs.
* **Hardware Efficiency:** Built in pure Go with zero JVM dependencies in the core pipeline, operating efficiently in containerized environments.
* **Zero Data Loss on Upgrades:** Named Docker volumes, automated pre-upgrade database snapshots, non-destructive idempotent migrations, and container restart safeguards.

---

## 2. End-to-End System Architecture Diagram

```
                             NETWORK & SECURITY INFRASTRUCTURE
                     ┌───────────────────────────────────────────────┐
                     │ Fortinet FortiGate • WatchGuard • Cisco ASA   │
                     │ Linux Servers • Windows AD • Switches/Routers │
                     └───────────────────────┬───────────────────────┘
                                             │
                        Syslog UDP/TCP/TLS (Ports 514, 5514)
                                             │
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                INGESTION & PIPELINE ENGINE                             │
│                                                                                        │
│   ┌───────────────────────────┐      ┌──────────────────┐      ┌──────────────────┐   │
│   │ Non-Blocking Ring Buffer  │ ───► │  Syslog Parser   │ ───► │ In-Memory Device │   │
│   │   (Atomic Drop Counter)   │      │ (RFC 3164/5424)  │      │ Cache (Postgres) │   │
│   └───────────────────────────┘      └────────┬─────────┘      └──────────────────┘   │
└───────────────────────────────────────────────┼────────────────────────────────────────┘
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     │                                                     │
                     ▼                                                     ▼
┌──────────────────────────────────────────┐      ┌──────────────────────────────────────┐
│        SIEM DETECTION & SOC ENGINE       │      │         DUAL-STORAGE ENGINE          │
│                                          │      │                                      │
│  ┌────────────────────────────────────┐  │      │  ┌────────────────────────────────┐  │
│  │ Multi-Vendor Normalization Engine  │  │      │  │ ClickHouse Columnar Store      │  │
│  │ (Fortinet, Cisco, Linux, Windows)  │  │      │  │ • ZSTD Compression             │  │
│  └─────────────────┬──────────────────┘  │      │  │ • Monthly Partitioning         │  │
│                    │                     │      │  │ • Tokenbf_v1 Text Search       │  │
│                    ▼                     │      │  │ • 100k+ EPS Analytical OLAP    │  │
│  ┌────────────────────────────────────┐  │      │  └────────────────────────────────┘  │
│  │ In-Memory Sliding-Window Engine    │  │      │                                      │
│  │ • Multi-event time buckets         │  │      │  ┌────────────────────────────────┐  │
│  │ • Brute Force / Spraying / Scans   │  │      │  │ PostgreSQL Relational ACID     │  │
│  │ • Alert Deduplication & Throttling │  │      │  │ • Registered Devices           │  │
│  └─────────────────┬──────────────────┘  │      │  │ • SIEM Rules & Incidents       │  │
│                    │                     │      │  │ • Analyst Case Notes & Audit   │  │
│                    ▼                     │      │  └────────────────────────────────┘  │
│  ┌────────────────────────────────────┐  │      │                                      │
│  │ MITRE ATT&CK® Matrix Mapping       │  │      │  ┌────────────────────────────────┐  │
│  │ • Tactics & Techniques (T1110,etc) │  │      │  │ Law 5651 Archival Engine       │  │
│  │ • Online STIX 2.1 Sync Engine      │  │      │  │ • Deterministic Daily Batches  │  │
│  └─────────────────┬──────────────────┘  │      │  │ • SHA-256 Hash Chaining        │  │
│                    │                     │      │  │ • TÜBİTAK KamuSM Timestamping  │  │
│                    ▼                     │      │  └────────────────────────────────┘  │
│  ┌────────────────────────────────────┐  │      └──────────────────────────────────────┘
│  │ Live WebSocket Alert Broadcast     │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        WEB APPLICATION & SOC USER INTERFACE                            │
│                                                                                        │
│   • SOC Threat Scoreboard & MITRE Badges       • Incident Triage & Forensic Notes      │
│   • ClickHouse Full-Text Search Terminal       • 5651 Certificate & Archive Verifier   │
│   • System Hardware Telemetry (CPU/RAM/EPS)    • 1-Click Automated Upgrade Engine      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Subsystem Breakdown

### 3.1 Tier 1: Ingestion & Socket Listeners
* **Protocols:** UDP (RFC 5426), TCP (RFC 5425), TLS (RFC 5425).
* **Ports:** Port 514 (standard root) and Port 5514 (unprivileged fallback).
* **Ingestion Model:** Sockets write raw datagrams into a non-blocking buffered Go channel (`inQueue`).
* **Zero-Trust Filtering:**
  * **Permissive Mode:** Unregistered senders are logged, indexed, and cataloged in `unregistered_sources` for 1-click device discovery.
  * **Strict Mode:** Traffic from unauthorized IP addresses is instantly dropped at the ingestion socket interface, shielding downstream databases from unauthorized noise.

---

### 3.2 Tier 2: Parser & Multi-Vendor Normalization
The normalization subsystem decodes raw vendor-specific syslog messages into a standardized `NormalizedEvent` struct:

```go
type NormalizedEvent struct {
    EventID         uuid.UUID
    Timestamp       time.Time
    SourceIP        string
    DestinationIP   string
    Username        string
    DeviceName      string
    EventCategory   string // authentication, network, threat, system, configuration
    EventAction     string // login-failed, connection-denied, privilege-escalation, malware-blocked
    EventOutcome    string // failure, success, blocked, allowed
    Severity        string // CRITICAL, HIGH, MEDIUM, LOW
    RiskScore       int    // 0-100
    MitreTactic     string // e.g. Credential Access
    MitreTechnique  string // e.g. T1110
    RawMessage      string
}
```

#### Specialized Vendor Normalizers:
1. **Fortinet FortiGate / FortiAnalyzer:** Key-value pairs (`action=`, `user=`, `srcip=`, `dstip=`, `attack=`, `virus=`).
2. **WatchGuard Firebox:** Packet dispatch semantics (`disp=Deny`, `src=`, `dst=`, `user=`).
3. **Cisco ASA / IOS:** Cisco syslog message headers (`%ASA-4-106023`, `%ASA-2-106001`).
4. **Linux Auth / SSH / Sudo:** PAM and audit logs (`sshd: Failed password`, `sudo: authentication failure`).
5. **Windows Security Events:** WinEvent logs (`EventID 4625` logon failure, `EventID 4720` account creation).
6. **Generic Fallback:** Extracts standard syslog facility and severity codes.

---

### 3.3 Tier 3: Real-Time Sliding-Window Correlation Engine
The correlation engine evaluates normalized events against active detection rules using in-memory sliding time windows:

* **Sliding Window State:** Each rule maintains dynamic buckets partitioned by `GroupBy` keys (e.g. `AUTH-001::source_ip` or `SYS-001::username`).
* **Multi-Event Threshold Evaluation:** Events outside the rule's `TimeframeSeconds` window are pruned dynamically.
* **Alert Deduplication & Throttling:** When an attack threshold is crossed (e.g. 10 failed logins within 3 minutes), the engine fires an alert, captures up to 10 raw syslog evidence logs, and throttles identical alerts for 30 seconds to prevent alert floods.
* **Live Broadcast:** New alerts are broadcast over WebSockets to all open SOC analyst dashboards in real time.

---

### 3.4 Tier 4: Storage Architecture

#### 1. ClickHouse (High-Performance Analytical Log Store)
* **Table:** `syslog.syslog_events`
* **Engine:** `MergeTree`
* **Partition Key:** `toYYYYMM(event_timestamp)` (partitioned monthly for high compression and instant retention dropping).
* **Order Key:** `(device_id, severity_code, event_timestamp, internal_id)`
* **Compression:** `DoubleDelta` on timestamps, `ZSTD(1)` on metadata, `ZSTD(6)` on raw log bodies.
* **Indices:** `tokenbf_v1(30720, 2, 0)` Bloom filter indices on `message` and `raw_message` for sub-second full-text token searches across billions of records.
* **Materialized View:** `syslog.mv_events_per_minute` feeding `SummingMergeTree` for instant EPS and log-rate telemetry.
* **Automated FIFO Storage Reclaim (Zero Log Miss Policy):** Background cleaner monitors host storage utilization every 30 seconds against a user-configured threshold percentage (default 85%). When the threshold is exceeded, the oldest monthly partition is dropped instantly via `ALTER TABLE DROP PARTITION` (or oldest 24h batch if 1 partition), guaranteeing continuous disk headroom so incoming logs are never dropped due to disk pressure.
* **Bounded Live Stream Ring Buffer:** Live WebSocket feed strictly displays the last 15 receiving logs, eliminating browser DOM thrashing while preserving instantaneous verification of active network traffic.
* **Dynamic Listener Hot-Reload:** Network addresses and ports for UDP (RFC 5426), TCP (RFC 6587), and TLS (RFC 5425) are hot-reloaded with zero container downtime directly from the Web UI Settings console.

#### 2. PostgreSQL (ACID Relational Metadata & SOC State)
* **Tables:**
  * `devices` & `device_groups`: Managed network assets, IP addresses, credentials, and polling profiles.
  * `unregistered_sources`: Auto-discovered network senders.
  * `siem_rules`: Detection rules, threshold criteria, time windows, and MITRE mapping.
  * `siem_alerts`: Triggered incidents, status lifecycle (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`), severity, and forensic evidence logs.
  * `siem_incident_notes`: Timestamped analyst case notes and investigation rationale.
  * `users` & `audit_logs`: Session authentication, RBAC, and tamper-evident administrative action logs.
  * `log_archives`: Daily 5651 archive manifests, SHA-256 hashes, and timestamping receipts.
  * `settings`: System configurations including `storage_fifo_threshold_pct`, `syslog_udp_listen_addr`, `syslog_tcp_listen_addr`, and `syslog_tls_listen_addr`.

---

### 3.5 Tier 5: Law No. 5651 & TÜBİTAK KamuSM Timestamping
To fulfill the legal requirements of Turkish Law No. 5651:
1. Logs are batched into deterministic time windows (hourly or daily).
2. The batch is compressed (`.jsonl.gz`) and hashed via **SHA-256**.
3. The SHA-256 hash digest is submitted via RFC 3161 protocol to **TÜBİTAK KamuSM** (Kamu Sertifikasyon Merkezi).
4. KamuSM returns a cryptographically signed timestamp token (`.tsq` / `.tsr` / `.zd`).
5. The signature bundles and metadata are stored immutably in `/opt/syslog-platform/archive/` and tracked in PostgreSQL `log_archives`.

---

## 4. Zero Data Loss Upgrade Architecture

A primary requirement of Valtrivo LogSeal is that **application upgrades must NEVER cause data loss**.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      ZERO DATA LOSS UPGRADE PROTOCOL                   │
│                                                                        │
│   [1. upgrade.sh Initiated]                                            │
│            │                                                           │
│            ▼                                                           │
│   [2. Automated Pre-Upgrade DB Snapshot]                               │
│       • Creates ./backups/postgres_backup_YYYYMMDD_HHMMSS.sql.gz       │
│       • Rotates to retain latest 5 snapshots                           │
│            │                                                           │
│            ▼                                                           │
│   [3. Fetch & Pull Latest Code] ─── (git stash pop preserves .env)     │
│            │                                                           │
│            ▼                                                           │
│   [4. Non-Destructive Migrations] ─ (CREATE TABLE/INDEX IF NOT EXISTS) │
│            │                                                           │
│            ▼                                                           │
│   [5. Isolated Container Rebuild] ─ (docker compose build syslog-app)  │
│            │                                                           │
│            ▼                                                           │
│   [6. Safe Graceful Recreate] ───── (stop_grace_period: 30s)           │
│       • In-flight ClickHouse batches flushed cleanly                   │
│       • PostgreSQL WAL checkpoints committed cleanly                   │
│       • Databases (postgres & clickhouse) NEVER stopped                │
│       • Named Volumes (clickhouse_data, postgres_data) UNTOUCHED       │
│            │                                                           │
│            ▼                                                           │
│   [7. Healthcheck Verification] ─── (/api/v1/system/health)            │
└────────────────────────────────────────────────────────────────────────┘
```

### Why Data is Guaranteed Safe:
1. **Named Volumes:** Databases run on named volumes `clickhouse_data` and `postgres_data`. Docker persists named volume data independently of container lifecycles.
2. **Targeted Recreate:** Upgrades only rebuild and restart `syslog-app`. The database engines (`postgres` and `clickhouse`) remain online and unmolested.
3. **Graceful Draining (`stop_grace_period: 30s`):** When stopping, `syslog-app` intercepts `SIGTERM`, shuts down socket listeners first, flushes all pending in-memory ClickHouse batches, and closes database connections cleanly.
4. **Idempotent Migrations:** SQL migrations strictly use `IF NOT EXISTS` and `ON CONFLICT DO NOTHING`. Existing tables, columns, indexes, and records are never overwritten or dropped.
5. **Pre-Upgrade Snapshots:** In the event of a catastrophic server power failure during an upgrade, an uncorrupted compressed SQL snapshot is ready for instant restoration in `./backups/`.

---

## 5. MITRE ATT&CK Matrix Synchronization

The platform includes an automated and air-gapped synchronization engine for MITRE ATT&CK:
* **Built-in Baseline:** Pre-loaded with Enterprise ATT&CK v15.1 covering all 14 tactics.
* **Online Feed:** Periodically or on-demand streams the official STIX 2.1 JSON catalog from MITRE's GitHub repository (`POST /api/v1/siem/mitre/sync`).
* **Air-Gapped Ingestion:** Allows loading local STIX JSON files in isolated networks.
* **SOC Matrix Visualizer:** Dynamic coverage reports (`GET /api/v1/siem/mitre`) compute real-time defense posture against active detection rules.

---

## 6. Security & Access Control (RBAC)

* **Authentication:** SHA-256 hashed passwords with cryptographically secure session cookies (`Secure`, `HttpOnly`, `SameSite=Lax`).
* **Role-Based Access Control (RBAC):**
  * **Super Administrator:** Full system control, software upgrades, raw database maintenance, user provisioning, and rule editing.
  * **SOC Analyst:** Alert triage, incident case notes, log search, device health monitoring, and MITRE matrix visualization.
  * **Auditor / Compliance Officer:** Read-only log search, 5651 archive validation, and tamper-evident audit logs.
* **Tamper-Evident Audit Log:** Every login, configuration change, rule toggle, incident update, and manual export is logged in PostgreSQL `audit_logs` with source IP, timestamp, user ID, and JSON details.
