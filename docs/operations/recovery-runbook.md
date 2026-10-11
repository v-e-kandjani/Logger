# LogSeal — Operations & Disaster Recovery Runbook

**Document Version:** 1.0.0 (Phase 10 Certification)  
**Applicable Platform:** Valtrivo LogSeal v1.6.9+  
**Target Audience:** DevOps, SRE, MSSP Operations, SOC Administrators

---

## 1. Incident Severity & Escalation Matrix

| Severity | Operational Condition | Target Response Time | Immediate Action |
|---|---|---|---|
| **SEV-1 (Critical)** | Core ClickHouse node down; Ingestion dropped; TSA token verification halted > 3 hours. | < 15 minutes | Activate Standby ClickHouse, inspect disk space, drain proxy spools. |
| **SEV-2 (High)** | Data Plane Governor entered `Pressure`/`Critical`; Alert correlation lagging > 5 minutes. | < 30 minutes | Review active heavy queries, stop analytical exports, check RAM pressure. |
| **SEV-3 (Medium)**| Remote branch edge proxy disconnected; WAN spool accumulating > 50% capacity. | < 2 hours | Check branch VPN/MPLS connectivity; verify remote proxy health. |
| **SEV-4 (Low)** | Minor syslog parsing anomalies; Single device reporting format mismatch. | Next Business Day | Update regex parser in vendor profile rules. |

---

## 2. Standard Service Lifecycle & Management

### 2.1 Service Unit Commands (Docker Compose Environment)
```bash
# Check overall stack status and health checks
docker compose ps

# Inspect logs of the core syslog platform
docker compose logs -f --tail=200 syslog-app

# Inspect database engine logs
docker compose logs -f --tail=200 syslog-clickhouse
docker compose logs -f --tail=200 syslog-postgres

# Graceful restart of the application container
docker compose restart syslog-app

# Rebuild and upgrade with zero downtime to databases
docker compose build syslog-app && docker compose up -d syslog-app
```

### 2.2 Systemd Native Services (Bare-Metal / VM Deployment)
```bash
# Check cgroup placement and resource consumption
systemctl status siem.slice
systemd-cgls /siem.slice

# Inspect control vs data plane slices
systemctl status syslog-platform.service
systemctl status clickhouse-server.service
systemctl status postgresql.service
```

---

## 3. Failure Scenarios & Recovery Procedures

### Scenario A: Abrupt Node / Container Crash Recovery

**Symptoms:** Machine rebooted unexpectedly or Docker engine crashed.
**Automated Recovery:**
1. On startup, `syslog-app` connects to PostgreSQL and invokes `reconcileDueHourlyWindows()`.
2. Any unsealed hourly windows from the downtime are discovered and queued into the sealer work pool.
3. If an edge proxy was running during the crash, `logseal-proxy` scans for stranded `drain_*.log` files on disk, verifies integrity, and replays them to the central collector.

**Manual Operator Checks:**
```bash
# 1. Verify container liveness
docker compose ps

# 2. Check for pending hourly archive sealing windows
curl -s http://localhost:8080/api/v1/governor/status | jq .sealer_status

# 3. Inspect PostgreSQL for stuck leases (lease_until < NOW())
docker compose exec syslog-postgres psql -U postgres -d logger -c \
  "SELECT id, tenant_id, period_start, period_end, status, lease_until FROM hourly_archives WHERE status = 'BUILDING';"
```

---

### Scenario B: WAN Outage & Remote Edge Proxy Backlog Replay

**Symptoms:** Branch office lost WAN connection for 4 hours; syslog packets spooled to `/var/spool/logseal/spool.log`.
**Behavior:** The edge proxy keeps accepting local syslog packets up to `MaxSpoolBytes` (500 MB default) and syncs to disk (`fsync`).

**Recovery Workflow:**
1. When WAN connectivity restores, the proxy establishes TLS to the central collector (`:5514`).
2. The proxy closes `spool.log` and renames it to `drain_<timestamp>.log`.
3. To prevent a **thundering herd** burst, the proxy enforces `ReplayRateEPS` with randomized sleep jitter (50–150ms).
4. Operator verifies that central ingestion rate remains stable:
```bash
# Inspect proxy log on edge device
tail -f /var/log/logseal-proxy.log | grep -E "draining|replayed|synced"

# Check EPS governor on central platform
curl -s http://localhost:8080/api/v1/governor/status | jq .current_eps
```

---

### Scenario C: External TÜBİTAK TSA (KamuSM) Service Outage

**Symptoms:** Internet link down or TÜBİTAK timestamp servers timing out. Archives transition to `TSA_PENDING` instead of `VERIFIED`.

> [!CAUTION]
> Under Law No. 5651, unverified timestamp responses must NEVER be marked as valid external TSA evidence. They remain in `TSA_PENDING` until a signed RFC 3161 timestamp token is returned.

**Recovery Workflow:**
1. Sealed payload archives and `manifest.sha256` are safely preserved on disk in `/opt/syslog-platform/archive/hourly/<tenant>/`.
2. The platform's backoff scheduler attempts automatic retries every 15 minutes.
3. Once TSA connectivity is restored, trigger manual batch retry for all pending tokens:
```bash
# Re-attempt TSA signing for all pending windows
docker compose exec syslog-app /opt/syslog-platform/bin/syslog-platform --retry-tsa-pending
```
4. Verify all windows transitioned to `VERIFIED`:
```bash
docker compose exec syslog-postgres psql -U postgres -d logger -c \
  "SELECT id, tenant_id, period_start, status, sha256_hash FROM hourly_archives WHERE status != 'VERIFIED';"
```

---

### Scenario D: ClickHouse Storage Pressure (≥ 85% Disk Utilization)

**Symptoms:** Host disk alert fires; ClickHouse throws `READONLY` or rejects inserts.

**Immediate Remediation Steps:**
1. **Identify Partition Footprint:**
```bash
docker compose exec syslog-clickhouse clickhouse-client --query \
  "SELECT partition, count(), formatReadableSize(sum(bytes_on_disk)) FROM syslog_events GROUP BY partition ORDER BY partition DESC;"
```
2. **Drop or Move Old Partitions (Beyond Legal Retention):**
```bash
# Example: Drop partitions older than 90 days
docker compose exec syslog-clickhouse clickhouse-client --query \
  "ALTER TABLE syslog_events DROP PARTITION '2026-06';"
```
3. **Verify Archive Preserved:** Ensure the corresponding hourly `.tar.gz` and `.tsr` evidence tokens exist on the cold storage mount before dropping database partitions.

---

### Scenario E: PostgreSQL Lock Contention or Stalled Migrations

**Symptoms:** API requests timing out; `ClaimNextArchiveJob` blocking.

**Diagnosis & Remediation:**
```bash
# 1. Identify long-running transactions
docker compose exec syslog-postgres psql -U postgres -d logger -c \
  "SELECT pid, now() - pg_stat_activity.query_start AS duration, query, state 
   FROM pg_stat_activity 
   WHERE (now() - pg_stat_activity.query_start) > interval '30 seconds' AND state != 'idle';"

# 2. Terminate blocking backend PID if safe
docker compose exec syslog-postgres psql -U postgres -d logger -c \
  "SELECT pg_terminate_backend(<PID>);"
```

---

## 4. Disaster Recovery & Offline Verification Drill

For regulatory audits (Law No. 5651, ISO 27001), perform quarterly offline integrity drills:

### Step 1: Export Archive Bundle
Locate the hourly archive on the server:
```bash
cd /opt/syslog-platform/archive/hourly/default/2026/10/11/
ls -la
# Files:
# - logseal_default_20261011_140000.tar.gz
# - logseal_default_20261011_140000.sha256
# - logseal_default_20261011_140000.tsr
```

### Step 2: Validate Exact Payload SHA-256 Hash
```bash
sha256sum -c logseal_default_20261011_140000.sha256
# Output: logseal_default_20261011_140000.tar.gz: OK
```

### Step 3: Verify TÜBİTAK RFC 3161 Timestamp Token (Offline)
Using OpenSSL and the KamuSM Root Certificate Authority bundle:
```bash
openssl ts -verify \
  -data logseal_default_20261011_140000.sha256 \
  -in logseal_default_20261011_140000.tsr \
  -CAfile /opt/syslog-platform/timestamp-client/kamusm_bundle.crt
# Expected Output: Verification: OK
```
