# Valtrivo LogSeal — Operator & Administrator Help Guide

This guide provides operational workflows, troubleshooting procedures, and architecture guidance for the **Valtrivo LogSeal** platform.

---

## 1. System Overview & Dual Engine Architecture

Valtrivo LogSeal combines high-throughput event ingestion with tamper-evident cryptographic compliance:
- **ClickHouse 24.3**: High-speed, columnar analytical store handling live event search, aggregation, and SIEM rule evaluations up to 100,000+ EPS. Partitioned monthly by event timestamp.
- **PostgreSQL 16**: Relational repository managing multi-tenant boundaries, device authorization inventory, user RBAC, audit trails, and archive ledgers.
- **TÜBİTAK KamuSM Timestamping**: Daily automated RFC 3161 cryptographic timestamping adhering to Law No. 5651.

---

## 2. Platform Upgrades & Zero-Data-Loss Maintenance

Valtrivo LogSeal provides two synchronized methods for applying platform upgrades with **zero difference in functionality**:

### Method A: Automated CLI Upgrade (Recommended)
On your VPS terminal:
```bash
sudo bash upgrade.sh
```
What it executes automatically:
1. Takes an automated pre-upgrade compressed database snapshot into `./backups/postgres_backup_YYYYMMDD_HHMMSS.sql.gz`.
2. Pulls latest changes from `origin/main`.
3. Verifies and applies database schema migrations.
4. Generates `config/.version_info` with commit SHA and version.
5. Rebuilds `syslog-app` with build args (`GOMAXPROCS` throttled to leave 1 CPU core free).
6. Recreates container and verifies healthcheck (`/api/v1/system/health`).

### Method B: 1-Click Web UI Upgrade
1. Log in as Root Super Administrator.
2. Navigate to **System Upgrade** (`🔄 Sistem Güncelleme`) on the left sidebar.
3. Click **🔍 Check for Updates** to query GitHub for latest commits.
4. Click **🚀 Apply Upgrade (Changed Files)**:
   - Streams live progress via Server-Sent Events (SSE).
   - Hot-patches web assets, templates, and scripts.
   - Downloads required Go libraries (`go mod download`).
   - Recompiles platform binary (`go build`) with embedded version metadata.
   - Updates runtime configuration and records audit log.
   - Automatically triggers graceful platform reload and reconnects dashboard upon completion.

---

## 3. Remote Proxy Nodes (`logseal-proxy`) Deployment

For branch offices, subsidiaries, or customer networks behind NAT/Firewall:

1. **Register the Edge Node**:
   - Go to **Settings** -> **Edge Forwarder Nodes**.
   - Click **+ Register Edge Node**, enter node name (e.g., `Ankara-Subesi-Edge`), tenant assignment, and allowed CIDRs.
   - Securely copy the generated **Bearer Token**.
2. **Deploy the Daemon**:
   - Install binary or run lightweight Docker container on the remote edge Linux machine:
     ```bash
     curl -sSL https://raw.githubusercontent.com/v-e-kandjani/Logger/main/scripts/install-edge.sh | sudo bash -s -- \
       --server https://<CENTRAL_IP>:8443 \
       --token <EDGE_BEARER_TOKEN>
     ```
3. **Verify Connection**:
   - The edge node connects outbound via **HTTPS 8443/tcp**.
   - Node status switches from `Awaiting Handshake` to `ONLINE` within 10 seconds.
   - If WAN drops, logs buffer to local SQLite spool and flush with zero loss upon reconnection.

---

## 4. Required Network Ports Quick Reference

| Port | Protocol | Service | Exposure |
| :--- | :---: | :--- | :--- |
| **8443** | TCP | HTTPS Web UI & Edge Forwarder API | Public / WAN |
| **8080** | TCP | HTTP Web UI (Redirect or internal) | Public / LAN |
| **514** | UDP/TCP | Syslog Ingestion (RFC 3164/5424) | Public / LAN |
| **5514** | UDP/TCP | Alternative Syslog Ingestion | Public / LAN |
| **6514** | TCP | TLS Syslog (RFC 5425) | Public / LAN |
| **5432** | TCP | PostgreSQL Metadata Database | **127.0.0.1 (Loopback Only)** |
| **8123** | TCP | ClickHouse HTTP Interface | **127.0.0.1 (Loopback Only)** |
| **9000** | TCP | ClickHouse Native Protocol | **127.0.0.1 (Loopback Only)** |

> [!TIP]
> For complete firewall configuration commands (`ufw`, `firewalld`), see [docs/PORT_SPECIFICATIONS.md](PORT_SPECIFICATIONS.md).

---

## 5. Troubleshooting Common Issues

### Issue 1: Device sends syslog, but logs do not appear in Live Stream
- Check **Unknown Sources** (`Tanımsız Kaynaklar`) tab: If device IP is not registered in Device Inventory, it may be held in unknown queue if Strict Filtering is enabled.
- Verify UDP port binding: `sudo netstat -tulpn | grep 514`.
- Send a test log: `logger -n 127.0.0.1 -P 514 "Test Log"`.

### Issue 2: Timestamp Verification warning in System Health
- Ensure Java 17 JRE is installed (included in Docker container).
- Check `timestamp-client/` directory for `tss-client-console-*.jar` and valid TÜBİTAK KamuSM credentials in Settings.

### Issue 3: Container unhealthy after reboot
- Check logs: `docker compose logs -f syslog-app`.
- Verify PostgreSQL is healthy: `docker compose ps postgres`.
- Verify ClickHouse is healthy: `docker compose ps clickhouse`.
