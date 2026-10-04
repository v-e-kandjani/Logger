# Valtrivo LogSeal — Installation & Deployment Guide

> **Valtrivo LogSeal: Centralized Log Management and Timestamping**  
> *"Her kayıt, zamanıyla kanıt."*

This guide provides comprehensive, step-by-step instructions for installing and deploying **Valtrivo LogSeal** on **Linux Ubuntu (20.04 / 22.04 / 24.04 LTS)** and Debian-based systems. It covers firewall (UFW) configuration, local database isolation, database initialization, and operational management.

---

## 🌐 Language / Dil
- 🇬🇧 **[English Guide (Current)](HOW_TO_INSTALL.en.md)**
- 🇹🇷 **[Türkçe Kurulum Kılavuzu](HOW_TO_INSTALL.tr.md)**
- 🏠 **[Main Project Readme](README.md)**

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Quick Installation (Automated Script in 2 Minutes)](#2-quick-installation-automated-script-in-2-minutes)
3. [Interactive Configuration Wizard Options](#3-interactive-configuration-wizard-options)
4. [Unattended CLI Flags (Automated Deployments)](#4-unattended-cli-flags-automated-deployments)
5. [Network & Firewall (UFW) Rules](#5-network--firewall-ufw-rules)
6. [Local-Only Database Isolation & Security](#6-local-only-database-isolation--security)
7. [Database Initialization & Table Schemas](#7-database-initialization--table-schemas)
8. [Manual Installation (Without the Script)](#8-manual-installation-without-the-script)
9. [Post-Installation Steps & Device Onboarding](#9-post-installation-steps--device-onboarding)
10. [Updating Ports & Environment Configuration](#10-updating-ports--environment-configuration)
11. [Troubleshooting & Frequently Asked Questions (FAQ)](#11-troubleshooting--frequently-asked-questions-faq)

---

## 1. System Requirements

| Component | Minimum (Test / Small Network) | Recommended (Production / 50+ Devices) |
| :--- | :--- | :--- |
| **Operating System** | Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS | Ubuntu 22.04 LTS or 24.04 LTS (x86_64) |
| **Processor (CPU)** | 2 vCPU | 4+ vCPU |
| **Memory (RAM)** | 4 GB | 8 GB - 16 GB |
| **Disk Space** | 20 GB SSD | 100 GB+ NVMe/SSD (Depends on retention period) |
| **Network Ports** | SSH (22), Web UI (8080 or custom), Syslog (514/5514/6514) | Static IP recommended |

---

## 2. Quick Installation (Automated Script in 2 Minutes)

Valtrivo LogSeal includes an automated installation script ([install.sh](install.sh)) that checks and installs all prerequisites (`curl`, `wget`, `ufw`, `jq`, `Docker`, `Docker Compose`).

### Step 1: Clone the Repository to Your Server
```bash
git clone https://github.com/v-e-kandjani/Logger.git
cd Logger
```

### Step 2: Run the Installation Script as Root
```bash
sudo bash install.sh
```

The script automatically executes the following:
1. Verifies root privileges and checks Ubuntu distribution.
2. Installs required system packages (`ca-certificates`, `curl`, `gnupg`, `ufw`, `jq`, `openssl`).
3. Installs official Docker CE and Docker Compose plugin if missing.
4. Prompts for Web UI Port, database credentials, and Super Administrator account.
5. Enables UFW firewall while preserving SSH port 22 to prevent administrator lockout.
6. Boots PostgreSQL and ClickHouse containers and waits for health checks.
7. Executes database migrations (`001_initial_schema.sql` and `001_initial_events.sql`).
8. Seeds the initial Super Administrator user with bcrypt salted password hashing.
9. Compiles and starts Valtrivo LogSeal, then verifies the healthcheck endpoint.

---

## 3. Interactive Configuration Wizard Options

When running `sudo bash install.sh`, the interactive wizard prompts:

```text
============================================================
 Valtrivo LogSeal - Interactive Configuration Wizard
============================================================
[?] Enter Web UI & API Port [default: 8080]: 
[?] Enter PostgreSQL Database Name [default: syslog_manager]: 
[?] Enter PostgreSQL Username [default: syslog_admin]: 
[?] Enter PostgreSQL Password [default: syslog_secret]: 
[?] Enter ClickHouse Database Name [default: syslog]: 
[?] Enter ClickHouse Username [default: default]: 
[?] Enter ClickHouse Password [default: (empty)]: 
[?] Enter Initial Super Admin Username [default: admin]: 
[?] Enter Initial Super Admin Password [default: Admin@LogSeal2026!]: 
```

- Enter your custom values or press `Enter` to accept the recommended secure defaults.

---

## 4. Unattended CLI Flags (Automated Deployments)

For automated server deployments (Ansible, Terraform, cloud-init), skip the interactive wizard by passing command-line flags:

### Example 1: Fully Automated Install with Defaults
```bash
sudo bash install.sh -y
# or
sudo bash install.sh --defaults
```

### Example 2: Custom Web Port and Strong Administrator Password
```bash
sudo bash install.sh -y --port 9000 --admin-user sysadmin --admin-pass "EnterpriseSecurePass2026!"
```

### Available CLI Flags:
| Flag | Description | Default |
| :--- | :--- | :--- |
| `-y, --yes, --defaults` | Skip interactive prompts and use defaults | Interactive |
| `-p, --port <PORT>` | Web Dashboard & REST API port | `8080` |
| `--pg-db <NAME>` | PostgreSQL database name | `syslog_manager` |
| `--pg-user <USER>` | PostgreSQL username | `syslog_admin` |
| `--pg-pass <PASS>` | PostgreSQL password | `syslog_secret` |
| `--ch-db <NAME>` | ClickHouse database name | `syslog` |
| `--ch-user <USER>` | ClickHouse username | `default` |
| `--ch-pass <PASS>` | ClickHouse password | *(empty)* |
| `--admin-user <USER>` | Initial Web UI Super Admin username | `admin` |
| `--admin-pass <PASS>` | Initial Web UI Super Admin password | `Admin@LogSeal2026!` |
| `-h, --help` | Show help and flag descriptions | - |

---

## 5. Network & Firewall (UFW) Rules

The installation script configures UFW to protect against external intrusion while ensuring network device logs and administrator access remain smooth:

```bash
# Automated UFW configuration applied by install.sh:
ufw allow 22/tcp comment 'SSH Access (Prevent Lockout)'
ufw allow 8080/tcp comment 'Valtrivo LogSeal Web UI & API'   # (or your chosen port)
ufw allow 514/udp comment 'Syslog Standard UDP'
ufw allow 514/tcp comment 'Syslog Standard TCP'
ufw allow 5514/udp comment 'Syslog High-Perf UDP'
ufw allow 5514/tcp comment 'Syslog High-Perf TCP'
ufw allow 6514/tcp comment 'Syslog Encrypted TLS'

# Block external access to database ports:
ufw deny 5432 comment 'Block External Postgres'
ufw deny 9000 comment 'Block External ClickHouse Native'
ufw deny 8123 comment 'Block External ClickHouse HTTP'

ufw --force enable
```

Check firewall status anytime:
```bash
sudo ufw status verbose
```

---

## 6. Local-Only Database Isolation & Security

Under Linux, Docker creates `iptables` NAT rules that could bypass UFW rules if ports are exposed to `0.0.0.0`.

**Valtrivo LogSeal Security Architecture:**
In [docker-compose.yml](docker-compose.yml), database ports are bound **strictly to the `127.0.0.1` (loopback) interface**:

```yaml
services:
  clickhouse:
    ports:
      - "127.0.0.1:9000:9000"
      - "127.0.0.1:8123:8123"
      
  postgres:
    ports:
      - "127.0.0.1:5432:5432"
```

### Benefits:
1. **Zero External Attack Surface**: Any packets originating outside the server targeting ports 5432 or 9000 are rejected at the Linux kernel level.
2. **Internal Container Interconnect**: The Valtrivo LogSeal application container (`syslog-app`) talks to the databases over the isolated Docker bridge network (`syslog_net`).
3. **Local Maintenance**: Administrators logged into the server via SSH can connect directly via terminal:
   ```bash
   # Connect to PostgreSQL from localhost:
   psql -h 127.0.0.1 -U syslog_admin -d syslog_manager
   
   # Connect to ClickHouse from localhost:
   clickhouse-client -h 127.0.0.1 --database syslog
   ```

---

## 7. Database Initialization & Table Schemas

During setup, schemas are applied automatically:

### A. PostgreSQL (Metadata, Devices, Users, Archives & Audit)
- Migration: [migrations/postgres/001_initial_schema.sql](migrations/postgres/001_initial_schema.sql)
- Tables:
  - `devices`: Registered network devices (FortiGate, WatchGuard, Cisco, Linux, etc.).
  - `users`: RBAC user accounts with salted bcrypt password hashes.
  - `daily_summaries`: Daily log archives, SHA-256 digests, and timestamp status.
  - `stamping_audit`: Cryptographic timestamp evidence audit log.
  - `system_settings`: Storage quotas, TÜBİTAK credentials, zero-trust filtering.

### B. ClickHouse (High-Throughput Vectorized Storage)
- Migration: [migrations/clickhouse/001_initial_events.sql](migrations/clickhouse/001_initial_events.sql)
- Tables:
  - `syslog_events`: Primary `MergeTree` table partitioned by month (`toYYYYMM`) with bloom filters for sub-second searches across millions of events.
  - `mv_events_per_minute`: Materialized view for live ingestion rate graphs.

---

## 8. Manual Installation (Without the Script)

If you prefer to perform the setup manually:

```bash
# 1. Install prerequisites
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release ufw jq openssl

# 2. Install Docker & Compose plugin
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker

# 3. Configure environment variables
cp .env.example .env
nano .env   # Customize APP_PORT, credentials, etc.

# 4. Configure UFW Firewall
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 514/udp
sudo ufw allow 514/tcp
sudo ufw allow 5514/udp
sudo ufw allow 5514/tcp
sudo ufw allow 6514/tcp
sudo ufw deny 5432
sudo ufw deny 9000
sudo ufw deny 8123
sudo ufw --force enable

# 5. Launch containers
docker compose up -d

# 6. Apply database schemas
docker exec -i syslog-postgres psql -U syslog_admin -d syslog_manager < migrations/postgres/001_initial_schema.sql
docker exec -i syslog-clickhouse clickhouse-client --database syslog --multiquery < migrations/clickhouse/001_initial_events.sql
```

---

## 9. Post-Installation Steps & Device Onboarding

### 1. Log In to Web Dashboard
Open your browser at:
```text
http://<SERVER_IP>:8080
```
- **Username**: `admin` *(or custom username)*
- **Password**: `Admin@LogSeal2026!` *(or custom password)*

### 2. Multi-Language Switch
Switch between **English (EN)** and **Türkçe (TR)** using the language toggle in the top-right header.

### 3. Forward Network Device Syslogs (FortiGate, WatchGuard, pfSense, Cisco)
Point your firewalls and switches to your Valtrivo LogSeal server:
- **Standard Syslog**: Port `514` (UDP or TCP)
- **High-Throughput Syslog**: Port `5514` (UDP or TCP)
- **Encrypted TLS Syslog**: Port `6514` (TCP)

Unknown sources appear in the **Auto-Discovered Senders** table for 1-click registration.

---

## 10. Updating Ports & Environment Configuration

To modify settings or change the Web UI port after installation:

1. Edit `.env`:
   ```bash
   nano .env
   # E.g. Set APP_PORT=8443
   ```
2. Update UFW if port was changed:
   ```bash
   sudo ufw allow 8443/tcp comment 'Valtrivo LogSeal New Port'
   ```
3. Restart containers:
   ```bash
   docker compose down
   docker compose up -d
   ```

---

## 11. Troubleshooting & Frequently Asked Questions (FAQ)

### Q1: How do I verify container health?
```bash
docker compose ps
```
All containers (`syslog-app`, `syslog-postgres`, `syslog-clickhouse`) should show `Up (healthy)`.

### Q2: How do I view live application logs?
```bash
docker compose logs -f syslog-app
```

### Q3: How do I reset the administrator password?
Run this SQL command in terminal:
```bash
docker exec -i syslog-postgres psql -U syslog_admin -d syslog_manager -c \
  "UPDATE users SET password_hash = crypt('NewStrongPass2026!', gen_salt('bf', 10)), updated_at = NOW() WHERE username = 'admin';"
```

### Q4: What happens if disk storage runs low?
Valtrivo LogSeal features **intelligent FIFO disk retention**. When disk usage reaches the configured threshold, the oldest raw log partitions in ClickHouse are automatically pruned to prevent storage exhaustion.

---

**Valtrivo LogSeal Team**  
*“Her kayıt, zamanıyla kanıt.”*  
[https://github.com/v-e-kandjani/Logger](https://github.com/v-e-kandjani/Logger)
