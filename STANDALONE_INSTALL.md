# Standalone (Bare-Metal / No Docker) Installation Guide

This guide describes how to install and run **Valtrivo LogSeal** directly on **Ubuntu 20.04, 22.04, 24.04, and 26.04 LTS** (or Debian 11/12) without Docker or container engines.

In standalone mode, all components run natively as standard Linux `systemd` services:
- **Application Server (`syslog-platform`)**: Native compiled Go binary running as a high-performance system daemon.
- **Relational Metadata Store**: Native **PostgreSQL 14 / 15 / 16** via system service.
- **Log Data Warehouse**: Native **ClickHouse Server** via official repository and system service.
- **5651 Timestamp Engine**: Native **OpenJDK 17 JRE Headless** invoking the TÜBİTAK KamuSM TSS client.

---

## 1. Quick Automated Installation

Clone the repository and run the automated standalone installer:

```bash
git clone https://github.com/v-e-kandjani/Logger.git
cd Logger
sudo bash install_standalone.sh -y
```

### Command-Line Arguments

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-y`, `--defaults` | — | Non-interactive mode using default credentials |
| `--port <PORT>` | `8080` | Web Dashboard HTTP port |
| `--admin-user <USER>` | `admin` | Initial Super Administrator username |
| `--admin-pass <PASSWORD>`| `admin5651!` | Initial Super Administrator password |
| `-h`, `--help` | — | Display CLI help menu |

---

## 2. Directory Layout

The installer deploys the platform into `/opt/syslog-platform`:

```text
/opt/syslog-platform/
├── bin/
│   ├── syslog-platform         # Main server daemon binary
│   └── logseal-proxy           # Edge proxy daemon binary
├── config/
│   └── config.yaml             # Main configuration file
├── web/
│   ├── templates/              # HTML templates (index.html, login.html)
│   └── static/                 # CSS stylesheets, JS scripts, icons
├── archive/                    # 5651 deterministic hourly log archives
├── timestamp-client/           # TÜBİTAK KamuSM Java JAR & credentials
├── data/spool/                 # Local spool buffer
└── scripts/                    # Utility and load-testing scripts
```

---

## 3. Systemd Service Management

The installer creates and activates the `/etc/systemd/system/syslog-platform.service` unit:

```bash
# Check service status
sudo systemctl status syslog-platform

# View real-time application logs
sudo journalctl -u syslog-platform -f

# Restart application
sudo systemctl restart syslog-platform

# Stop / Start service
sudo systemctl stop syslog-platform
sudo systemctl start syslog-platform
```

### Underlying Database Services

```bash
# PostgreSQL service
sudo systemctl status postgresql

# ClickHouse Server service
sudo systemctl status clickhouse-server
```

---

## 4. Network & Firewall Configuration (UFW)

The installer configures UFW to allow incoming syslog traffic while shielding local database ports from public network access:

| Port | Protocol | Purpose | Access |
| :--- | :--- | :--- | :--- |
| `8080` | TCP | Web Dashboard HTTP | Public / Management LAN |
| `8443` | TCP | Web Dashboard HTTPS | Public / Management LAN |
| `514` | UDP/TCP | Syslog Standard Port | Network Devices |
| `5514` | UDP/TCP | Syslog Alternate Port | Network Devices / Proxies |
| `6514` | TCP | Syslog TLS (RFC 5425) | Secure Syslog Clients |
| `5432` | TCP | PostgreSQL Metadata | **Localhost Only (127.0.0.1)** |
| `9000` / `8123` | TCP | ClickHouse Native / HTTP | **Localhost Only (127.0.0.1)** |

---

## 5. Manual Step-by-Step Installation

If you prefer to install manually without the automated script:

### Step 1: Install PostgreSQL & OpenJDK 17
```bash
sudo apt-get update
sudo apt-get install -y postgresql postgresql-contrib openjdk-17-jre-headless build-essential
sudo systemctl enable --now postgresql
```

### Step 2: Configure PostgreSQL Database & User
```bash
sudo -u postgres psql -c "CREATE USER syslog_admin WITH PASSWORD 'syslog_secret';"
sudo -u postgres psql -c "CREATE DATABASE syslog_manager OWNER syslog_admin;"
sudo -u postgres psql -d syslog_manager -c "GRANT ALL ON SCHEMA public TO syslog_admin;"
```

### Step 3: Install ClickHouse Server
```bash
curl https://clickhouse.com/ | sh
sudo ./clickhouse install
sudo systemctl enable --now clickhouse-server
```

### Step 4: Apply Database Migrations
```bash
PGPASSWORD="syslog_secret" psql -h 127.0.0.1 -U syslog_admin -d syslog_manager -f migrations/postgres/001_initial_schema.sql
PGPASSWORD="syslog_secret" psql -h 127.0.0.1 -U syslog_admin -d syslog_manager -f migrations/postgres/002_siem_tables.sql

clickhouse-client --query "CREATE DATABASE IF NOT EXISTS syslog;"
clickhouse-client --multiquery < migrations/clickhouse/001_initial_events.sql
```

### Step 5: Compile Binary & Deploy Files
```bash
go build -trimpath -ldflags="-s -w" -o /opt/syslog-platform/bin/syslog-platform ./cmd/server/main.go
sudo cp -r web/templates /opt/syslog-platform/web/
sudo cp -r web/static /opt/syslog-platform/web/
sudo cp config/config.yaml /opt/syslog-platform/config/
```

### Step 6: Enable and Start Systemd Unit
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now syslog-platform
```

---

## 6. Updating the Standalone Application

To update an existing bare-metal installation:

```bash
cd /path/to/Logger
git pull origin main
go build -trimpath -ldflags="-s -w" -o /opt/syslog-platform/bin/syslog-platform ./cmd/server/main.go
sudo cp -r web/templates/* /opt/syslog-platform/web/templates/
sudo cp -r web/static/* /opt/syslog-platform/web/static/
sudo systemctl restart syslog-platform
```
