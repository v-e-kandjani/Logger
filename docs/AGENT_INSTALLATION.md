# LOGGER Agent - Cross-Platform Installation & Deployment Guide

> **Valtrivo LogSeal Endpoint Security Subsystem**  
> Native Lightweight Cross-Platform Agent Daemon (`logger-agent`)  
> Supported Platforms: **Linux** (systemd), **Windows** (Service), **macOS** (launchd), and **Docker / Containers**

---

## 1. Architecture & Network Requirements

The LOGGER Agent is an ultra-lightweight, native compiled Go daemon designed for continuous endpoint telemetry, live asset inventory, vulnerability assessment, and security log streaming.

### Network Communication Profile:
- **Direction**: **100% Outbound Only** (The agent initiates all connections; **zero inbound open ports** are required on endpoints).
- **Protocol**: HTTP/2 over TLS (or HTTP during local testing).
- **Default Ports**:
  - `8080` (HTTP) or `8443` (HTTPS) to Central LogSeal Server.
- **Traffic Profile**:
  - **Enrollment**: 1-time mutual handshake returning unique agent UUID and signed JWT auth token.
  - **Heartbeat**: Periodic lightweight JSON telemetry ping (default: every 30 seconds with ±10% jitter).
  - **Payload Size**: ~1.5 KB per heartbeat (CPU %, RAM RSS, Queue depth, policy revision).

---

## 2. Enrollment Token Generation

Before deploying agents, generate an enrollment token:
1. Open the LogSeal Web Dashboard and navigate to **Endpoint Security > Kurulum & Belirteçler (Deployment & Tokens)**.
2. Click **+ Yeni Kurulum Belirteci (+ New Enrollment Token)**.
3. Configure:
   - **Token Name**: e.g., `Production Linux Servers` or `HQ Windows Laptops`.
   - **Tenant Scope**: Target customer organization or `default`.
   - **Max Uses**: `0` for unlimited, or a specific limit (e.g., `50`).
   - **Single-Use**: Restricts each token to exactly one agent registration.
   - **Allowed OS**: Optional platform filter (Linux, Windows, macOS).
   - **Expiration**: Optional validity window (e.g. 7 days).
4. Copy the generated token starting with `lp_ea_...`.

---

## 3. Platform Installation Guides

### A. Linux (Ubuntu, Debian, RHEL, Rocky Linux, CentOS, Alpine, SUSE)

#### Method 1: 1-Click Automated Installer (Recommended)
Run the following single command in terminal as root or with `sudo`:

```bash
curl -sSL http://<LOGSEAL_SERVER>:8080/static/scripts/install-agent.sh | sudo bash -s -- \
  --server "http://<LOGSEAL_SERVER>:8080" \
  --token "<ENROLLMENT_TOKEN>"
```

*For HTTPS with self-signed certificate, append `--insecure`:*
```bash
curl -k -sSL https://<LOGSEAL_SERVER>:8443/static/scripts/install-agent.sh | sudo bash -s -- \
  --server "https://<LOGSEAL_SERVER>:8443" \
  --token "<ENROLLMENT_TOKEN>" \
  --insecure
```

#### Method 2: Manual Installation & Systemd Service
1. **Create directories**:
   ```bash
   sudo mkdir -p /opt/logger-agent/bin /etc/logger-agent /var/log/logger-agent
   ```
2. **Place the binary**:
   ```bash
   sudo cp logger-agent /opt/logger-agent/bin/logger-agent
   sudo chmod +x /opt/logger-agent/bin/logger-agent
   ```
3. **Create `/etc/logger-agent/config.json`**:
   ```json
   {
     "server_url": "http://<LOGSEAL_SERVER>:8080",
     "enrollment_token": "lp_ea_YOUR_TOKEN_HERE",
     "insecure_tls": false,
     "log_level": "info",
     "data_dir": "/opt/logger-agent/data",
     "heartbeat_interval_sec": 30,
     "identity_file": "/etc/logger-agent/identity.json"
   }
   ```
   ```bash
   sudo chmod 600 /etc/logger-agent/config.json
   ```
4. **Create `/etc/systemd/system/logger-agent.service`**:
   ```ini
   [Unit]
   Description=Valtrivo LogSeal Native Endpoint Agent
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=root
   ExecStart=/opt/logger-agent/bin/logger-agent -config /etc/logger-agent/config.json
   Restart=always
   RestartSec=5s
   LimitNOFILE=65536
   StandardOutput=append:/var/log/logger-agent/agent.log
   StandardError=append:/var/log/logger-agent/agent-error.log

   [Install]
   WantedBy=multi-user.target
   ```
5. **Enable and start the service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now logger-agent
   sudo systemctl status logger-agent
   ```

---

### B. Windows (Windows 10, 11 & Windows Server 2016, 2019, 2022, 2025)

#### Method 0: Standalone Windows .exe Setup Wizard (Easiest & SCCM/GPO Ready)
Download `logger-agent-setup.exe` directly from the LogSeal dashboard (`/static/downloads/logger-agent-setup.exe`).

- **Interactive Install**: Double-click `logger-agent-setup.exe` as Administrator. It will interactively prompt for Server URL and Enrollment Token, extract files to `C:\Program Files\LOGGER Agent`, configure `config.json`, register the `LoggerAgent` Windows Service, and register in Windows Add/Remove Programs.
- **Silent Automated Install (SCCM / GPO / Intune)**:
  ```cmd
  logger-agent-setup.exe -server "http://<LOGSEAL_SERVER>:8080" -token "<ENROLLMENT_TOKEN>" -silent
  ```
- **Custom Install Directory & Insecure TLS**:
  ```cmd
  logger-agent-setup.exe -server "https://<LOGSEAL_SERVER>:8443" -token "<ENROLLMENT_TOKEN>" -insecure -dir "D:\Security\LOGGER Agent" -silent
  ```
- **Uninstall**:
  ```cmd
  logger-agent-setup.exe -uninstall
  ```
  *(Or uninstall directly from Windows Settings > Installed Apps / Control Panel Programs and Features).*

#### Method 1: Automated PowerShell 1-Liner (Administrator)
Open **PowerShell as Administrator** and execute:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
iwr -useb "http://<LOGSEAL_SERVER>:8080/static/scripts/install-agent.ps1" -OutFile "$env:TEMP\install-agent.ps1";
& "$env:TEMP\install-agent.ps1" -Server "http://<LOGSEAL_SERVER>:8080" -Token "<ENROLLMENT_TOKEN>"
```

#### Method 2: Manual Installation as Windows Service
1. Create directory `C:\Program Files\LOGGER Agent\`.
2. Copy `logger-agent.exe` into `C:\Program Files\LOGGER Agent\`.
3. Create `config.json` inside `C:\Program Files\LOGGER Agent\config.json`:
   ```json
   {
     "server_url": "http://<LOGSEAL_SERVER>:8080",
     "enrollment_token": "lp_ea_YOUR_TOKEN_HERE",
     "insecure_tls": false,
     "log_level": "info",
     "data_dir": "C:\\Program Files\\LOGGER Agent\\data",
     "heartbeat_interval_sec": 30,
     "identity_file": "C:\\Program Files\\LOGGER Agent\\identity.json"
   }
   ```
4. Register the Windows Service using `sc.exe`:
   ```cmd
   sc.exe create LoggerAgent binPath= "\"C:\Program Files\LOGGER Agent\logger-agent.exe\" -config \"C:\Program Files\LOGGER Agent\config.json\"" start= auto DisplayName= "LogSeal Endpoint Security Agent"
   sc.exe description LoggerAgent "Valtrivo LogSeal endpoint telemetry and security daemon"
   sc.exe failure LoggerAgent reset= 86400 actions= restart/5000/restart/10000/restart/60000
   net start LoggerAgent
   ```
5. Verify service status in PowerShell:
   ```powershell
   Get-Service LoggerAgent
   ```

---

### C. macOS (Apple Silicon M1/M2/M3/M4 & Intel x86_64)

#### Method 0: macOS Disk Image (.dmg) & Apple Installer Package (.pkg) (Easiest)
Download `LOGGER-Agent-Installer.dmg` from the LogSeal dashboard (`/static/downloads/logger-agent-installer.dmg`).

1. Double-click `LOGGER-Agent-Installer.dmg` to mount the image.
2. Inside the DMG you will find:
   - **`Install LOGGER Agent.pkg`**: Native macOS Installer package with Universal ARM64/Intel binary. Double-click and follow the standard macOS installation wizard.
   - **`Install LOGGER Agent.command`**: Interactive Terminal setup script. Double-click to run; prompts for Server URL and Token, copies binary to `/opt/logger-agent`, and loads the `launchd` daemon.
   - **`Uninstall LOGGER Agent.command`**: Clean uninstaller script that unloads launchd daemon and deletes `/opt/logger-agent`.

#### Method 1: Automated Script Install (Terminal / Sudo)
Open Terminal and run with `sudo`:

```bash
curl -sSL http://<LOGSEAL_SERVER>:8080/static/scripts/install-agent.sh | sudo bash -s -- \
  --server "http://<LOGSEAL_SERVER>:8080" \
  --token "<ENROLLMENT_TOKEN>"
```

#### Managing the launchd Daemon on macOS:
- **Check Status**: `sudo launchctl list | grep logger`
- **View Logs**: `tail -f /var/log/logger-agent/agent.log`
- **Stop Daemon**: `sudo launchctl unload /Library/LaunchDaemons/com.valtrivo.logger-agent.plist`
- **Start Daemon**: `sudo launchctl load -w /Library/LaunchDaemons/com.valtrivo.logger-agent.plist`

---

### D. Docker Container / Container Host

To run the agent on containerized hosts (e.g., CoreOS, Alpine container host):

```bash
docker run -d \
  --name logger-agent \
  --restart unless-stopped \
  --net=host \
  --pid=host \
  -v /etc/logger-agent:/etc/logger-agent \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  logger-agent:latest \
  -server "http://<LOGSEAL_SERVER>:8080" \
  -token "<ENROLLMENT_TOKEN>"
```

---

## 4. Verification & Health Inspection

Once the agent is running:

1. **Check Agent CLI Version**:
   ```bash
   logger-agent -v
   # Output: LOGGER Agent v0.1.0 (Commit: 324f698, Built: 2026-10-21, linux/amd64)
   ```
2. **Inspect Local Agent Logs**:
   - **Linux / macOS**: `tail -f /var/log/logger-agent/agent.log`
   - **Windows**: `Get-Content "C:\Program Files\LOGGER Agent\agent.log" -Tail 20`
   - Expected Output:
     ```
     [LOGGER Agent] Initialized identity: UUID=7ad19566-... Hostname=srv-web-01
     [LOGGER Agent] Enrolling with LogSeal server at http://192.168.1.100:8080...
     [LOGGER Agent] Enrollment successful! Assigned to tenant 'default'
     [LOGGER Agent] Heartbeat sent successfully (status: 200)
     ```
3. **Web Dashboard Verification**:
   - Open **Endpoint Security > Ajanlar (Agents)**.
   - The newly registered host will appear immediately with a green **Healthy (Online)** status badge, its authentic internal IP, OS version, kernel, and initial hardware inventory.

---

## 5. Uninstallation

### Linux:
```bash
sudo systemctl stop logger-agent
sudo systemctl disable logger-agent
sudo rm -f /etc/systemd/system/logger-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/logger-agent /etc/logger-agent /var/log/logger-agent
```

### Windows:
```powershell
Stop-Service LoggerAgent -Force
& sc.exe delete LoggerAgent
Remove-Item -Recurse -Force "C:\Program Files\LOGGER Agent"
```

### macOS:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.valtrivo.logger-agent.plist
sudo rm -f /Library/LaunchDaemons/com.valtrivo.logger-agent.plist
sudo rm -rf /opt/logger-agent /etc/logger-agent /var/log/logger-agent
```
