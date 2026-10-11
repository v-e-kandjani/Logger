#!/usr/bin/env bash
# ==============================================================================
# Valtrivo LogSeal - Cgroups v2 & Systemd Slices Automated Setup
# Designed for Ubuntu Server 26.04, 24.04 & 22.04 LTS
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo " Valtrivo LogSeal - Cgroups v2 Resource Governor Setup"
echo "======================================================================"

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (sudo)." >&2
    exit 1
fi

# 1. Preflight Cgroups v2 Check
echo "[*] Step 1: Preflight Cgroups v2 unified hierarchy validation..."
if [ -d "/sys/fs/cgroup" ]; then
    CG_TYPE=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo "unknown")
    if [ "$CG_TYPE" != "cgroup2fs" ]; then
        echo "[-] Error: Unified cgroup v2 (cgroup2fs) required, found: $CG_TYPE" >&2
        echo "    Add 'systemd.unified_cgroup_hierarchy=1' to kernel cmdline and reboot." >&2
        exit 1
    fi
    echo "[+] Verified: cgroups v2 unified filesystem active."
else
    echo "[-] Error: /sys/fs/cgroup directory not found." >&2
    exit 1
fi

CONTROLLERS=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo "")
echo "[*] Available root controllers: $CONTROLLERS"
for c in cpu cpuset memory; do
    if [[ ! " $CONTROLLERS " =~ " $c " ]]; then
        echo "[!] Warning: '$c' controller not visible in root cgroup.controllers."
    fi
done

# 2. Topology Discovery
TOTAL_CPUS=$(nproc --all || grep -c ^processor /proc/cpuinfo || echo 1)
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}' || echo 0)
TOTAL_RAM_MB=$(( TOTAL_RAM_KB / 1024 ))
TOTAL_RAM_GB=$(( TOTAL_RAM_MB / 1024 ))

echo "[*] Step 2: System Topology Detected:"
echo "    - Total Logical CPUs : $TOTAL_CPUS"
echo "    - Total Physical RAM : ${TOTAL_RAM_GB} GB (${TOTAL_RAM_MB} MB)"

# Determine CPU Quota & Set
if [ "$TOTAL_CPUS" -le 1 ]; then
    DATA_CPUS="0"
    DATA_QUOTA="70%"
    CTRL_CPUS="0"
    echo "[*] Applying Single-CPU Profile (Shared CPU 0, Worker Quota: 70%)"
elif [ "$TOTAL_CPUS" -eq 2 ]; then
    DATA_CPUS="1"
    DATA_QUOTA="100%"
    CTRL_CPUS="0"
    echo "[*] Applying Dual-CPU Profile (Management on CPU 0, Workers on CPU 1 [100%])"
elif [ "$TOTAL_CPUS" -eq 8 ]; then
    DATA_CPUS="1-7"
    DATA_QUOTA="700%"
    CTRL_CPUS="0"
    echo "[*] Applying 8-CPU Profile (Management on CPU 0, Workers on CPUs 1-7 [700%])"
else
    LAST_CPU=$(( TOTAL_CPUS - 1 ))
    DATA_CPUS="1-${LAST_CPU}"
    DATA_QUOTA="$(( (TOTAL_CPUS - 1) * 100 ))%"
    CTRL_CPUS="0"
    echo "[*] Applying Multi-CPU Profile (Management on CPU 0, Workers on CPUs 1-${LAST_CPU} [${DATA_QUOTA}])"
fi

# Determine RAM Limits (D = Total - OS - Control - Emergency)
# O=2G, C=2G, E=1G -> Reserve at least 4-5G if machine has >= 8G
if [ "$TOTAL_RAM_GB" -ge 16 ]; then
    DATA_MEM_MAX="11G"
    DATA_MEM_HIGH="9G"
    CTRL_MEM_MAX="2G"
    CTRL_MEM_HIGH="1792M"
elif [ "$TOTAL_RAM_GB" -ge 8 ]; then
    DATA_MEM_MAX="5G"
    DATA_MEM_HIGH="4G"
    CTRL_MEM_MAX="1536M"
    CTRL_MEM_HIGH="1280M"
elif [ "$TOTAL_RAM_GB" -ge 4 ]; then
    DATA_MEM_MAX="2500M"
    DATA_MEM_HIGH="2000M"
    CTRL_MEM_MAX="1024M"
    CTRL_MEM_HIGH="800M"
else
    DATA_MEM_MAX="$(( TOTAL_RAM_MB * 60 / 100 ))M"
    DATA_MEM_HIGH="$(( TOTAL_RAM_MB * 50 / 100 ))M"
    CTRL_MEM_MAX="$(( TOTAL_RAM_MB * 30 / 100 ))M"
    CTRL_MEM_HIGH="$(( TOTAL_RAM_MB * 25 / 100 ))M"
fi

echo "[*] Step 3: Generating systemd slices in /etc/systemd/system/..."

# Write siem.slice
cat <<EOF > /etc/systemd/system/siem.slice
[Unit]
Description=LogSeal SIEM Root Slice
Documentation=https://github.com/v-e-kandjani/Logger
Before=slices.target

[Slice]
CPUAccounting=yes
MemoryAccounting=yes
IOAccounting=yes
MemoryLow=1024M
MemoryMin=512M
EOF

# Write siem-control.slice
cat <<EOF > /etc/systemd/system/siem-control.slice
[Unit]
Description=LogSeal SIEM Management & Control Services Slice
Documentation=https://github.com/v-e-kandjani/Logger
Before=slices.target

[Slice]
CPUAccounting=yes
MemoryAccounting=yes
IOAccounting=yes
AllowedCPUs=${CTRL_CPUS}
CPUWeight=1000
MemoryLow=512M
MemoryMin=256M
MemoryHigh=${CTRL_MEM_HIGH}
MemoryMax=${CTRL_MEM_MAX}
EOF

# Write siem-data.slice
cat <<EOF > /etc/systemd/system/siem-data.slice
[Unit]
Description=LogSeal SIEM Aggregate Worker & Data Ingestion Budget Slice
Documentation=https://github.com/v-e-kandjani/Logger
Before=slices.target

[Slice]
CPUAccounting=yes
MemoryAccounting=yes
IOAccounting=yes
AllowedCPUs=${DATA_CPUS}
CPUQuota=${DATA_QUOTA}
CPUQuotaPeriodSec=20ms
CPUWeight=100
MemoryHigh=${DATA_MEM_HIGH}
MemoryMax=${DATA_MEM_MAX}
MemorySwapMax=0
EOF

# 4. Activate Slices
echo "[*] Step 4: Reloading systemd daemon and enabling slices..."
systemctl daemon-reload
systemctl start siem.slice siem-control.slice siem-data.slice || true

echo "[+] Success! Slices active:"
systemctl status siem.slice --no-pager || true
echo "======================================================================"
echo "[✓] Cgroups v2 & Systemd Slice Configuration Complete!"
echo "======================================================================"
