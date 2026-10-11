# LogSeal — Production Resource Profiles & Sizing Guidelines

**Document Version:** 1.0.0 (Phase 10 Certification)  
**Applicable Platform:** Valtrivo LogSeal v1.6.9+  
**Target OS:** Ubuntu 24.04 / 26.04 LTS, Debian 12+, RHEL 9+

---

## 1. Candidate Hardware Profiles

The following hardware profiles are benchmarked baseline candidates for standalone LogSeal installations. All profiles enforce strict management plane isolation (`siem-control.slice`) and data plane containment (`siem-data.slice`).

| Profile Tier | Host vCPU / RAM | Target Sustained Workload | Target Peak Burst | Storage Class | Recommended Topology |
|---|---|---|---|---|---|
| **Entry / Branch** | 4 vCPU / 16 GiB | 500 EPS (~43M ev/day) | 1,500 EPS | NVMe (≥ 500 GB) | Standalone Appliance |
| **Mid-Market / Corporate** | 16 vCPU / 64 GiB | 5,000 EPS (~432M ev/day) | 12,000 EPS | Enterprise NVMe PCIe 4.0 | Standalone or Split Engine |
| **Enterprise Core** | 32 vCPU / 128 GiB | 20,000 EPS (~1.72B ev/day) | 45,000 EPS | RAID-10 NVMe (U.2/U.3) | Distributed ClickHouse + Dedicated App |
| **SaaS / Multi-Tenant MSP**| 64+ vCPU / 256+ GiB | 50,000+ EPS (>4.3B ev/day) | 120,000 EPS | SAN / Ceph / NVMe Cluster | Sharded ClickHouse Cluster + NGINX LB |

> [!IMPORTANT]
> A single large server remains a single failure domain. For compliance (Law No. 5651) and 24/7 SIEM detection SLOs, high-throughput multi-tenant deployments must deploy at least 2 database replicas using `ReplicatedMergeTree` with ClickHouse Keeper or ClickHouse Cloud.

---

## 2. Whole-Host Memory Ledger & Budgeting

LogSeal uses a strict, non-borrowing whole-host memory ledger:

$$R = O + C + E + D$$

Where:
- **$R$**: Usable Physical Host RAM.
- **$O$**: Operating System, SSH daemon, monitoring agents, kernel buffers ($~2 \text{ GiB}$ on 16G, $~4 \text{ GiB}$ on 64G+).
- **$C$**: Control Plane envelope (PostgreSQL, `syslog-app` HTTP control API, Governor, SSH reserve).
- **$E$**: Emergency headroom withheld from normal allocations ($1\text{--}4 \text{ GiB}$) to prevent OOM panic.
- **$D$**: Aggregate Data Plane budget ($R - O - C - E$), allocated between ClickHouse, Ingestion queues, Detection workers, and Sealer.
- **$H$**: Data pressure threshold ($0.85 \times D$), where the Governor begins shedding analytical tasks and deferring reports.

### Detailed RAM Allocations by Profile

```text
+---------------------------------------------------------------------------------------+
| 16 GiB Host (Entry):   O=2.0 GiB | C=2.0 GiB | E=1.0 GiB | D=11.0 GiB (H=9.3 GiB)     |
| 64 GiB Host (Mid):     O=4.0 GiB | C=6.0 GiB | E=4.0 GiB | D=50.0 GiB (H=42.5 GiB)    |
| 128 GiB Host (Core):   O=8.0 GiB | C=12.0 GiB| E=8.0 GiB | D=100.0 GiB (H=85.0 GiB)   |
+---------------------------------------------------------------------------------------+
```

### Component Breakdown within Data Plane ($D$)

| Subsystem | 16 GiB Host | 64 GiB Host | 128 GiB Host | Notes |
|---|---|---|---|---|
| **ClickHouse Server** (`max_server_memory_usage`) | 7.5 GiB | 36.0 GiB | 72.0 GiB | Configured in `config.xml` |
| **Go Ingestion Queue Semaphore** | 1.0 GiB | 4.0 GiB | 8.0 GiB | Byte-bounded channel buffer |
| **Detection State (In-Memory Windows)** | 1.0 GiB | 4.0 GiB | 8.0 GiB | Bounded rule correlation table |
| **Archive Payload & JVM (TÜBİTAK TSA)** | 1.0 GiB | 4.0 GiB | 8.0 GiB | Headless Java 17 + ZSTD streaming |
| **Safety Headroom to $D$ Ceiling** | 0.5 GiB | 2.0 GiB | 4.0 GiB | Absorb transient allocations |

---

## 3. CPU Policy & cgroups v2 Slicing

To protect management access (SSH, Web UI, Governor) under hostile EPS saturation, LogSeal partitions processes into systemd slices:

### 3.1 Allocation Matrix

| Topology | Control Plane (`siem-control.slice`) | Data Plane (`siem-data.slice`) | Effective Worker Cap |
|---|---|---|---|
| **1 CPU** | CPU 0 (shared) | CPU 0 (shared) | `CPUQuota=70%` (20ms period) |
| **2 CPUs** | CPU 0 | CPU 1 | `AllowedCPUs=1`, `CPUQuota=100%` |
| **4 CPUs** | CPU 0 | CPUs 1–3 | `AllowedCPUs=1-3`, `CPUQuota=300%` |
| **16 CPUs** | CPU 0–1 | CPUs 2–15 | `AllowedCPUs=2-15`, `CPUQuota=1400%` |
| **32 CPUs** | CPU 0–1 | CPUs 2–31 | `AllowedCPUs=2-31`, `CPUQuota=3000%` |

### 3.2 Linux systemd Slice Configurations

Create `/etc/systemd/system/siem.slice`:
```ini
[Unit]
Description=LogSeal Unified Platform Parent Slice
Before=slices.target

[Slice]
MemoryAccounting=yes
CPUAccounting=yes
```

Create `/etc/systemd/system/siem-control.slice`:
```ini
[Unit]
Description=LogSeal Control & Management Plane (Protected)
PartOf=siem.slice

[Slice]
CPUWeight=800
MemoryMin=2G
MemoryLow=2G
```

Create `/etc/systemd/system/siem-data.slice`:
```ini
[Unit]
Description=LogSeal Data Plane (Bounded Ingestion, ClickHouse, Java TSA)
PartOf=siem.slice

[Slice]
CPUWeight=200
AllowedCPUs=1-15
CPUQuota=1400%
MemoryHigh=42G
MemoryMax=50G
```

---

## 4. Storage Capacity Worksheet

Use standard decimal units ($1 \text{ GB} = 10^9 \text{ bytes}$, $1 \text{ TB} = 10^{12} \text{ bytes}$) when sizing disks:

### 4.1 Equations

1. **Daily Volume:**
   $$\text{Events/Day} = \text{Average EPS} \times 86{,}400$$
   $$\text{Raw GB/Day} = \frac{\text{Average EPS} \times 86{,}400 \times \text{Avg Wire Bytes}}{10^9}$$

2. **ClickHouse Hot Analytical Storage:**
   $$\text{ClickHouse TB} = \frac{\text{Events/Day} \times \text{CH Stored Bytes/Event} \times \text{Retention Days} \times \text{Replicas}}{10^{12} \times \text{Target Utilization (0.80)}}$$
   *(Empirical average compressed event in ClickHouse: 110–140 bytes).*

3. **Hourly Law No. 5651 Evidence Archive Storage:**
   $$\text{Archive TB} = \frac{\text{Events/Day} \times \text{Compressed Archive Bytes/Event} \times \text{Retention Days}}{10^{12}}$$
   *(Empirical tar.gz + SHA256 archive: 85–115 bytes/event).*

4. **Edge Proxy WAN Outage Spool Sizing:**
   $$\text{Spool GB} = \frac{\text{Design Peak EPS} \times \text{Spool Wire Bytes/Event (350 B)} \times \text{Outage Seconds} \times \text{Safety Factor (1.5)}}{10^9}$$

5. **Network Ingress Bandwidth:**
   $$\text{Ingress Mbps} = \frac{\text{Peak EPS} \times \text{Avg Wire Bytes} \times 8}{10^6}$$

6. **Post-Outage Catch-Up Ingestion Budget:**
   $$\text{Recovery EPS} = \text{Live EPS} + \frac{\text{Spool Backlog Events}}{\text{Catch-up Window Seconds}}$$

### 4.2 Representative Sizing Reference Table

Assuming **350 bytes** raw wire event, **125 bytes** in ClickHouse (ZSTD), **100 bytes** in Law 5651 `.tar.gz`, 90 days analytical retention, and 730 days (2 years) legal evidence retention:

| Metric | 500 EPS (Entry) | 5,000 EPS (Mid) | 20,000 EPS (Core) |
|---|---|---|---|
| **Daily Events** | 43.2 Million | 432 Million | 1.728 Billion |
| **Daily Raw Ingest** | 15.1 GB / day | 151.2 GB / day | 604.8 GB / day |
| **Network Ingress (Peak 2x)** | 2.8 Mbps | 28.0 Mbps | 112.0 Mbps |
| **ClickHouse 90-day Hot Storage** | ~608 GB | ~6.08 TB | ~24.3 TB |
| **Law 5651 2-Year Archive Storage** | ~3.15 TB | ~31.5 TB | ~126.1 TB |
| **Edge Spool (24-hr WAN Outage)** | ~22.6 GB | ~226.8 GB | ~907.2 GB |
| **PostgreSQL Metadata Storage** | 25 GB | 120 GB | 400 GB |
| **Recommended OS Disk (NVMe)** | 100 GB | 250 GB | 500 GB |

---

## 5. Software & Engine Tuning Directives

### 5.1 ClickHouse Server (`/etc/clickhouse-server/config.d/tuning.xml`)
```xml
<clickhouse>
    <max_server_memory_usage>38654705664</max_server_memory_usage> <!-- 36 GiB for 64G Profile -->
    <max_concurrent_queries>60</max_concurrent_queries>
    <max_memory_usage>12884901888</max_memory_usage>              <!-- 12 GiB max per single analytical query -->
    <background_pool_size>16</background_pool_size>
    <background_merges_mutations_concurrency_ratio>2</background_merges_mutations_concurrency_ratio>
    <parts_to_delay_insert>150</parts_to_delay_insert>
    <parts_to_throw_insert>300</parts_to_throw_insert>
</clickhouse>
```

### 5.2 PostgreSQL Server (`/etc/postgresql/16/main/postgresql.conf`)
```ini
# Sized for 64 GiB host Control Plane (6 GiB envelope)
shared_buffers = 2GB
effective_cache_size = 4GB
maintenance_work_mem = 512MB
work_mem = 32MB
max_connections = 150
wal_buffers = 64MB
checkpoint_completion_target = 0.9
max_wal_size = 16GB
min_wal_size = 2GB
random_page_cost = 1.1 # NVMe SSD storage
```

### 5.3 Go Runtime Environment (`/etc/default/syslog-platform`)
```bash
# 64 GiB Profile: Pin Go to 14 cores, 12 GiB soft limit
GOMAXPROCS=14
GOMEMLIMIT=12GiB
```
