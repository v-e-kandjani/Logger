# MITRE ATT&CK® Integration & Synchronization Guide
### Valtrivo LogSeal SIEM Security Architecture

---

## 1. Executive Overview

A modern **Security Information and Event Management (SIEM)** platform must transcend basic log storage: it must contextualize security events against recognized adversary tactics and techniques. 

**Valtrivo LogSeal SIEM** incorporates the globally recognized **MITRE ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge)** Enterprise framework. This enables security operations centers (SOC) and system administrators to:
1. **Map security incidents** directly to standardized adversary behaviors (e.g. Brute Force `T1110`, Port Probing `T1046`, Sudo Abuse `T1548.003`).
2. **Quantify defensive posture** across the 14 Enterprise ATT&CK tactical objectives.
3. **Continuously synchronize** technique definitions from the official MITRE STIX 2.1 knowledgebase or maintain local air-gapped matrices.
4. **Author detection rules** that correlate vendor syslog events into high-confidence MITRE-tagged security alerts.

---

## 2. MITRE ATT&CK Enterprise Matrix Architecture

The Enterprise ATT&CK matrix categorizes adversary behavior into **14 Tactical Objectives**, spanning the entire cyber attack lifecycle:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        MITRE ATT&CK® ENTERPRISE MATRIX                                 │
├──────────────┬──────────────┬──────────────┬──────────────┬──────────────┬─────────────┤
│ Reconnaissance│ Resource Dev │ Initial Access│  Execution   │ Persistence  │ Priv Esc    │
│   (TA0043)   │   (TA0042)   │   (TA0001)   │   (TA0002)   │   (TA0003)   │  (TA0004)   │
├──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼─────────────┤
│Def. Evasion  │  Cred Access │  Discovery   │ Lateral Mvmt │  Collection  │  C2         │
│   (TA0005)   │   (TA0006)   │   (TA0007)   │   (TA0008)   │   (TA0009)   │  (TA0011)   │
├──────────────┴──────────────┼──────────────┴──────────────┴──────────────┴─────────────┤
│        Exfiltration         │                   Impact                                 │
│          (TA0010)           │                  (TA0040)                                │
└─────────────────────────────┴──────────────────────────────────────────────────────────┘
```

Each tactic contains hundreds of granular **Techniques** (e.g., `T1110`) and **Sub-Techniques** (e.g., `T1110.003`).

---

## 3. How Valtrivo LogSeal Ingests, Normalizes & Maps to MITRE

The transformation from raw vendor syslog text to a MITRE ATT&CK security incident follows a 4-tier pipeline:

```
[Raw Syslog Packet]
      │
      ▼
[1. Multi-Vendor Parser] ─── (Fortinet, Cisco ASA, WatchGuard, Linux, Windows)
      │
      ▼
[2. Normalization Schema] ── (event_category, event_action, event_outcome, src_ip, user)
      │
      ▼
[3. Correlation Engine] ──── (Sliding window bucket evaluation, threshold triggers)
      │
      ▼
[4. MITRE Tagged Alert] ──── (Tactics: "Credential Access", Technique: "T1110")
```

### Normalization Examples

| Vendor / Source | Sample Raw Log Fragment | Normalized Event | MITRE Technique Mapping |
|---|---|---|---|
| **FortiGate Firewall** | `action="login-failed" status="failed" user="admin" srcip=198.51.100.4` | `category=authentication`, `action=login-failed`, `outcome=failure` | **T1110 (Brute Force)** |
| **FortiGate IPS** | `attack="Apache.Struts.RCE" action="deny" srcip=203.0.113.88` | `category=threat`, `action=malware-blocked`, `outcome=blocked` | **T1190 (Exploit Public-Facing App)** |
| **Cisco ASA** | `%ASA-4-106023: Deny tcp src outside:192.0.2.1/51234 dst inside:10.0.0.5/445` | `category=network`, `action=connection-denied`, `outcome=blocked` | **T1046 (Network Service Discovery)** |
| **Linux Auth / SSH** | `sshd[1024]: Failed password for invalid user root from 185.x.x.x` | `category=authentication`, `action=login-failed`, `outcome=failure` | **T1110 (Brute Force)** |
| **Linux Sudo** | `sudo: pam_unix(sudo:auth): authentication failure; logname=alex uid=1000` | `category=system`, `action=privilege-escalation`, `outcome=failure` | **T1548.003 (Sudo and Sudoers)** |
| **Windows Security** | `EventID 4625: An account failed to log on. Account: Administrator` | `category=authentication`, `action=login-failed`, `outcome=failure` | **T1110 (Brute Force)** |
| **Windows Security** | `EventID 4720: A user account was created. Target: backdoor_admin` | `category=configuration`, `action=account-created`, `outcome=success` | **T1136.001 (Local Account Creation)** |

---

## 4. Built-In Detection Rules & MITRE Coverage

Out of the box, Valtrivo LogSeal SIEM comes seeded with operational detection rules pre-mapped to ATT&CK:

```
┌───────────┬──────────────────────────────────────────┬────────────────────────┬───────────────────┐
│ Rule ID   │ Detection Rule Name                      │ MITRE Tactic           │ MITRE Technique   │
├───────────┼──────────────────────────────────────────┼────────────────────────┼───────────────────┤
│ AUTH-001  │ Multiple Failed Logins (Brute Force)     │ Credential Access      │ T1110             │
│ AUTH-002  │ Multi-Account Password Spraying          │ Credential Access      │ T1110.003         │
│ NET-001   │ Horizontal Port Scan / Reconnaissance    │ Discovery              │ T1046             │
│ NET-002   │ Perimeter Firewall Denial Flood          │ Impact                 │ T1499             │
│ SYS-001   │ Privilege Escalation Failure (Sudo / Su) │ Privilege Escalation   │ T1548.003         │
│ SYS-002   │ Local Account Creation / Persistence     │ Persistence            │ T1136.001         │
│ THREAT-001│ Perimeter Threat / Exploit Blocked       │ Initial Access         │ T1190             │
└───────────┴──────────────────────────────────────────┴────────────────────────┴───────────────────┘
```

---

## 5. How the App Gets & Updates the MITRE ATT&CK Database

Valtrivo LogSeal SIEM supports three synchronization methods to fetch and maintain MITRE ATT&CK definitions:

### Method 1: Automated Web UI / REST API Sync (Online)

The platform provides a built-in REST endpoint that streams and parses the official MITRE Enterprise ATT&CK STIX 2.1 JSON catalog directly from the MITRE GitHub organization:

* **Official Source**: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
* **API Route**: `POST /api/v1/siem/mitre/sync`

#### CLI Invocation:
```bash
# Authenticate and trigger MITRE ATT&CK matrix sync
curl -X POST http://127.0.0.1:8080/api/v1/siem/mitre/sync \
     -H "Content-Type: application/json" \
     -b "session_token=<YOUR_ADMIN_SESSION_TOKEN>" \
     -d '{}'
```

#### JSON Response:
```json
{
  "success": true,
  "synced_techniques": 635,
  "message": "Successfully synchronized 635 MITRE ATT&CK techniques"
}
```

The synchronization engine:
1. Streams STIX 2.1 objects without exhausting server RAM.
2. Filters for active `attack-pattern` objects (ignoring deprecated or revoked items).
3. Extracts external references (`mitre-attack` IDs such as `T1110`, `T1059`).
4. Maps kill-chain phases directly to the 14 Enterprise Tactics (`reconnaissance`, `initial-access`, `credential-access`, etc.).
5. Updates in-memory lookup maps and records an audit log (`SIEM_MITRE_SYNC`).

---

### Method 2: Air-Gapped & Offline Synchronization

For isolated or high-security networks without direct Internet access:

1. Download the latest official MITRE STIX 2.1 bundle from an internet-connected workstation:
   ```bash
   curl -s -O https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
   ```

2. Copy the file to your Valtrivo LogSeal server:
   ```bash
   scp enterprise-attack.json alex@168.231.106.208:/home/alex/projects/logger/enterprise-attack.json
   ```

3. Trigger the sync specifying the local file path:
   ```bash
   curl -X POST http://127.0.0.1:8080/api/v1/siem/mitre/sync \
        -H "Content-Type: application/json" \
        -b "session_token=<YOUR_ADMIN_SESSION_TOKEN>" \
        -d '{"file_path": "/home/alex/projects/logger/enterprise-attack.json"}'
   ```

---

### Method 3: Lightweight Custom JSON Schema

You can also import a curated subset of techniques using our simple JSON schema:

```json
{
  "version": "Custom Corporate SOC Matrix v2.0",
  "techniques": [
    {
      "id": "T1078",
      "name": "Valid Accounts",
      "tactic_id": "TA0003",
      "tactic_name": "Persistence",
      "description": "Adversaries abuse legitimate credentials to maintain access.",
      "url": "https://attack.mitre.org/techniques/T1078/"
    },
    {
      "id": "T1021.001",
      "name": "Remote Desktop Protocol",
      "tactic_id": "TA0008",
      "tactic_name": "Lateral Movement",
      "description": "Adversaries log into interactive desktop sessions to expand presence.",
      "url": "https://attack.mitre.org/techniques/T1021/001/"
    }
  ]
}
```

---

## 6. How to Query Current ATT&CK Matrix Coverage

You can inspect your organization's MITRE coverage and triggered incident statistics in real time:

* **Endpoint**: `GET /api/v1/siem/mitre`
* **Response Structure**:

```json
{
  "version": "v15.1 Enterprise Matrix",
  "last_updated": "2026-10-08T18:00:00Z",
  "source": "Embedded Enterprise ATT&CK Baseline",
  "total_tactics": 14,
  "total_techniques": 24,
  "covered_techniques": 7,
  "total_alerts_mapped": 14,
  "tactics": [
    {
      "id": "TA0006",
      "name": "Credential Access",
      "total_techniques": 4,
      "covered_techniques": 2,
      "coverage_percent": 50.0,
      "techniques": [
        {
          "id": "T1110",
          "name": "Brute Force",
          "covered": true,
          "rule_ids": ["AUTH-001"],
          "rule_names": ["Multiple Failed Logins (Brute Force)"],
          "alert_count": 8,
          "last_seen_alert": "2026-10-08T18:14:00Z"
        }
      ]
    }
  ]
}
```

---

## 7. Authoring New Detection Rules Mapped to MITRE

When adding a custom detection rule (via SQL or API), assign the relevant `mitre_tactic` and `mitre_technique`:

### SQL Example: Detect RDP Lateral Movement Probes (`T1021.001`)

```sql
INSERT INTO siem_rules (
    id, name, description, severity, risk_score, category,
    threshold, timeframe_seconds, group_by,
    mitre_tactic, mitre_technique, is_enabled,
    match_category, match_action, match_outcome
) VALUES (
    'LAT-001',
    'Suspicious RDP Inbound Connection Spike',
    'Detects rapid RDP port 3389 connections from an internal host indicating lateral movement',
    'HIGH',
    80,
    'network',
    5,
    120,
    ARRAY['source_ip'],
    'Lateral Movement',
    'T1021.001',
    TRUE,
    'network',
    'connection-denied',
    'blocked'
) ON CONFLICT (id) DO NOTHING;
```

---

## 8. SOC Analyst Triage Workflow with MITRE Context

When an incident triggers in the **SOC Operations Console**:
1. The alert card highlights the **MITRE ATT&CK Tactic badge** (e.g., `Credential Access`) and **Technique link** (`T1110`).
2. Clicking the technique tag displays official MITRE mitigation recommendations, detection strategies, and common adversary groups (APT28, APT29, FIN7).
3. The analyst can view all **Raw Forensic Evidence Logs** captured inside the detection sliding window.
4. The analyst records case notes and transitions the state (`NEW` ➔ `INVESTIGATING` ➔ `RESOLVED` / `FALSE_POSITIVE`).

---

## Automatic Release Activation & Persistence (v1.3.9+)

- **Persistence**: Every successful sync stores the parsed catalog (tactics, techniques, sub-techniques, ATT&CK version, feed ETag) in PostgreSQL table `mitre_catalog_cache`. It is restored at startup, so restarts and upgrades no longer revert to the embedded 30-technique baseline.
- **Release watcher**: ~45 s after startup and then every `MITRE_SYNC_INTERVAL_HOURS` (default 24) the server sends a conditional `If-None-Match` request to the feed. `304 Not Modified` → nothing to do. A changed feed is downloaded, parsed and activated immediately; techniques that did not exist in the previous catalog are flagged `is_new` and shown with a **NEW** badge plus a release banner in the matrix.
- **Dynamic tactics**: Tactics and their order come from the STIX `x-mitre-tactic` / `x-mitre-matrix` objects, so newly introduced tactics (e.g. ATT&CK v19 *Defense Impairment* TA0112) appear without a code change. Techniques are listed under every tactic they belong to.
- **Controls**:
  | Setting | Purpose |
  |---|---|
  | Matrix modal → “Auto-activate new ATT&CK releases” | Enable/disable the watcher (persisted in settings) |
  | Matrix modal → “Check for New Release” | Run the conditional check now |
  | `MITRE_AUTO_SYNC=false` | Disable watcher by default |
  | `MITRE_SYNC_INTERVAL_HOURS=24` | Check interval |
  | `MITRE_STIX_URL=<url>` | Internal mirror for air-gapped networks |
- **API**: `GET /api/v1/siem/mitre/autosync` (status), `POST {"enabled":bool}` or `POST {"check_now":true}`.
