# ADCS Watchdog

> **Active Directory Certificate Services (ADCS) audit tool — ESC1-9 detection, GUID-aware ACL analysis, interactive web dashboard, Excel/JSON export and scan-to-scan diff tracking.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Parrot%20%7C%20Ubuntu-lightgrey)

---

## What it does

ADCS Watchdog connects to Active Directory via LDAP, enumerates all certificate templates and Enterprise CAs, parses every Security Descriptor at the binary level with full GUID-awareness, and serves an interactive HTML dashboard locally on any port.

### Key features

| Feature | Details |
|---|---|
| **ESC1–ESC9 detection** | Every condition verified individually — no false positives |
| **GUID-aware ACL parser** | Distinguishes `WriteProperty[msPKI-*]` (ESC4) from `WriteProperty[Certificate-Enrollment]` (enroll only) |
| **Full ACL table** | All principals classified: `[HIGH]` `[LOW]` `[UNKNOWN]` `[SYSTEM]` |
| **Principal analysis** | Per-template breakdown of what each group has vs what they need |
| **Raw tool verification** | Simulated `ldapsearch`, `dacledit`, `bloodyAD` output per template |
| **Built-in ESC Guide** | Reference page explaining every ESC with exact conditions and exploit commands |
| **Excel export** | Multi-sheet `.xlsx` — Summary, ACL Details, ESC Findings, Changes, CAs |
| **JSON export** | Full structured report for automation or SIEM ingestion |
| **Scan history & diff** | Every run saved — new findings and ACL changes shown between scans |
| **Multi-filter dashboard** | Combine severity × ESC type × principal tier filters simultaneously |

---

## Requirements

- Python 3.8+
- Network access to target DC on **port 389 (LDAP)**
- Any valid domain account — standard user is enough for a full read-only audit

---

## Installation

### Quick (recommended)

```bash
git clone https://github.com/c0desBym3ta/adcs-watchdog.git
cd adcs-watchdog
chmod +x install.sh && ./install.sh
```

### Manual

```bash
git clone https://github.com/c0desBym3ta/adcs-watchdog.git
cd adcs-watchdog
pip install -r requirements.txt
```

### Kali / Parrot (system Python)

```bash
pip install -r requirements.txt --break-system-packages
```

### Isolated venv

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

```bash
python3 adcs_watchdog.py -u USER@DOMAIN -p 'PASSWORD' -d DC_IP
```

Open **http://localhost:4000** in your browser.

### All options

```
required:
  -u, --user        Username  (user@domain or DOMAIN\user)
  -p, --password    Password
  -d, --dc-ip       Domain Controller IP

optional:
  --domain          Domain FQDN — auto-detected from -u if omitted
  --port            HTTP port to serve on  (default: 4000)
  --no-ntlm         Use SIMPLE bind instead of NTLM
  --output FILE     Also save HTML report to disk
```

### Examples

```bash
# Standard run
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5

# Custom port
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5 --port 8080

# Save HTML report to disk as well
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5 --output audit.html

# If NTLM is blocked
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5 --no-ntlm
```

---

## Export endpoints

While the server is running these endpoints are available:

| URL | Description |
|-----|-------------|
| `http://localhost:4000` | Interactive HTML dashboard |
| `http://localhost:4000/export/json` | Full JSON audit report |
| `http://localhost:4000/export/excel` | Multi-sheet Excel workbook |
| `http://localhost:4000/export/history` | All historical scan snapshots |

---

## ESC coverage

| ESC | Severity | Description | How detected |
|-----|----------|-------------|-------------|
| **ESC1** | 🔴 CRITICAL | Enrollee supplies SAN → impersonate any user including DA | Template flags |
| **ESC1-UPN** | 🔴 CRITICAL | UPN SAN variant — identical impact | Template flags |
| **ESC2** | 🟠 HIGH | Any Purpose EKU or no EKU defined | Template flags |
| **ESC3** | 🟠 HIGH | Enrollment Agent EKU — including implicit via Any Purpose | Template flags |
| **ESC4** | 🟠 HIGH | Non-admin has dangerous write on template object | GUID-aware SD parser |
| **ESC5** | 🟠 HIGH | Non-admin write on PKI container objects | Container SD parser |
| **ESC6** | 🟠 HIGH | `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on CA | Manual — certutil cmd shown |
| **ESC7** | 🟠 HIGH | ManageCA / ManageCertificates rights on CA | CA ACL parser |
| **ESC8** | 🟠 HIGH | Web enrollment accessible over HTTP (NTLM relay) | Manual — curl cmd shown |
| **ESC9** | 🟡 MEDIUM/HIGH | `CT_FLAG_NO_SECURITY_EXTENSION` — missing SID binding | Template flags |

### Why no false positives on ESC4

Most ADCS tools flag `WriteProperty[Certificate-Enrollment]` as ESC4.
This is wrong — that GUID is an **enroll right**, not a template attribute write.

ADCS Watchdog reads the **ObjectType GUID** from every Object ACE:

| ACE in SDDL | What it means | ESC4? |
|-------------|---------------|-------|
| `(OA;;0x130;0e10c968-...;;Domain-Users)` | Enroll right only — completely normal | ❌ No |
| `(A;;WP;;;Domain-Users)` | Unscoped WriteProperty — all attributes | ✅ Yes |
| `(OA;;WP;d15ef7d8-...;;Domain-Users)` | WriteProperty on `msPKI-Certificate-Name-Flag` | ✅ Yes |

---

## Dashboard filters

Three independent filter groups that **AND** together:

```
SEVERITY   [All] [Critical] [High] [Medium] [Clean] [Published only]
ESC TYPE   [ESC1] [ESC1-UPN] [ESC2] [ESC3] [ESC4] [ESC9]
PRINCIPAL  [Low Priv Users] [Custom Groups] [Privileged Users]
```

Within each group buttons are **OR**. Across groups they are **AND**.

---

## Scan history & diff

Every run automatically saves a snapshot to `adcs_history.json`.
On the next run the **🔄 Changes** tab shows:

- New vulnerabilities appeared
- Vulnerabilities remediated
- Severity regressions or improvements
- ACL changes — new ACEs, rights gained or lost
- Templates published or unpublished

---

## Compatibility

| OS | Python | Status |
|----|--------|--------|
| Kali Linux 2023+ | 3.11 / 3.12 | ✅ Tested |
| Parrot OS 6 | 3.10 / 3.11 | ✅ Tested |
| Ubuntu 22.04 | 3.10 | ✅ Tested |

Target: Windows Server 2016 / 2019 / 2022

---

## Notes

- **Read-only** — never modifies any AD object
- Uses plain LDAP port 389 — avoids SSL timeout issues common in enterprise networks
- SID resolution is cached — large domains may take 60–90 seconds on first run
- `adcs_history.json` is in `.gitignore` — scan data never accidentally committed

---

## License

MIT — free to use, credit appreciated.

---

## Acknowledgements

- [ly4k/Certipy](https://github.com/ly4k/Certipy) — ESC research and vulnerability definitions
- [SpecterOps — Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) — original ADCS attack research
- [fortra/impacket](https://github.com/fortra/impacket) — dacledit reference
- [CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD) — LDAP/ACL tooling
