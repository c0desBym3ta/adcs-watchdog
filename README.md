# ADCS Watchdog

> **Active Directory Certificate Services (ADCS) audit tool — ESC1-9 detection, GUID-aware ACL analysis, interactive web dashboard, Excel/JSON export, scan-to-scan diff tracking and certipy integration.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Version](https://img.shields.io/badge/version-1.1-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Parrot%20%7C%20Ubuntu-lightgrey)

---

## What's new in v1.1

- **certipy integration** — CA-level permissions (ManageCA, ManageCertificates) now read via DCOM/RPC registry, matching certipy's output exactly
- **Terminal mode** (`--terminal`) — full colour-coded findings summary without starting the web server
- **Kerberos authentication** (`-k`) — use existing ccache ticket for authentication
- **Pass-the-hash** (`--hashes LM:NT`) — authenticate with NTLM hash instead of password
- **All cards collapsed by default** — cleaner dashboard, click to expand
- **ESC5–ESC11 filter buttons** — full ESC coverage in the filter bar
- **CA-level vulnerability cards** — ESC6/7/8/11 shown in dedicated expandable CA cards with certipy data
- **Scan history diff** — changes between scans shown in the 🔄 Changes tab

---

## What it does

ADCS Watchdog connects to Active Directory via LDAP, enumerates all certificate templates and Enterprise CAs, parses every Security Descriptor at the binary level with full GUID-awareness, and serves an interactive HTML dashboard locally on any port.

For CA-level checks (ESC6/7/8/11), it also runs certipy via DCOM/RPC to read the CA registry security — the same method certipy uses — giving accurate ManageCA/ManageCertificates results that LDAP alone cannot provide.

### Key features

| Feature | Details |
|---|---|
| **ESC1–ESC9 + ESC11** | Every condition verified — no false positives |
| **GUID-aware ACL parser** | Distinguishes `WriteProperty[msPKI-*]` (ESC4) from `WriteProperty[Certificate-Enrollment]` (enroll only) |
| **CA registry via certipy** | Real ManageCA/ManageCertificates from DCOM/RPC, not just LDAP |
| **Terminal mode** | `--terminal` for quick CLI output without web server |
| **Kerberos + PTH** | `-k` for ccache, `--hashes` for pass-the-hash |
| **Full ACL table** | All principals classified `[HIGH]` `[LOW]` `[UNKNOWN]` `[SYSTEM]` |
| **Raw tool verification** | Simulated `ldapsearch`, `dacledit`, `bloodyAD` output per template |
| **Built-in ESC Guide** | Reference page for every ESC with conditions and exploit commands |
| **Excel + JSON export** | Multi-sheet `.xlsx` and full structured JSON |
| **Scan history & diff** | Every run saved — new findings and ACL changes tracked |

---

## Requirements

- Python 3.8+
- Network access to DC on **port 389 (LDAP)**
- Any valid domain account (read-only audit)
- `certipy-ad` (optional — for CA registry checks via DCOM/RPC)

---

## Installation

```bash
git clone https://github.com/c0desBym3ta/adcs-watchdog.git
cd adcs-watchdog
chmod +x install.sh && ./install.sh
```

### Manual

```bash
pip install -r requirements.txt
pip install certipy-ad --break-system-packages   # optional but recommended
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
  -u, --user        Username (user@domain). Not needed with --kerberos
  -p, --password    Password. Not needed with --kerberos or --hashes
  -d, --dc-ip       Domain Controller IP

authentication:
  -k, --kerberos    Use Kerberos (requires KRB5CCNAME env var)
  --hashes LM:NT    Pass-the-hash (:NTHASH or LMHASH:NTHASH)
  --no-ntlm         Use SIMPLE bind instead of NTLM

optional:
  --domain          Domain FQDN (auto-detected from -u if omitted)
  --port            HTTP port (default: 4000)
  --terminal        Print findings to terminal only, skip web server
  --no-certipy      Skip certipy CA checks (LDAP-only mode)
  --browser         Auto-open dashboard in browser after startup
  --output FILE     Also save HTML report to disk
  --reset-history   Clear scan history before running (fresh baseline)
```

### Examples

```bash
# Standard run
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5

# Terminal only — quick check, no browser needed
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5 --terminal

# Kerberos auth (from ccache)
export KRB5CCNAME=/tmp/alice.ccache
python3 adcs_watchdog.py -k -d 10.10.10.5 --domain corp.local

# Pass-the-hash
python3 adcs_watchdog.py -u alice@corp.local --hashes :ee22ddf0f8a66db4217050e6a948f9d6 -d 10.10.10.5

# Auto-open browser + custom port
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5 --port 8080 --browser

# Fresh baseline (clear previous scan history)
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5 --reset-history

# Skip certipy (LDAP only, no DCOM/RPC)
python3 adcs_watchdog.py -u alice@corp.local -p 'Password1!' -d 10.10.10.5 --no-certipy
```

---

## Export endpoints

| URL | Description |
|-----|-------------|
| `http://localhost:4000` | Interactive HTML dashboard |
| `http://localhost:4000/export/json` | Full JSON audit report |
| `http://localhost:4000/export/excel` | Multi-sheet Excel workbook |
| `http://localhost:4000/export/history` | All historical scan snapshots |

---

## ESC coverage

| ESC | Severity | Description | Source |
|-----|----------|-------------|--------|
| **ESC1** | 🔴 CRITICAL | Enrollee supplies SAN → impersonate any user | LDAP template flags |
| **ESC1-UPN** | 🔴 CRITICAL | UPN SAN variant | LDAP template flags |
| **ESC2** | 🟠 HIGH | Any Purpose EKU or no EKU | LDAP template flags |
| **ESC3** | 🟠 HIGH | Enrollment Agent EKU (incl. via Any Purpose) | LDAP template flags |
| **ESC4** | 🟠 HIGH | Non-admin dangerous write on template | GUID-aware SD parser |
| **ESC5** | 🟠 HIGH | Non-admin write on PKI container objects | Container SD parser |
| **ESC6** | 🟠 HIGH | `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA | certipy/RPC + manual |
| **ESC7** | 🟠 HIGH | ManageCA/ManageCertificates on CA | certipy/RPC + LDAP SD |
| **ESC8** | 🟠 HIGH | Web enrollment over HTTP (NTLM relay) | HTTP probe + certipy |
| **ESC9** | 🟡 MEDIUM/HIGH | `CT_FLAG_NO_SECURITY_EXTENSION` | LDAP template flags |
| **ESC11** | 🟠 HIGH | Encryption not enforced for ICPR | certipy/RPC |

### Why no ESC4 false positives

The most common false positive in ADCS tooling is flagging `WriteProperty[Certificate-Enrollment]` as ESC4. This GUID is an **enroll right** — it lets users request certs but cannot touch template attributes.

ADCS Watchdog reads the **ObjectType GUID** from every Object ACE:

| ACE | Meaning | ESC4? |
|-----|---------|-------|
| `(OA;;CR;0e10c968-...;;Domain-Users)` | Enroll right only | ❌ No |
| `(A;;WP;;;Domain-Users)` | Unscoped WriteProperty — all attributes | ✅ Yes |
| `(OA;;WP;d15ef7d8-...;;Domain-Users)` | WriteProperty on `msPKI-Certificate-Name-Flag` | ✅ Yes |

### Why certipy sees different CA permissions than LDAP

Windows CAs have **two separate permission stores**:

| Store | Read via | What it controls |
|-------|----------|-----------------|
| `nTSecurityDescriptor` (LDAP) | ldapsearch, bloodyAD, dacledit | AD object access |
| CA Registry Security | DCOM/RPC (`ICertAdminD2`) | CA operations (ManageCA, ManageCertificates) |

ADCS Watchdog reads both. The LDAP section shows what `nTSecurityDescriptor` contains. The certipy section shows what `ICertAdminD2.GetCASecurity()` returns via RPC — the real CA management permissions.

---

## Dashboard

- All cards **collapsed by default** — click any card header to expand
- Three independent filter groups (AND between groups, OR within):

```
SEVERITY   [All] [Critical] [High] [Medium] [Clean] [Published only]
ESC TYPE   [ESC1] [ESC1-UPN] [ESC2] [ESC3] [ESC4] [ESC5] [ESC6] [ESC7] [ESC8] [ESC9]
PRINCIPAL  [Low Priv Users] [Custom Groups] [Privileged Users]
```

Each template card contains:
- Template metadata and flags
- Full LDAP ACL table
- Principal permissions analysis (what each group has vs what ESC needs)
- ESC check table with every condition
- Exploitation path for confirmed findings
- Raw tool tabs: Template Flags / ldapsearch ACL / dacledit / bloodyAD / CA Checks

Each CA card contains:
- ESC6/7/8/11 verdict table with verify commands
- ESC7 principals from LDAP SD
- certipy DCOM/RPC permissions (ManageCA/ManageCertificates with real principals)
- Full LDAP nTSecurityDescriptor ACL

---

## Scan history & diff

Every run saves a snapshot to `adcs_history.json`. The **🔄 Changes** tab shows:
- New vulnerabilities
- Fixed vulnerabilities
- Severity changes (worsened / improved)
- ACL changes — new ACEs, rights gained or lost

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
- Uses plain LDAP port 389
- `adcs_history.json` is gitignored — scan data never committed
- certipy runs automatically unless `--no-certipy` is passed
- If certipy is not installed, CA checks fall back to LDAP-only with a note

---

## Changelog

### v1.1
- certipy DCOM/RPC integration for real CA permissions
- Terminal mode (`--terminal`)
- Kerberos auth (`-k`) and pass-the-hash (`--hashes`)
- All cards collapsed by default
- ESC5–ESC11 filter buttons
- Dedicated CA vulnerability cards
- Fixed ESC3 false negative (Any Purpose implies Enrollment Agent)
- Fixed ESC4 false positive (Certificate-Enrollment GUID is Enroll only)
- Fixed CA ACL decoding (standard ACE vs Object ACE context)
- Python 3.8+ compatibility (no f-string backslash)

### v1.0
- Initial release
- ESC1–ESC9 detection
- GUID-aware ACL parser
- Web dashboard with dark theme
- Excel and JSON export
- Scan history tracking

---

## License

MIT — free to use, credit appreciated.

---

## Acknowledgements

- [ly4k/Certipy](https://github.com/ly4k/Certipy) — ESC research and vulnerability definitions
- [SpecterOps — Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) — original ADCS attack research
- [fortra/impacket](https://github.com/fortra/impacket) — dacledit reference
- [CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD) — LDAP/ACL tooling
