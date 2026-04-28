#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ADCS Watchdog v1.1 — installer
# https://github.com/c0desBym3ta/adcs-watchdog
# Tested: Kali Linux, Parrot OS, Ubuntu 22.04+  |  Python 3.8+
# ─────────────────────────────────────────────────────────────

set -e

BOLD="\033[1m"
RED="\033[91m"
GREEN="\033[92m"
CYAN="\033[96m"
YELLOW="\033[93m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║       ADCS Watchdog v1.1 — Installer        ║"
echo "║  github.com/c0desBym3ta/adcs-watchdog        ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Check Python ─────────────────────────────────────────────
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo -e "${RED}[!] python3 not found. Install it:${RESET}"
    echo "    sudo apt install python3 python3-pip"
    exit 1
fi

PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")
echo -e "${GREEN}[+] Python $PY_VER found${RESET}"

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    echo -e "${RED}[!] Python 3.8+ required (found $PY_VER)${RESET}"
    exit 1
fi

# ── Find pip ─────────────────────────────────────────────────
if command -v pip3 &>/dev/null; then
    PIP="pip3"
elif $PYTHON -m pip --version &>/dev/null 2>&1; then
    PIP="$PYTHON -m pip"
else
    echo -e "${RED}[!] pip not found — installing...${RESET}"
    sudo apt-get update -qq && sudo apt-get install -y python3-pip
    PIP="pip3"
fi
echo -e "${GREEN}[+] pip: $PIP${RESET}"

# ── Core dependencies ─────────────────────────────────────────
echo -e "\n${CYAN}[*] Installing core dependencies...${RESET}"
if $PIP install -r requirements.txt -q 2>/dev/null; then
    echo -e "${GREEN}[+] Core dependencies installed${RESET}"
elif $PIP install -r requirements.txt --break-system-packages -q 2>/dev/null; then
    echo -e "${GREEN}[+] Core dependencies installed (--break-system-packages)${RESET}"
else
    echo -e "${CYAN}[*] Trying venv...${RESET}"
    $PYTHON -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt -q
    echo -e "${GREEN}[+] Installed in venv — activate with: source venv/bin/activate${RESET}"
fi

# ── Optional: certipy-ad ──────────────────────────────────────
echo -e "\n${CYAN}[*] Installing certipy-ad (for CA-level ESC6/7/8/11 detection)...${RESET}"
if $PIP install certipy-ad -q 2>/dev/null; then
    echo -e "${GREEN}[+] certipy-ad installed${RESET}"
elif $PIP install certipy-ad --break-system-packages -q 2>/dev/null; then
    echo -e "${GREEN}[+] certipy-ad installed (--break-system-packages)${RESET}"
else
    echo -e "${YELLOW}[!] certipy-ad install failed — CA registry checks will be skipped${RESET}"
    echo "    Manual install: pip install certipy-ad --break-system-packages"
fi

# ── Permissions ──────────────────────────────────────────────
chmod +x adcs_watchdog.py
echo -e "${GREEN}[+] adcs_watchdog.py is executable${RESET}"

# ── Verify ───────────────────────────────────────────────────
echo -e "\n${CYAN}[*] Verifying installation...${RESET}"
$PYTHON - << 'PYEOF'
import sys
ok = True
try:
    import ldap3
    print(f"  \033[92m✓\033[0m ldap3 {ldap3.__version__}")
except ImportError:
    print("  \033[91m✗\033[0m ldap3 NOT found"); ok = False

try:
    import openpyxl
    print(f"  \033[92m✓\033[0m openpyxl {openpyxl.__version__}")
except ImportError:
    print("  \033[93m!\033[0m openpyxl not found — Excel export disabled")

try:
    import subprocess, shutil
    c = shutil.which("certipy") or shutil.which("certipy-ad")
    if c:
        print(f"  \033[92m✓\033[0m certipy found at {c}")
    else:
        print("  \033[93m!\033[0m certipy not found — CA RPC checks will be skipped")
except: pass

if ok:
    print("\n  \033[92mReady to run!\033[0m")
else:
    print("\n  \033[91mMissing required dependencies\033[0m")
    sys.exit(1)
PYEOF

echo -e "\n${GREEN}${BOLD}[+] Installation complete! (ADCS Watchdog v1.1)${RESET}"
echo ""
echo -e "  ${BOLD}Basic usage:${RESET}"
echo "    python3 adcs_watchdog.py -u USER@DOMAIN -p 'PASSWORD' -d DC_IP"
echo ""
echo -e "  ${BOLD}Terminal mode (no browser):${RESET}"
echo "    python3 adcs_watchdog.py -u USER@DOMAIN -p 'PASSWORD' -d DC_IP --terminal"
echo ""
echo -e "  ${BOLD}Kerberos auth:${RESET}"
echo "    export KRB5CCNAME=/tmp/ticket.ccache"
echo "    python3 adcs_watchdog.py -k -d DC_IP --domain DOMAIN"
echo ""
echo -e "  ${BOLD}Pass-the-hash:${RESET}"
echo "    python3 adcs_watchdog.py -u USER@DOMAIN --hashes :NTHASH -d DC_IP"
echo ""
echo -e "  ${BOLD}Then open:${RESET}  http://localhost:4000"
echo ""
