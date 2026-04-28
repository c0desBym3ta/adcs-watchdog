#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ADCS Watchdog — one-shot installer
# https://github.com/c0desBym3ta/adcs-watchdog
# Tested: Kali Linux, Parrot OS, Ubuntu 22.04+  |  Python 3.8+
# ─────────────────────────────────────────────────────────────

set -e

BOLD="\033[1m"
RED="\033[91m"
GREEN="\033[92m"
CYAN="\033[96m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║         ADCS Watchdog — Installer            ║"
echo "║  github.com/c0desBym3ta/adcs-watchdog        ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Check Python version ─────────────────────────────────────
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

# ── Install dependencies ─────────────────────────────────────
echo -e "\n${CYAN}[*] Installing dependencies from requirements.txt...${RESET}"

if $PIP install -r requirements.txt -q 2>/dev/null; then
    echo -e "${GREEN}[+] Dependencies installed${RESET}"
elif $PIP install -r requirements.txt --break-system-packages -q 2>/dev/null; then
    echo -e "${GREEN}[+] Dependencies installed (--break-system-packages)${RESET}"
else
    echo -e "${CYAN}[*] Trying venv install...${RESET}"
    $PYTHON -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt -q
    echo -e "${GREEN}[+] Installed in venv${RESET}"
    echo -e "${CYAN}    Activate with: source venv/bin/activate${RESET}"
fi

# ── Permissions ──────────────────────────────────────────────
chmod +x adcs_watchdog.py
echo -e "${GREEN}[+] adcs_watchdog.py is executable${RESET}"

# ── Verify ───────────────────────────────────────────────────
echo -e "\n${CYAN}[*] Verifying...${RESET}"
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
    print("  \033[93m!\033[0m openpyxl not found — Excel export will be disabled")

if ok:
    print("\n  \033[92mAll required dependencies OK\033[0m")
else:
    print("\n  \033[91mMissing required dependencies — see above\033[0m")
    sys.exit(1)
PYEOF

# ── Done ─────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}[+] Installation complete!${RESET}"
echo ""
echo -e "  ${BOLD}Run:${RESET}"
echo "    python3 adcs_watchdog.py -u USER@DOMAIN -p 'PASSWORD' -d DC_IP"
echo ""
echo -e "  ${BOLD}Then open:${RESET}  http://localhost:4000"
echo ""
echo -e "  ${BOLD}Options:${RESET}"
echo "    --port 8080       use a different port"
echo "    --output FILE     also save HTML to disk"
echo "    --no-ntlm         use SIMPLE bind"
echo ""
