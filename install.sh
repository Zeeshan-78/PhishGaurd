#!/usr/bin/env bash
# ================================================================
#   PhishGuard AI — Installer v2.1.0
#   Supports : Linux (Debian/Ubuntu/Kali/Arch) | Termux (Android)
#   Usage    : bash install.sh
# ================================================================

set -e

# ── Colors ───────────────────────────────────────────────────────
RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'
CYN='\033[96m'; BLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

ok()   { echo -e "  ${GRN}✓${RST}  $*"; }
info() { echo -e "  ${CYN}→${RST}  $*"; }
warn() { echo -e "  ${YLW}⚠${RST}  $*"; }
err()  { echo -e "  ${RED}✗${RST}  $*"; exit 1; }
step() { echo -e "\n${BLD}${CYN}[$1/$TOTAL]${RST}  $2"; }

TOTAL=6

# ── Banner ───────────────────────────────────────────────────────
clear
echo -e "${BLD}${CYN}"
cat << 'BANNER'
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
BANNER
echo -e "${RST}"
echo -e "  ${DIM}PhishGuard AI — Installer v2.1.0${RST}"
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"

# ── Detect Environment ───────────────────────────────────────────
step 1 "Detecting environment"

IS_TERMUX=false; IS_LINUX=false
PKG_MGR=""; BIN_DIR=""

if [ -d "/data/data/com.termux" ] || [ -n "${TERMUX_VERSION:-}" ] || \
   echo "${PREFIX:-}" | grep -q "termux" 2>/dev/null; then
    IS_TERMUX=true
    BIN_DIR="${PREFIX}/bin"
    PKG_MGR="pkg"
    info "Termux (Android) detected"
elif [ "$(uname -s)" = "Linux" ]; then
    IS_LINUX=true
    BIN_DIR="/usr/local/bin"
    if   command -v apt-get &>/dev/null; then PKG_MGR="apt-get"
    elif command -v apt     &>/dev/null; then PKG_MGR="apt"
    elif command -v dnf     &>/dev/null; then PKG_MGR="dnf"
    elif command -v pacman  &>/dev/null; then PKG_MGR="pacman"
    else                                      PKG_MGR="apt"; fi
    info "Linux detected — package manager: ${PKG_MGR}"
else
    err "Unsupported OS. Only Linux and Termux are supported."
fi
ok "Environment ready"

# ── Python Check ─────────────────────────────────────────────────
step 2 "Checking Python 3.7+"

PYTHON=""
for py in python3 python3.11 python3.10 python3.9 python3.8 python3.7 python; do
    if command -v "$py" &>/dev/null; then
        VER=$("$py" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
        MAJOR=${VER%%.*}; MINOR=${VER##*.}
        if [ "${MAJOR:-0}" -ge 3 ] && [ "${MINOR:-0}" -ge 7 ] 2>/dev/null; then
            PYTHON="$py"
            ok "Found Python ${VER} at $(command -v $py)"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    warn "Python 3.7+ not found — installing..."
    if $IS_TERMUX; then
        pkg install python -y || err "Python install failed"
    else
        sudo ${PKG_MGR} install -y python3 python3-pip 2>/dev/null \
            || err "Python install failed — run: sudo apt install python3 python3-pip"
    fi
    PYTHON="python3"
    ok "Python installed"
fi

# Ensure pip
if ! $PYTHON -m pip --version &>/dev/null 2>&1; then
    warn "pip not found — installing..."
    if $IS_TERMUX; then
        pkg install python-pip -y 2>/dev/null || true
    else
        sudo ${PKG_MGR} install -y python3-pip 2>/dev/null \
            || curl -fsSL https://bootstrap.pypa.io/get-pip.py | $PYTHON
    fi
fi
ok "pip ready"

# ── System Packages ──────────────────────────────────────────────
step 3 "Installing system packages"

_sys_install() {
    local pkg="$1" label="${2:-$1}"
    if $IS_TERMUX; then
        pkg list-installed 2>/dev/null | grep -q "^${pkg}" \
            && ok "${label} already installed" \
            || { info "Installing ${label}..."; pkg install "$pkg" -y &>/dev/null \
                 && ok "${label} installed" || warn "${label} install failed (skipping)"; }
    else
        if command -v "$pkg" &>/dev/null \
           || (command -v dpkg &>/dev/null && dpkg -l "$pkg" &>/dev/null 2>&1); then
            ok "${label} already installed"
        else
            info "Installing ${label}..."
            sudo ${PKG_MGR} install -y "$pkg" &>/dev/null \
                && ok "${label} installed" || warn "${label} install failed (skipping)"
        fi
    fi
}

_sys_install tor  "Tor"
_sys_install curl "curl"

# ── Python Packages ──────────────────────────────────────────────
step 4 "Installing Python packages"

PY_PKGS=("rich" "pyfiglet" "requests" "requests[socks]")
for pkg in "${PY_PKGS[@]}"; do
    label="${pkg%%\[*}"
    info "Installing ${label}..."
    # FIX: Kali/Debian mein PEP 668 hota hai — --break-system-packages chahiye
    # Pehle normal, phir --break-system-packages, phir --user try karo
    if $PYTHON -m pip install "$pkg" -q 2>/dev/null; then
        ok "${label}"
    elif $PYTHON -m pip install "$pkg" -q --break-system-packages 2>/dev/null; then
        ok "${label} (system)"
    elif $PYTHON -m pip install "$pkg" -q --user 2>/dev/null; then
        ok "${label} (user)"
    else
        warn "${label} install failed — tool may still partially work"
    fi
done

# ── Install Command ──────────────────────────────────────────────
step 5 "Installing 'ai-detect' command"

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ai_detect.py"
[ -f "$SCRIPT" ] || err "ai_detect.py not found.\nRun from the phishguard-ai directory."

chmod +x "$SCRIPT"

WRAPPER="#!/usr/bin/env bash
exec ${PYTHON} \"${SCRIPT}\" \"\$@\""

TARGET="${BIN_DIR}/ai-detect"

if $IS_TERMUX; then
    echo "$WRAPPER" > "$TARGET" && chmod +x "$TARGET"
elif [ -w "$BIN_DIR" ]; then
    echo "$WRAPPER" > "$TARGET" && chmod +x "$TARGET"
else
    echo "$WRAPPER" | sudo tee "$TARGET" > /dev/null && sudo chmod +x "$TARGET"
fi
ok "Installed to ${TARGET}"

# ── Verify ───────────────────────────────────────────────────────
step 6 "Verifying installation"

# FIX: PATH ko is session mein bhi refresh karo
export PATH="$BIN_DIR:$PATH"
hash -r 2>/dev/null || true

if command -v ai-detect &>/dev/null; then
    ok "'ai-detect' command globally available"
else
    warn "'ai-detect' not in PATH — running: export PATH=\"$BIN_DIR:\$PATH\""
    export PATH="$BIN_DIR:$PATH"
fi

$PYTHON -c "import rich, pyfiglet, requests; print('  \033[92m✓\033[0m  Python packages OK')" \
    2>/dev/null || warn "Some packages may be missing"

# ── Done ─────────────────────────────────────────────────────────
echo -e "\n${BLD}${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "  ${GRN}${BLD}✅  PhishGuard AI v2.1.0 installed!${RST}"
echo -e "${BLD}${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"
echo -e "  ${CYN}Run:${RST}   ${BLD}ai-detect${RST}"
echo -e "  ${DIM}First run mein Gemini API key set karni hogi.${RST}"
echo -e "  ${DIM}Free key: https://aistudio.google.com/app/apikey${RST}\n"

$IS_TERMUX && echo -e "  ${YLW}Termux:${RST} agar kaam na kare to: ${DIM}source ~/.bashrc${RST}\n"

printf "  Launch now? [Y/n]: "
read -r LAUNCH
case "${LAUNCH:-Y}" in
    [Yy]*)
        echo
        # FIX: 'exec ai-detect' fail hota tha kyunki PATH refresh nahi tha
        # Full path use karo ya python3 se directly chalao
        if command -v ai-detect &>/dev/null; then
            exec ai-detect
        elif [ -f "$TARGET" ]; then
            exec "$TARGET"
        else
            exec $PYTHON "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ai_detect.py"
        fi
        ;;
    *)   echo -e "\n  ${DIM}Type 'ai-detect' anytime to start.${RST}\n" ;;
esac
