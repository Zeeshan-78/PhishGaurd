#!/usr/bin/env bash
# ================================================================
#  PhishGuard AI (ai-detect) installer, v3.2.0
#  Linux (Debian/Ubuntu/Kali/Arch/Fedora) and Termux
#
#    bash install.sh                 install
#    bash install.sh --with-tor      install and also install Tor (optional)
#    bash install.sh --uninstall     remove
#
#  Environment variables:
#    AI_DETECT_PREFIX=/some/dir      install to a custom location (no sudo)
#    AI_DETECT_NO_DEPS=1             skip installing Python packages
# ================================================================
set -u

R=$'\033[91m'; G=$'\033[92m'; Y=$'\033[93m'; C=$'\033[96m'; B=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'
ok()   { echo -e "  ${G}[OK]${N}     $*"; }
info() { echo -e "  ${C}[..]${N}     $*"; }
warn() { echo -e "  ${Y}[!]${N}      $*"; }
die()  { echo -e "  ${R}[ERROR]${N}  $*"; exit 1; }
step() { echo -e "\n${B}${C}Step $1 of 4${N}  $2"; }

WITH_TOR=0; UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --with-tor)  WITH_TOR=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)   sed -n '2,14p' "$0"; exit 0 ;;
  esac
done

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SRC_DIR/ai_detect.py"

# -- environment -------------------------------------------------
IS_TERMUX=0
if [ -d /data/data/com.termux ] || [ -n "${TERMUX_VERSION:-}" ]; then IS_TERMUX=1; fi

if [ -n "${AI_DETECT_PREFIX:-}" ]; then PFX="$AI_DETECT_PREFIX"
elif [ "$IS_TERMUX" = 1 ];          then PFX="${PREFIX:-/data/data/com.termux/files/usr}"
else                                     PFX="/usr/local"; fi
BIN="$PFX/bin"; LIB="$PFX/lib/ai-detect"

# Run a command with sudo only when the target location is not writable.
as_root() {
  if [ "$(id -u)" = 0 ] || [ -w "$PFX" ] || { [ ! -e "$PFX" ] && [ -w "$(dirname "$PFX")" ]; }; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else die "No write permission and sudo is not available. Try: AI_DETECT_PREFIX=\$HOME/.local bash install.sh"; fi
}

if [ "$UNINSTALL" = 1 ]; then
  as_root rm -f "$BIN/ai-detect"; as_root rm -rf "$LIB"
  ok "Removed ai-detect ($BIN/ai-detect and $LIB)"
  echo -e "  ${D}Your settings and history are kept in ${HOME}/.ai-detect. Delete that folder if you want them gone.${N}"
  exit 0
fi

echo -e "\n${B}${C}  PhishGuard AI installer v3.2.0${N}"
[ -f "$SCRIPT" ] || die "ai_detect.py was not found. Run install.sh from the folder that contains ai_detect.py."

# -- 1. python ---------------------------------------------------
step 1 "Checking for Python 3.7 or newer"
PY=""
for p in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python; do
  if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3,7) else 1)' 2>/dev/null; then
    PY="$(command -v "$p")"; break
  fi
done
if [ -z "$PY" ]; then
  warn "Python 3.7+ not found. Installing it now."
  if   [ "$IS_TERMUX" = 1 ];               then pkg install -y python
  elif command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y python3 python3-pip
  elif command -v dnf >/dev/null 2>&1;     then sudo dnf install -y python3 python3-pip
  elif command -v pacman >/dev/null 2>&1;  then sudo pacman -S --noconfirm python python-pip
  else die "Please install Python 3.7 or newer yourself, then run this script again."; fi
  PY="$(command -v python3)" || die "Python installation failed."
fi
ok "Python $("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')  ($PY)"

# -- 2. python packages ------------------------------------------
step 2 "Python packages (rich, pyfiglet, requests)"
if [ "${AI_DETECT_NO_DEPS:-0}" = 1 ]; then
  info "AI_DETECT_NO_DEPS=1, skipping"
else
  if ! "$PY" -m pip --version >/dev/null 2>&1; then
    warn "pip not found. Installing it now."
    if   [ "$IS_TERMUX" = 1 ];               then pkg install -y python-pip
    elif command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y python3-pip
    else "$PY" -m ensurepip --user >/dev/null 2>&1 || warn "Could not install pip."; fi
  fi
  for spec in "rich:rich" "pyfiglet:pyfiglet" "requests:requests"; do
    mod="${spec%%:*}"; pkg="${spec##*:}"
    if "$PY" -c "import $mod" >/dev/null 2>&1; then ok "$pkg (already installed)"; continue; fi
    info "Installing $pkg"
    if   "$PY" -m pip install -q --disable-pip-version-check "$pkg" >/dev/null 2>&1; then ok "$pkg"
    elif "$PY" -m pip install -q --disable-pip-version-check --break-system-packages "$pkg" >/dev/null 2>&1; then ok "$pkg (system)"
    elif "$PY" -m pip install -q --disable-pip-version-check --user "$pkg" >/dev/null 2>&1; then ok "$pkg (user)"
    elif "$PY" -m pip install -q --disable-pip-version-check --user --break-system-packages "$pkg" >/dev/null 2>&1; then ok "$pkg (user)"
    else warn "Could not install $pkg. ai-detect will try again on its first run."; fi
  done
fi

# -- 3. optional Tor ---------------------------------------------
step 3 "Tor (optional)"
if command -v tor >/dev/null 2>&1; then ok "Tor is already installed"
elif [ "$WITH_TOR" = 1 ]; then
  info "Installing Tor"
  if   [ "$IS_TERMUX" = 1 ];               then pkg install -y tor
  elif command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y tor
  elif command -v dnf >/dev/null 2>&1;     then sudo dnf install -y tor
  elif command -v pacman >/dev/null 2>&1;  then sudo pacman -S --noconfirm tor
  fi; command -v tor >/dev/null 2>&1 && ok "Tor installed" || warn "Could not install Tor"
else
  info "Skipped. Tor is optional; install it with: bash install.sh --with-tor"
fi

# -- 4. install command ------------------------------------------
step 4 "Installing the 'ai-detect' command"
as_root mkdir -p "$BIN" "$LIB"
as_root cp "$SCRIPT" "$LIB/ai_detect.py"
as_root chmod 644 "$LIB/ai_detect.py"
TMP_WRAP="$(mktemp)"
printf '#!/usr/bin/env bash\nexec "%s" "%s/ai_detect.py" "$@"\n' "$PY" "$LIB" > "$TMP_WRAP"
as_root cp "$TMP_WRAP" "$BIN/ai-detect"; rm -f "$TMP_WRAP"
as_root chmod 755 "$BIN/ai-detect"
ok "Installed: $BIN/ai-detect"

if VER="$("$BIN/ai-detect" --version 2>&1)"; then ok "Verified: $VER"
else warn "Verification failed: $VER"; fi

case ":$PATH:" in *":$BIN:"*) ;; *) warn "$BIN is not in your PATH. Add it with:  export PATH=\"$BIN:\$PATH\"" ;; esac

echo -e "\n${B}${G}  Installation complete.${N}\n"
echo -e "  ${B}ai-detect${N}                   interactive menu (asks for your API key on first run)"
echo -e "  ${B}ai-detect url example.com${N}   scan a website directly"
echo -e "  ${B}ai-detect --help${N}            all commands"
echo -e "  ${D}Free key: aistudio.google.com/app/apikey (keys starting with AQ or AIza both work)${N}\n"

if [ -t 0 ] && [ -t 1 ]; then
  printf "  Start ai-detect now? [Y/n]: "; read -r ans
  case "${ans:-Y}" in [Yy]*) exec "$BIN/ai-detect" ;; esac
fi
