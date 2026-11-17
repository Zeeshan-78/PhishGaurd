#!/usr/bin/env bash
# ================================================================
#  PhishGuard AI (ai-detect) — installer v3.1.0
#  Linux (Debian/Ubuntu/Kali/Arch/Fedora) + Termux
#
#    bash install.sh                 install
#    bash install.sh --with-tor      install + Tor (optional)
#    bash install.sh --uninstall     remove
#
#  env:  AI_DETECT_PREFIX=/some/dir  (no sudo, custom location)
#        AI_DETECT_NO_DEPS=1         (skip pip package install)
# ================================================================
set -u

R=$'\033[91m'; G=$'\033[92m'; Y=$'\033[93m'; C=$'\033[96m'; B=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'
ok()   { echo -e "  ${G}✓${N}  $*"; }
info() { echo -e "  ${C}→${N}  $*"; }
warn() { echo -e "  ${Y}!${N}  $*"; }
die()  { echo -e "  ${R}✗${N}  $*"; exit 1; }
step() { echo -e "\n${B}${C}[$1/4]${N} $2"; }

WITH_TOR=0; UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --with-tor)  WITH_TOR=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)   sed -n '2,13p' "$0"; exit 0 ;;
  esac
done

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SRC_DIR/ai_detect.py"

# ── environment ────────────────────────────────────────────────
IS_TERMUX=0
if [ -d /data/data/com.termux ] || [ -n "${TERMUX_VERSION:-}" ]; then IS_TERMUX=1; fi

if [ -n "${AI_DETECT_PREFIX:-}" ]; then PFX="$AI_DETECT_PREFIX"
elif [ "$IS_TERMUX" = 1 ];          then PFX="${PREFIX:-/data/data/com.termux/files/usr}"
else                                     PFX="/usr/local"; fi
BIN="$PFX/bin"; LIB="$PFX/lib/ai-detect"

# run a command with sudo only if the target isn't writable
as_root() {
  if [ "$(id -u)" = 0 ] || [ -w "$PFX" ] || { [ ! -e "$PFX" ] && [ -w "$(dirname "$PFX")" ]; }; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else die "Write permission nahi (sudo bhi nahi). Try: AI_DETECT_PREFIX=\$HOME/.local bash install.sh"; fi
}

if [ "$UNINSTALL" = 1 ]; then
  as_root rm -f "$BIN/ai-detect"; as_root rm -rf "$LIB"
  ok "ai-detect hata diya  ($BIN/ai-detect, $LIB)"
  echo -e "  ${D}Aapka config/history ${HOME}/.ai-detect mein hai — chaho to khud delete karo.${N}"
  exit 0
fi

echo -e "\n${B}${C}  🔰 PhishGuard AI installer v3.1.0${N}"
[ -f "$SCRIPT" ] || die "ai_detect.py nahi mili. install.sh ko usi folder se chalao jahan ai_detect.py hai."

# ── 1. python ──────────────────────────────────────────────────
step 1 "Python 3.7+ check"
PY=""
for p in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python; do
  if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3,7) else 1)' 2>/dev/null; then
    PY="$(command -v "$p")"; break
  fi
done
if [ -z "$PY" ]; then
  warn "Python 3.7+ nahi mila — install kar raha hoon"
  if   [ "$IS_TERMUX" = 1 ];            then pkg install -y python
  elif command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y python3 python3-pip
  elif command -v dnf >/dev/null 2>&1;     then sudo dnf install -y python3 python3-pip
  elif command -v pacman >/dev/null 2>&1;  then sudo pacman -S --noconfirm python python-pip
  else die "Python khud install karo (3.7+), phir dobara chalao."; fi
  PY="$(command -v python3)" || die "Python install fail."
fi
ok "Python $("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')  ($PY)"

# ── 2. python packages ─────────────────────────────────────────
step 2 "Python packages (rich, pyfiglet, requests)"
if [ "${AI_DETECT_NO_DEPS:-0}" = 1 ]; then
  info "AI_DETECT_NO_DEPS=1 — skip"
else
  if ! "$PY" -m pip --version >/dev/null 2>&1; then
    warn "pip nahi mila — install kar raha hoon"
    if   [ "$IS_TERMUX" = 1 ];            then pkg install -y python-pip
    elif command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y python3-pip
    else "$PY" -m ensurepip --user >/dev/null 2>&1 || warn "pip install nahi hua"; fi
  fi
  for spec in "rich:rich" "pyfiglet:pyfiglet" "requests:requests"; do
    mod="${spec%%:*}"; pkg="${spec##*:}"
    if "$PY" -c "import $mod" >/dev/null 2>&1; then ok "$pkg  (already installed)"; continue; fi
    info "$pkg install ho raha hai..."
    if   "$PY" -m pip install -q --disable-pip-version-check "$pkg" >/dev/null 2>&1; then ok "$pkg"
    elif "$PY" -m pip install -q --disable-pip-version-check --break-system-packages "$pkg" >/dev/null 2>&1; then ok "$pkg  (system)"
    elif "$PY" -m pip install -q --disable-pip-version-check --user "$pkg" >/dev/null 2>&1; then ok "$pkg  (user)"
    elif "$PY" -m pip install -q --disable-pip-version-check --user --break-system-packages "$pkg" >/dev/null 2>&1; then ok "$pkg  (user)"
    else warn "$pkg install nahi hua — ai-detect pehli run par khud koshish karega"; fi
  done
fi

# ── 3. optional Tor ────────────────────────────────────────────
step 3 "Tor (optional)"
if command -v tor >/dev/null 2>&1; then ok "Tor installed hai"
elif [ "$WITH_TOR" = 1 ]; then
  info "Tor install ho raha hai..."
  if   [ "$IS_TERMUX" = 1 ];            then pkg install -y tor
  elif command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y tor
  elif command -v dnf >/dev/null 2>&1;     then sudo dnf install -y tor
  elif command -v pacman >/dev/null 2>&1;  then sudo pacman -S --noconfirm tor
  fi; command -v tor >/dev/null 2>&1 && ok "Tor installed" || warn "Tor install nahi hua"
else
  info "Skip — Tor optional hai. Chahiye to:  bash install.sh --with-tor"
fi

# ── 4. install command ─────────────────────────────────────────
step 4 "'ai-detect' command install"
as_root mkdir -p "$BIN" "$LIB"
as_root cp "$SCRIPT" "$LIB/ai_detect.py"
as_root chmod 644 "$LIB/ai_detect.py"
TMP_WRAP="$(mktemp)"
printf '#!/usr/bin/env bash\nexec "%s" "%s/ai_detect.py" "$@"\n' "$PY" "$LIB" > "$TMP_WRAP"
as_root cp "$TMP_WRAP" "$BIN/ai-detect"; rm -f "$TMP_WRAP"
as_root chmod 755 "$BIN/ai-detect"
ok "Installed: $BIN/ai-detect"

if VER="$("$BIN/ai-detect" --version 2>&1)"; then ok "Verify: $VER"
else warn "Verify fail: $VER"; fi

case ":$PATH:" in *":$BIN:"*) ;; *) warn "$BIN aapke PATH mein nahi — add karo:  export PATH=\"$BIN:\$PATH\"" ;; esac

echo -e "\n${B}${G}  ✅ Installation complete!${N}\n"
echo -e "  ${B}ai-detect${N}                  ${D}interactive menu (pehli baar API key maangega)${N}"
echo -e "  ${B}ai-detect url example.com${N}  ${D}seedha website scan${N}"
echo -e "  ${B}ai-detect --help${N}           ${D}saari commands${N}"
echo -e "  ${D}Free key: aistudio.google.com/app/apikey  (AQ... ya AIza... dono theek hain)${N}\n"

if [ -t 0 ] && [ -t 1 ]; then
  printf "  Abhi chalayein? [Y/n]: "; read -r ans
  case "${ans:-Y}" in [Yy]*) exec "$BIN/ai-detect" ;; esac
fi
