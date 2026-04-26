#!/usr/bin/env bash
# ─────────────────────────────────────────────────────
#  ReconCLI v3 — Installer
#  Linux / macOS / Termux (Android)
#  DSwebTEAM | github.com/DSwebTEAM/ReconCLI
# ─────────────────────────────────────────────────────
set -e

RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'
CYN='\033[96m'; DIM='\033[90m'; RST='\033[0m'

COLS=$(tput cols 2>/dev/null || echo 60)
DIV=$(printf '─%.0s' $(seq 1 $((COLS < 62 ? COLS-2 : 60))))

step()    { echo -e "${CYN}  [*] $1${RST}"; }
ok()      { echo -e "${GRN}  [✔] $1${RST}"; }
warn()    { echo -e "${YLW}  [!] $1${RST}"; }
fail()    { echo -e "${RED}  [✘] $1${RST}"; exit 1; }

# ── Banner ────────────────────────────────────────────
echo -e "${RED}"
if [ "$COLS" -ge 70 ]; then
  echo '  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗██╗     ██╗'
  echo '  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║     ██║'
  echo '  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║     ██║     ██║'
  echo '  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║     ██║     ██║'
  echo '  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║╚██████╗███████╗██║'
  echo '  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝'
elif [ "$COLS" -ge 42 ]; then
  echo '  ____                      _____ _     ___'
  echo ' |  _ \ ___  ___ ___  _ __ / ____| |   |_ _|'
  echo ' | |_) / _ \/ __/ _ \| '"'"'_ \ |    | |    | |'
  echo ' |  _ <  __/ (_| (_) | | | | |___| |___ | |'
  echo ' |_| \_\___|\___\___/|_| |_|\____|_____|___|'
else
  echo '  [ ReconCLI v3 ]'
fi
echo -e "${RST}"
echo -e "${DIM}  $DIV${RST}"
echo -e "${CYN}  v3.0.0  |  DSwebTEAM  |  Installer${RST}"
echo -e "${DIM}  $DIV${RST}\n"

# ── Detect environment ────────────────────────────────
IS_TERMUX=false; IS_MAC=false

if [ -d "/data/data/com.termux" ]; then
  IS_TERMUX=true; step "Environment: Termux (Android)"
elif [[ "$(uname)" == "Darwin" ]]; then
  IS_MAC=true; step "Environment: macOS"
else
  step "Environment: Linux"
fi

# ── Python ────────────────────────────────────────────
step "Checking Python 3.8+..."
if ! command -v python3 &>/dev/null; then
  if $IS_TERMUX; then pkg install python -y
  elif $IS_MAC;  then fail "Install Python from https://python.org or: brew install python"
  else
    sudo apt-get install -y python3 python3-pip 2>/dev/null || \
    sudo dnf install -y python3 python3-pip 2>/dev/null || \
    fail "Cannot auto-install Python. Please install manually."
  fi
fi

PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYOK=$(python3 -c "import sys; print('ok' if sys.version_info >= (3,8) else 'fail')")
[ "$PYOK" = "ok" ] && ok "Python $PYVER" || fail "Python 3.8+ required, found $PYVER"

# ── pip ───────────────────────────────────────────────
step "Checking pip..."
if ! python3 -m pip --version &>/dev/null; then
  curl -sS https://bootstrap.pypa.io/get-pip.py | python3 - || fail "Cannot install pip"
fi
ok "pip ready"

# ── Install package ───────────────────────────────────
step "Installing ReconCLI..."
if $IS_TERMUX; then
  pip install -e . --break-system-packages 2>/dev/null || pip install -e . || fail "Install failed"
elif $IS_MAC; then
  pip3 install -e . --user 2>/dev/null || pip3 install -e . || fail "Install failed"
else
  pip3 install -e . --user 2>/dev/null || sudo pip3 install -e . || fail "Install failed"
fi
ok "ReconCLI installed"

# ── PATH check ────────────────────────────────────────
step "Checking PATH..."
if command -v reconcli &>/dev/null; then
  ok "reconcli is in PATH"
else
  warn "reconcli not found in PATH yet."
  USER_BIN="$(python3 -m site --user-base 2>/dev/null)/bin"

  RC_FILE=""
  if $IS_TERMUX; then RC_FILE="$HOME/.bashrc"
  elif [ -f "$HOME/.zshrc" ]; then RC_FILE="$HOME/.zshrc"
  elif [ -f "$HOME/.bashrc" ]; then RC_FILE="$HOME/.bashrc"
  fi

  if [ -n "$RC_FILE" ]; then
    echo "" >> "$RC_FILE"
    echo "# ReconCLI" >> "$RC_FILE"
    echo "export PATH=\"$USER_BIN:\$PATH\"" >> "$RC_FILE"
    warn "Added $USER_BIN to $RC_FILE"
    warn "Run: source $RC_FILE  (or restart terminal)"
  fi
fi

# ── pyreadline3 on Windows (Termux won't hit this) ───
if python3 -c "import sys; exit(0 if sys.platform != 'win32' else 1)" 2>/dev/null; then
  : # not windows
fi

# ── Done ──────────────────────────────────────────────
echo ""
echo -e "${DIM}  $DIV${RST}"
echo -e "${GRN}  ReconCLI v3 installed!${RST}"
echo -e "${DIM}  $DIV${RST}"
echo ""
echo -e "  ${CYN}Usage:${RST}"
echo -e "    reconcli                                   # interactive shell"
echo -e "    reconcli recon/subdomain -t hibiki.app    # direct mode"
echo -e "    reconcli --list                            # all modules"
echo ""
echo -e "  ${YLW}! Authorized use on your own systems only.${RST}"
echo ""
