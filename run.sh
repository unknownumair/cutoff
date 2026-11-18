#!/usr/bin/env bash
# CUTOFF launcher.
#
# First run installs the app system-wide (root dir) so `cutoff` works from any
# directory, then serves the installed copy. After that `cutoff` alone is all
# you need; this script stays as the "run it from the checkout" shortcut.
#
#   ./run.sh                       installs to /opt/cutoff on first run, then serves
#   CUTOFF_NO_INSTALL=1 ./run.sh   stay local (dev mode, uses ./.venv)
#   CUTOFF_PREFIX=... ./run.sh     custom install dir
set -euo pipefail
cd "$(dirname "$0")"

PREFIX="${CUTOFF_PREFIX:-/opt/cutoff}"
PYTHON="${PYTHON:-python3}"

# ---------------------------------------------------------------- dev mode
if [ "${CUTOFF_NO_INSTALL:-0}" = "1" ]; then
  if [ ! -x .venv/bin/python ]; then
    echo "[*] creating local virtual environment"
    "$PYTHON" -m venv .venv
  fi
  .venv/bin/python -m pip install -q -r backend/requirements.txt
  if [ "$(id -u)" -ne 0 ] && sudo -n true 2>/dev/null; then
    echo "[i] running the checkout under sudo (live enforcement)"
    exec sudo -E env "PATH=$PATH" .venv/bin/python backend/app.py
  fi
  [ "$(id -u)" -ne 0 ] && echo "[i] unprivileged: blocks are simulated (sudo ./run.sh for live)"
  exec .venv/bin/python backend/app.py
fi

# ------------------------------------------------- first run: install global
if [ ! -x "$PREFIX/.venv/bin/python" ] || [ ! -f "$PREFIX/backend/app.py" ]; then
  echo "[*] first run — installing CUTOFF into $PREFIX so 'cutoff' works globally"
  if [ "$(id -u)" -eq 0 ]; then
    "$PWD/tools/install-global.sh" --no-start
  elif [ -w "$PREFIX" ] || [ -w "$(dirname "$PREFIX")" ]; then
    "$PWD/tools/install-global.sh" --no-start      # user-writable prefix
  else
    sudo -E "$PWD/tools/install-global.sh" --no-start
  fi
fi

# --------------------------------------------------------------- serve it
CLI="$PREFIX/bin/cutoff"
[ -x "$CLI" ] || { echo "[x] install incomplete: $CLI missing" >&2; exit 1; }

echo "[i] serving the installed copy: $PREFIX"
echo "[i] later: 'cutoff' starts the service, 'cutoff status' shows the URL"
if [ "$(id -u)" -ne 0 ] && sudo -n true 2>/dev/null; then
  exec sudo -E env "PATH=$PATH" "CUTOFF_PREFIX=$PREFIX" "$CLI" serve
fi
[ "$(id -u)" -ne 0 ] && echo "[i] unprivileged: blocks are simulated — 'sudo ./run.sh' for live enforcement"
exec env "CUTOFF_PREFIX=$PREFIX" "$CLI" serve
