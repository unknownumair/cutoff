#!/usr/bin/env bash
# Fetch the bundled binaries (nmap, bettercap) that are not committed to git.
# Run once after cloning; the app degrades gracefully without them.
#
#   ./tools/fetch-vendor.sh
#
# Both installers are idempotent and write into vendor/.
set -euo pipefail
cd "$(dirname "$0")"

status=0

if [ -x "../vendor/nmap/usr/bin/nmap" ] || [ -x "../vendor/nmap/win32" ]; then
  echo "[=] nmap already present"
else
  echo "[*] fetching nmap"
  bash ./install-nmap-rpm.sh || status=1
fi

if [ -x "../vendor/bettercap/bettercap" ] || [ -e "../vendor/bettercap/win64/bettercap.exe" ]; then
  echo "[=] bettercap already present"
else
  echo "[*] fetching bettercap"
  bash ./install-bettercap.sh || status=1
fi

if [ "$status" -ne 0 ]; then
  echo "[!] one or more downloads failed — the console still runs; those tools stay unavailable" >&2
fi
exit "$status"
