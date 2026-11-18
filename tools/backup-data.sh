#!/usr/bin/env bash
# Snapshot the CUTOFF inventory, events and logs into one tarball.
#
#   ./tools/backup-data.sh                 # -> backend/data/backups/cutoff-<ts>.tar.gz
#   CUTOFF_BACKUP_DIR=/var/backups ./tools/backup-data.sh
#   CUTOFF_KEEP=14 ./tools/backup-data.sh   # keep the newest 14 archives
#
# Safe to run while the service is up: the store rewrites devices.json
# atomically, so the copy is always a complete file.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$PROJECT/backend/data"
DEST="${CUTOFF_BACKUP_DIR:-$DATA/backups}"
KEEP="${CUTOFF_KEEP:-10}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

[ -d "$DATA" ] || { echo "[!] no data dir at $DATA" >&2; exit 1; }
mkdir -p "$DEST"

OUT="$DEST/cutoff-$STAMP.tar.gz"
tar -czf "$OUT" -C "$DATA" \
  --exclude='backups' \
  --exclude='nmap' \
  --exclude='*.tmp' \
  devices.json events.jsonl api_token monitor.json cutoff.log 2>/dev/null || true

# inventories can be large; keep only the newest N archives
mapfile -t archives < <(ls -1t "$DEST"/cutoff-*.tar.gz 2>/dev/null || true)
if [ "${#archives[@]}" -gt "$KEEP" ]; then
  printf '%s\n' "${archives[@]:$KEEP}" | xargs -r rm -f
fi

printf '[+] %s (%s)\n' "$OUT" "$(du -h "$OUT" | cut -f1)"
