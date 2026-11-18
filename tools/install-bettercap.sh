#!/usr/bin/env bash
# Bundle bettercap under vendor/ — no system install, no root needed to fetch.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-v2.41.7}"
DEST="vendor/bettercap"
mkdir -p "$DEST/lib"

if [ ! -x "$DEST/bettercap" ]; then
  echo "[*] downloading bettercap $VERSION"
  curl -L --retry 5 --retry-delay 2 -o "$DEST/bettercap.zip" \
    "https://github.com/bettercap/bettercap/releases/download/$VERSION/bettercap_linux_amd64.zip"
  curl -sSL --max-time 30 -o "$DEST/bettercap.sha256" \
    "https://github.com/bettercap/bettercap/releases/download/$VERSION/bettercap_linux_amd64.sha256"
  unzip -o -q "$DEST/bettercap.zip" -d "$DEST"
  chmod +x "$DEST/bettercap"
  rm -f "$DEST/bettercap.zip"
fi

if [ -f "$DEST/bettercap.sha256" ]; then
  EXPECTED=$(awk -F'= ' '/SHA2-256/{print $2}' "$DEST/bettercap.sha256")
  ACTUAL=$(sha256sum "$DEST/bettercap" | awk '{print $1}')
  if [ -n "$EXPECTED" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "checksum mismatch: expected $EXPECTED got $ACTUAL" >&2
    exit 1
  fi
  echo "[*] sha256 verified: $ACTUAL"
fi

# Ubuntu builds link libpcap.so.0.8; Fedora ships libpcap.so.1. A local soname
# symlink keeps the binary portable without touching system libraries.
PCAP=$(ldconfig -p 2>/dev/null | awk '/libpcap\.so\.1 /{print $NF; exit}')
if [ -n "$PCAP" ]; then
  ln -sf "$PCAP" "$DEST/lib/libpcap.so.0.8"
fi

LD_LIBRARY_PATH="$PWD/$DEST/lib" "$DEST/bettercap" -version 2>&1 | head -n 3
echo "bettercap bundled at $DEST (run CUTOFF as root for ARP/sniffing)"
