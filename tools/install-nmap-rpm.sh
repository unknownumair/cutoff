#!/usr/bin/env bash
# Fetch the Fedora nmap RPM and extract it under vendor/ — no root required.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -x vendor/nmap/usr/bin/nmap ]; then
  NMAPDATADIR="$PWD/vendor/nmap/usr/share/nmap" vendor/nmap/usr/bin/nmap --version | head -n 2
  exit 0
fi

command -v dnf >/dev/null || { echo "dnf is required" >&2; exit 1; }
command -v rpm2cpio >/dev/null || { echo "rpm2cpio is required" >&2; exit 1; }

mkdir -p vendor/rpms vendor/nmap
dnf download nmap --destdir vendor/rpms
RPM=$(realpath "$(ls -S vendor/rpms/nmap-*.rpm | head -1)")
(cd vendor/nmap && rpm2cpio "$RPM" | cpio -idm --quiet)

NMAPDATADIR="$PWD/vendor/nmap/usr/share/nmap" vendor/nmap/usr/bin/nmap --version | head -n 2
echo "nmap extracted to vendor/nmap (unprivileged -sT scans; root adds -sS/-O)"
