#!/usr/bin/env bash
# Service installers.
#
#   sudo ./tools/install-service.sh                -> delegates to install-global.sh
#                                                     (copies to /opt/cutoff, unit "cutoff")
#   sudo ./tools/install-service.sh --unprivileged -> runs the CHECKOUT as CUTOFF_RUN_USER
#                                                     with a narrow sudoers rule and
#                                                     cap_net_raw, unit "cutoff-user"
#
# The unprivileged flavour is for hosts where you do not want a root-owned
# process holding the console; it needs the checkout to stay in place.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_USER="${CUTOFF_RUN_USER:-$(id -un)}"
MODE="root"

for arg in "$@"; do
  case "$arg" in
    --unprivileged) MODE="user" ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] run as root: sudo $0" >&2
  exit 1
fi

if [ "$MODE" = "root" ]; then
  exec "$PROJECT/tools/install-global.sh" --force
fi

UNIT_NAME="cutoff-user"
UNIT_DST="/etc/systemd/system/${UNIT_NAME}.service"
DATA_DIR="$PROJECT/backend/data"
SITE_PACKAGES_PY="$PROJECT/.venv/bin/python"

if [ ! -x "$SITE_PACKAGES_PY" ]; then
  echo "[*] creating the venv first (needs network once)"
  ( cd "$PROJECT" && python3 -m venv .venv && .venv/bin/pip install -q -r backend/requirements.txt )
fi

echo "[*] installing $UNIT_DST (user=$RUN_USER)"
cat > "$UNIT_DST" <<UNITEOF
[Unit]
Description=CUTOFF console (unprivileged service user)
Documentation=file://$PROJECT/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
WorkingDirectory=$PROJECT
Environment=CUTOFF_HOST=127.0.0.1
Environment=CUTOFF_PORT=8848
Environment=CUTOFF_DATA_DIR=$DATA_DIR
Environment=CUTOFF_SIMULATE=auto
ExecStart=$SITE_PACKAGES_PY $PROJECT/backend/app.py
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=$DATA_DIR
ProtectHome=read-only
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK
SystemCallArchitectures=native
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cutoff

[Install]
WantedBy=multi-user.target
UNITEOF

# Raw ARP needs the capability on the interpreter, not on the script.
setcap cap_net_raw+ep "$(readlink -f "$SITE_PACKAGES_PY")" || \
  echo "[!] setcap failed — ARP sweep falls back to ping + neighbour table"

SUDOERS=/etc/sudoers.d/cutoff
cat > "$SUDOERS.tmp" <<EOF
# CUTOFF: let the service user drive only the firewall binaries.
$RUN_USER ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/hostapd_cli
EOF
if visudo -cf "$SUDOERS.tmp" >/dev/null; then
  install -m 0440 "$SUDOERS.tmp" "$SUDOERS"
  echo "[*] wrote $SUDOERS"
else
  echo "[!] sudoers validation failed; not installed" >&2
fi
rm -f "$SUDOERS.tmp"

mkdir -p "$DATA_DIR"
chown -R "$RUN_USER:" "$DATA_DIR"
chmod 0700 "$DATA_DIR"

systemctl daemon-reload
systemctl enable --now "${UNIT_NAME}.service"
systemctl --no-pager --lines=5 status "${UNIT_NAME}.service" || true

echo "[*] dashboard: http://127.0.0.1:8848/  (token $DATA_DIR/api_token)"
echo "[*] uninstall: systemctl disable --now ${UNIT_NAME}; rm $UNIT_DST"
