# CUTOFF — network device control

Local web console for your own LAN: discover **every** device including the
machine running CUTOFF, extract names and metadata (mDNS, NetBIOS, UPnP, HTTP
titles, TLS certificates, SNMP), drive bundled nmap and bettercap from the UI, then cut access
with the platform firewall, ARP interception and (where the hardware allows)
Wi-Fi deauthentication.

Python backend (Flask + standard library; scapy only on Windows) and a
zero-build HTML/CSS/JS frontend. Runs on **Linux and Windows**. Everything binds
to `127.0.0.1`, behind a generated API token that the page receives
automatically for loopback clients.

![CUTOFF dashboard](docs/screenshot.png)

---

Full feature inventory: [`docs/FEATURES.md`](docs/FEATURES.md).

## Install

### Linux — one command, global `cutoff` command

```bash
git clone <your-remote> cutoff && cd cutoff
sudo ./tools/install-global.sh
```

The installer copies the app to `/opt/cutoff`, builds its own virtualenv, creates
`/var/lib/cutoff` (0700; token and log forced to 0600) and writes a hardened
`cutoff.service`. It then starts the service and prints the URL.

```bash
cutoff                 # start the service (same as: systemctl start cutoff)
cutoff status          # version, paths, URL, port, service state
cutoff logs            # journalctl -u cutoff -f
cutoff stop|restart
cutoff serve           # run in the foreground instead of systemd
cutoff url | token     # http://127.0.0.1:8848/  |  the API token
cutoff doctor          # live plumbing self-check
cutoff update          # reinstall from the checkout you run it in
sudo cutoff uninstall  # remove service, binary, install and data dirs
```

Paths are overridable: `CUTOFF_PREFIX` (default `/opt/cutoff`),
`CUTOFF_BIN_DIR` (`/usr/local/bin`), `CUTOFF_DATA_DIR` (`/var/lib/cutoff`),
`CUTOFF_PORT` (`8848`).

**First-run shortcut.** `sudo ./run.sh` installs to `/opt/cutoff` the first time
it runs and then serves the installed copy. Afterwards `cutoff` is all you need.
Developers who want to run the checkout itself:
`CUTOFF_NO_INSTALL=1 ./run.sh`.

### Windows — `%ProgramData%\CUTOFF` + `cutoff` command

Double-click `run.bat` (or right-click → Run as administrator). On first run it:

1. elevates itself to Administrator,
2. installs the app to `%ProgramData%\CUTOFF` and builds its venv
   (`tools\install-global.bat` does this step on its own too),
3. writes `cutoff.cmd` / `cutoff-doctor.cmd` and appends that bin dir to the
   machine PATH — `cutoff` then works in any new terminal,
4. downloads and silently installs **Npcap 1.90** (WinPcap mode) if missing,
5. downloads portable **nmap 7.92** and **bettercap 2.41.7** into `vendor\`,
6. starts the console on <http://127.0.0.1:8848>.

Only Python 3.10+ must already be installed; the first run needs internet, later
runs are offline. `run.bat` falls back to running from the folder if the global
install fails. Npcap ships under its own license and may ask for a reboot.

### Running without installing

```bash
python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt
CUTOFF_SIMULATE=on .venv/bin/python backend/app.py     # safe, no kernel changes
```

The console prints the URL and the token file. Open <http://127.0.0.1:8848/> —
the token is baked into the page for loopback clients, so there is no paste
step. If you bind beyond localhost, set `CUTOFF_TOKEN_INJECTION=0` and unlock
with the token file manually (`#token=…` works once and is stored locally).

### Bundled tools are not committed

`vendor/` holds ~190 MB of binaries, so it is git-ignored. After cloning:

```bash
./tools/fetch-vendor.sh     # nmap 7.92 + bettercap 2.41.7 into vendor/
```

Without them the console still runs; the Nmap and Bettercap pages report the
tool as unavailable.

**Modes**

| Mode | When | Behaviour |
|---|---|---|
| Live | root / passwordless sudo (Linux) or Administrator (Windows) | real ARP scan, real firewall rules, real ARP block |
| Simulation | unprivileged, or `CUTOFF_SIMULATE=on` | scan still works (ping + neighbour table); blocks are recorded and shown, but no kernel rule is installed. A yellow banner states this everywhere. |

Force a mode with `CUTOFF_SIMULATE=on|off`. `auto` (default) picks simulation
only when the process cannot enforce.

### Platform support

| Capability | Linux | Windows |
|---|---|---|
| Inventory / names / fingerprinting | yes | yes |
| nmap console | bundled 7.92 | bundled 7.92 (auto-download) |
| bettercap console | bundled 2.41.7 | bundled 2.41.7 + Npcap |
| LAN-wide block | iptables + raw ARP | Windows Firewall + scapy/Npcap ARP |
| Block works without driver | yes (root) | needs Npcap (auto-installed) |
| Wi-Fi deauth | hostapd or monitor adapter | not supported |
| Gateway/AP topology | yes | only if Windows is the gateway |

On Windows, CUTOFF refuses a block if the ARP layer cannot start; Windows
Firewall alone only filters traffic to/from the Windows PC, and the UI never
claims a LAN-wide block in that case.

---

## What it does

**Discovery**
- ARP sweep of the local subnet — raw `AF_PACKET` on Linux (root), scapy +
  Npcap on Windows (Administrator) — fastest and catches devices that block ICMP.
- Falls back to a parallel ICMP ping sweep + the OS neighbour table when the
  driver/privileges are missing.
- Resolves names from reverse DNS and Linux dnsmasq/NetworkManager DHCP leases,
  vendors from a built-in OUI table (`backend/data/oui.csv` extends it).
- Merges everything into a persistent inventory: first/last seen, online/offline,
  user-assigned name, notes.

**Fingerprinting & nmap**
- mDNS (service instances, `.local` hostnames, TXT models), NetBIOS node status,
  SSDP/UPnP descriptions, HTTP titles, TLS certificate subject/SAN and SNMP
  `sysName` — all unprivileged, all merged into each device's `info`.
- **Deep scan** runs the bundled nmap 7.92 (`vendor/nmap`, extracted from the
  Fedora RPM, no install): TCP connect scan, version detection, hostname scripts
  (`nbstat`, `http-title`, `ssl-cert`, `smb-os-discovery`, `upnp-info`,
  `snmp-sysdescr`). Root adds SYN scan + OS detection.
- The host running CUTOFF is included as a normal row tagged **this host**, with
  its platform, kernel and addresses in the details modal.

**Control**
- `Block` — Linux: tagged iptables rules in `INPUT`, `FORWARD` and `OUTPUT`
  (source and destination MAC/IP); Windows: `CUTOFF-*` Windows Firewall rules by
  IP. Both add a **bidirectional ARP black hole**: the victim is told the
  gateway is at our MAC, the gateway is told the victim is at our MAC.
  **Complete isolation** additionally poisons every known active LAN peer in
  both directions, so direct device-to-device traffic is dropped too.
  Optional Wi-Fi deauth.
- `Unblock` — deletes exactly the rules tagged with that MAC and restores ARP.
- `Cut Wi-Fi` — Linux: `hostapd_cli deauthenticate` when this host runs the AP,
  else 802.11 deauth frames through a monitor-mode adapter. Windows: not
  supported (use Block).
- `Restore all` — emergency exit: stops interception, flushes the chain, clears
  every block.
- `Network map` page (`/map`) — gateway-centred topology of every client with
  live/blocked/offline lines, clickable nodes and a detail card.
- Every action is written to an append-only activity log (`backend/data/events.jsonl`).
- Blocks persist across restarts: in live mode the backend re-applies every
  remembered block (firewall + interception) at startup. `Restore all` clears them.

---

## Nmap console (`/nmap`)

nmap 7.92 is bundled under `vendor/nmap` (Windows build in `vendor/nmap/win32`,
auto-downloaded by `run.bat`) — nothing to install manually. The page turns
presets into buttons and restricts targets to your own network:

| Button | What it runs |
|---|---|
| Discover hosts | `-sn` sweep |
| Fast scan + versions | top 100 TCP ports, `-sV` |
| Service scan | TCP 1–1024, `-sV` |
| OS detection | `-sS -O --osscan-guess` (root only) |
| Default scripts | top 50 ports + safe NSE |
| Vulnerability scripts | `--script vuln` (slow, loud) |
| Full TCP + versions | all 65535 ports (very slow) |

Target = whole subnet, gateway, one inventoried device, or a custom IP/CIDR
inside the local subnet. Live host table, raw output and a Stop button.
Unprivileged runs use TCP connect scans; OS detection needs `sudo ./run.sh`.

`-Pn` can label a silent target "up", so CUTOFF only counts a host as found when
nmap has evidence (an open port, a closed/reset port, or a real discovery
reason). Responsive hosts are synced back into the inventory, so a device found
by nmap no longer shows offline on the Devices page; targets with no response
are labelled **no response** and never mark a device online. A device that was
confirmed in the last five minutes also stays **online** through a missed ping
sweep, so a sleeping phone does not flap offline between nmap scans.

## Bettercap console (`/bettercap`)

bettercap 2.41.7 is bundled under `vendor/bettercap` (Linux, with a local
libpcap soname shim) and `vendor/bettercap/win64` (Windows, uses Npcap).
Buttons start fixed, auditable presets:

| Preset | What it does |
|---|---|
| Network recon | `net.probe on`, `net.show` |
| Sniff traffic | `net.sniff on` |
| Full LAN monitor | ARP spoof (whole LAN or one device) + sniff |
| HTTP proxy | transparent HTTP proxy + sniff |

Live console, Start/Stop, target picker and log clearing. Bettercap needs root
for ARP/sniffing; the page disables start when unprivileged and warns that ARP
spoofing is visible on the LAN. Only run it on a network you administer.

## How blocking actually works (read this)

A firewall on a normal workstation cannot filter another device's traffic. CUTOFF
picks the strongest layer the current topology allows and reports exactly what it
did:

| This host is… | What `Block` does | Scope |
|---|---|---|
| the gateway / AP (default gateway is one of this host's IPs, or hostapd is running) | iptables `INPUT` + `FORWARD` DROP by MAC/IP | network-wide |
| an ordinary LAN host | iptables drop for traffic to this machine **+** forged ARP replies telling the victim the gateway is at our MAC, so its off-LAN traffic is black-holed | internet cut for the victim; LAN-to-LAN traffic between other hosts is unaffected |
| unprivileged | nothing — simulated block, banner shown | none |

The ARP layer is one-directional, never enables `ip_forward`, re-poisons every
2 seconds, expires after `CUTOFF_POISON_MAX_MIN` (default 120), and always sends
corrective ARP replies on unblock/shutdown. If `ip_forward` is already enabled
(Docker/VPN), interception is only allowed after the MAC-level `FORWARD` drop is
verified — otherwise it refuses, because forwarding would turn a block into a MITM.

**What "complete" means on a workstation.** With `isolation: "full"` the
victim's IPv4 path to the gateway and to every peer known at block time is
black-holed in both directions, and iptables drops anything that still reaches
this host. Two gaps remain on a non-gateway host: IPv6 (ARP cannot poison NDP)
and peers discovered after the block. Run CUTOFF on the gateway/AP, or use the
router's own client-block API, for a hardware-level cut. The UI/API state this
in the block warnings.

## IPv6 (`/ipv6`)

IPv6 does not use ARP, so ARP interception never covers it. CUTOFF closes that
gap in `ip6tables` with two rule types, both tagged and removable:

| Rule | Where | What it stops |
|---|---|---|
| MAC match (`--mac-source`) | `CUTOFF_BLOCK` (INPUT, FORWARD) | every IPv6 packet from that device the host or a forwarded path sees, including addresses that rotate |
| per-address `-s` / `-d` | `CUTOFF_BLOCK` + `CUTOFF_OUT` (OUTPUT) | the known global/ULA/link-local addresses in both directions, including packets this host sends to the victim |
| prefix block (`-s`/`-d <prefix>`) | both chains | anything a device generates inside a /64, which is what SLAAC privacy addresses need |

Why two chains: the `xt_mac` match is only valid for packets *entering* a host,
and ip6tables rejects a chain containing a MAC rule when that chain is reached
from `OUTPUT`. `CUTOFF_BLOCK` therefore serves INPUT/FORWARD and `CUTOFF_OUT`
serves OUTPUT; upgrades from older builds drop the stale OUTPUT jump.

The NDP cache (`ip -6 neigh`) is the only mapping from IPv6 to a MAC, so the
inventory joins v6 addresses to devices by MAC on every scan. Addresses that
disappear from the cache are cleared, not kept as stale blockable values.

Guards: a prefix wider than `/16` is refused, a `/128` is refused (block the
device instead), and a prefix containing one of this host's own addresses is
refused unless `force=true` — blocking your own /64 cuts the console off the
link it administers.

**Blocking from Devices is one action for both families.** The Block dialog on
the dashboard sends `ip6: true`, so the same click installs the IPv4 MAC/IP
rules, the IPv6 MAC rule, and the device's known IPv6 addresses; it lists the
addresses it is about to cut and reports `IPv4 + IPv6 (n addrs)` in the toast.
Unblock removes both families and any prefix rule the block created.

If the inventory has no IPv6 address for the device, `block()` asks the kernel's
NDP cache directly before giving up, so a device that has been quiet since the
last scan is still covered. An optional checkbox adds the covering `/64` for a
global/ULA address — that is what keeps SLAAC privacy addresses dead after they
rotate, at the cost of cutting IPv6 for every host in that prefix.

**Scope, stated plainly:** on an ordinary host these rules filter traffic to and
from this machine. A LAN-wide IPv6 cut still needs CUTOFF on the gateway/AP. The
page repeats that in the footer, and every block response carries its warnings.

**Wi-Fi deauth is a kick, not a ban.** Without AP control or a monitor adapter
this machine physically cannot deauth anyone — the UI says so and points at
`Block`. Deauth also only works on wireless clients; it does nothing to wired
devices.

---

## Requirements

- Linux with `iptables` (nft backend is fine; `ip6tables` used when present)
- Python 3.10+ (`python3-venv`)
- nmap 7.92 is bundled under `vendor/nmap`; `tools/install-nmap-rpm.sh` re-fetches it
- bettercap 2.41.7 is bundled under `vendor/bettercap`; `tools/install-bettercap.sh`
  re-fetches it (libpcap runtime is the only host dependency)
- Optional: `hostapd`/`hostapd_cli` if this host is the AP, `iw` + a monitor-mode
  adapter for frame injection
- `waitress` (in `backend/requirements.txt`) serves the app; without it the app
  falls back to the Flask dev server and says so on startup
- Ports: none inbound beyond the local listener on `127.0.0.1:8848`

---

## API

All `/api/*` routes require `X-API-Token: <token>` (or `?token=`), except
`/api/health`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness, no auth |
| GET | `/api/status` | interface, counts, topology, capabilities, scan state |
| GET | `/api/devices` | inventory merged with block state |
| GET | `/api/devices/<mac>` | full record for one device |
| GET | `/api/nmap` | presets, targets, binary info, last scan |
| POST | `/api/nmap/run` | `{ "preset", "target", "custom"? }` |
| POST | `/api/nmap/stop` | stop the running scan |
| GET | `/api/bettercap` | session state, log, capabilities, devices |
| POST | `/api/bettercap/start` | `{ "preset", "targets"? }` |
| POST | `/api/bettercap/stop` | stop and restore bettercap |
| POST | `/api/scan` | start scan; body `{"deep": true}` adds nmap (`202`), `409` if running |
| GET | `/api/scan` | scan progress/result |
| POST | `/api/devices/<mac>/name` | `{ "name": "…" }` |
| POST | `/api/block` | `{ "mac", "mode": "mac"\|"ip"\|"both", "isolation": "full"\|"internet", "force"?, "ip6"? (default true), "ip6_prefix"? }` — one call blocks IPv4 **and** IPv6 |
| POST | `/api/unblock` | `{ "mac" }` |
| POST | `/api/wifi/cut` | `{ "mac", "seconds"?, "bssid"? }` |
| POST | `/api/panic` | remove all rules + interceptions (both families, both chains) |
| GET | `/api/ipv6` | addresses, prefixes, NDP neighbours, live IPv6 rules, ip6tables capabilities |
| POST | `/api/ipv6/block` | `{ "mac", "mode"?, "isolation"?, "force"?, "ip6_prefix"? }` — same merged block, addressed from the IPv6 page |
| POST | `/api/ipv6/unblock` | `{ "mac" }` — removes the v4 and v6 rules in both chains |
| POST | `/api/ipv6/prefix` | `{ "prefix": "2001:db8:1::/64", "force"? }` — block a whole prefix |
| POST | `/api/ipv6/prefix/unblock` | `{ "prefix" }` |
| GET/DELETE | `/api/events` | activity log |

Example:

```bash
TOKEN=$(cat backend/data/api_token)

curl -s -X POST -H "X-API-Token: $TOKEN" http://127.0.0.1:8848/api/scan
curl -s -H "X-API-Token: $TOKEN" http://127.0.0.1:8848/api/devices | jq
curl -s -X POST -H "X-API-Token: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"mac":"aa:bb:cc:dd:ee:ff","mode":"both"}' \
     http://127.0.0.1:8848/api/block
```

Guardrails: own MACs, multicast/broadcast and unknown devices are refused; the
gateway requires `force: true` because blocking it disconnects everything,
including the console host.

---

## Tests & diagnostics

```bash
.venv/bin/python -m unittest discover -s tests -v     # 57 tests, no root needed
sudo .venv/bin/python backend/doctor.py --apply       # safe live plumbing check
```

`doctor.py --apply` adds and removes a rule for `02:00:00:00:00:01` /
`203.0.113.7` (TEST-NET-3), so it never touches a real device.

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CUTOFF_HOST` | `127.0.0.1` | bind address (do not expose without TLS/auth review) |
| `CUTOFF_PORT` | `8848` | HTTP port |
| `CUTOFF_SIMULATE` | `auto` | `auto` / `on` / `off` |
| `CUTOFF_TOKEN` | file-generated | override the API token |
| `CUTOFF_DATA_DIR` | `backend/data` | inventory, events, token, logs |
| `CUTOFF_SCAN_CONCURRENCY` | `64` | ping sweep workers |
| `CUTOFF_SCAN_MAX_HOSTS` | `1024` | refuse larger subnets |
| `CUTOFF_RECENT_SEC` | `300` | keep a device online this long after its last sighting |
| `CUTOFF_POISON_REFRESH` | `2` | ARP re-poison interval (seconds) |
| `CUTOFF_POISON_MAX_MIN` | `120` | interception auto-expiry |
| `CUTOFF_LOG_LEVEL` | `INFO` | log verbosity |

Data lives in `backend/data/` (`devices.json`, `events.jsonl`, `api_token`,
`cutoff.log`). Delete `devices.json` to reset the inventory.

---

## Service flavours

| Flavour | Install | Runs as | Unit | Use when |
|---|---|---|---|---|
| Global (recommended) | `sudo ./tools/install-global.sh` | root | `cutoff` | normal host; `/opt/cutoff`, data in `/var/lib/cutoff` |
| Unprivileged | `sudo ./tools/install-service.sh --unprivileged` | `$CUTOFF_RUN_USER` | `cutoff-user` | you do not want a root-owned console; keeps the checkout in place |
| Foreground | `./run.sh` / `cutoff serve` | your shell | — | development, debugging, one-off |

The unprivileged flavour grants exactly three binaries through
`/etc/sudoers.d/cutoff` (`iptables`, `ip6tables`, `hostapd_cli`), validates the
file with `visudo -cf`, and sets `cap_net_raw+ep` on the venv interpreter for the
ARP sweep. That removes the "every Flask route runs as root" property, at the
cost of a `sudo -n` call per rule change.

Operational bits:

```bash
./tools/backup-data.sh                 # tar.gz of inventory/events/token/log (keep 10)
CUTOFF_KEEP=30 ./tools/backup-data.sh   # retention override
```

- Logs rotate at 5 MB × 5 files; the console keeps serving if a log write fails.
- The data dir is `0700`; `devices.json`, `events.jsonl`, `api_token` and the log
  are forced to `0600` at startup (`config.secure_data_dir()`).
- `backend/requirements.lock` pins the resolved graph for offline rebuilds.
- `CUTOFF_SIMULATE=auto` keeps an unprivileged run honest: rules are modelled and
  displayed (tagged `simulated`), never written.

## Security & limitations

- The console is local-only by default and token-protected, but it is plain HTTP.
  If you bind it wider, put TLS and real authentication in front of it.
- MAC blocks are defeated by MAC randomisation; IP blocks by DHCP renewal.
  Blocking is a LAN-management control, not a security boundary against a
  determined attacker.
- ARP interception breaks if the victim uses IPv6 for internet traffic or has a
  static ARP entry; deploy CUTOFF on the gateway for complete coverage.
- Windows: the firewall layer is IP-based (no MAC filter in Windows Firewall);
  the ARP layer (scapy + Npcap) provides the LAN cut. Windows refuses a block if
  the ARP layer cannot start, rather than pretending the firewall blocked it.
  Wi-Fi deauth is Linux-only.
- iptables rules persist until unblocked or `Restore all`; the chain is not
  removed on process exit (interception *is* restored on exit).
- Only use this on networks you own or administer. Cutting another person's
  access without authorisation is a crime in most jurisdictions.
- Deauth/jamming can be illegal even on your own network depending on local
  radio regulations; it is rate-limited to a short burst per request.
- Windows requires Administrator for Npcap/firewall/ARP. Npcap is a third-party
  driver downloaded at first start, not bundled; review its license before use.

---

## Layout

```
CUTOFF/
├── backend/
│   ├── app.py          Flask API + static hosting + scan job
│   ├── discovery.py    ARP/ping sweep, self host, nmap merge
│   ├── fingerprint.py  mDNS, NetBIOS, SSDP, HTTP, TLS, SNMP probes
│   ├── nmapscan.py     bundled nmap adapter + XML parser
│   ├── nmapgui.py      preset runner + target validation
│   ├── bettercap_ctl.py bundled bettercap session controller
│   ├── platform_ops.py OS privileges, Npcap/scapy install, portable tools
│   ├── ipv6.py         NDP cache, address/prefix parsing, inventory join
│   ├── firewall.py     Linux iptables + ip6tables chains (CUTOFF_BLOCK/CUTOFF_OUT)
│   ├── firewall_win.py Windows Firewall rules (IP-level, v4 + v6)
│   ├── arpguard.py     Linux ARP interception + gateway mode
│   ├── arpguard_win.py Windows ARP block via scapy/Npcap
│   ├── wifi.py         hostapd / monitor-mode deauth (Linux)
│   ├── enforcer.py     topology choice, guardrails, orchestration
│   ├── store.py        atomic JSON inventory + JSONL audit log
│   ├── netinfo.py      routes, interfaces, neighbour/lease parsing
│   ├── oui.py          offline vendor table
│   ├── doctor.py       live plumbing self-check
│   └── config.py
├── frontend/
│   ├── index.html        device inventory
│   ├── map.html          gateway topology
│   ├── nmap.html         nmap console
│   ├── bettercap.html    bettercap console
│   ├── ipv6.html         IPv6 console (addresses, prefixes, NDP, rules)
│   └── assets/{style.css,app.js,map.js,nmap.js,bettercap.js,ipv6.js}
├── tests/test_cutoff.py
├── docs/{flows.mmd,flows.svg,ARCHITECTURE.md,screenshot.png}
├── tools/{install-service.sh,backup-data.sh,install-nmap-rpm.sh,install-bettercap.sh}
├── run.sh              Linux launcher
├── run.bat             Windows launcher (elevates, installs Npcap on first run)
├── vendor/nmap         portable nmap (Linux + Windows)
├── vendor/bettercap    portable bettercap (Linux + Windows)
├── cutoff.service      hardened systemd unit (install via tools/install-service.sh)
└── backend/requirements.lock   pinned dependency graph
```
