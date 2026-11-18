# CUTOFF — complete feature list

Local console for a LAN you administer: discover every device, learn what it is,
and cut its access — IPv4 and IPv6 — from one page. Linux and Windows, no cloud,
no account, no install of the big tools (nmap and bettercap are bundled).

Everything binds to `127.0.0.1`. The page is plain HTML/CSS/JS with no build step.

---

## 1. Pages

| Page | Route | What it does |
|---|---|---|
| Devices | `/` | Inventory table, scan/deep-scan, block/unblock, Wi-Fi cut, rename, detail modal, activity log, stat cards, live/simulation badge |
| Network map | `/map` | Gateway-centred SVG topology, status-coloured links, hover tooltip, click-through device card |
| Nmap | `/nmap` | Seven fixed presets, target picker (subnet / gateway / any inventoried device / custom IP-CIDR), host table, raw output, stop |
| Bettercap | `/bettercap` | Four fixed presets, target multi-select, live REPL log ring, start/stop/clear |
| IPv6 | `/ipv6` | Own addresses and prefixes, NDP neighbours, prefix blocks, live `ip6tables` rules, filter by scope |

Every page: token auto-injected for loopback clients, `Cache-Control: no-store`,
**dark and off-white light themes** with a persisted toggle (OS preference on
first visit, no flash), glass sidebar shell that collapses to a wrapping top bar,
bento dashboard grid, uniform responsive footer, `prefers-reduced-motion` and
`prefers-reduced-transparency` respected, keyboard-reachable controls with visible
focus rings, `aria-live` toasts.

---

## 2. Discovery and inventory

- **ARP sweep** over `AF_PACKET`/`ETH_P_ARP` (needs `CAP_NET_RAW`) with a
  configurable timeout.
- **Unprivileged fallback**: parallel `ping` sweep (bounded workers) followed by
  the kernel neighbour table (`ip neigh`, `/proc/net/arp`; PowerShell
  `Get-NetNeighbor` on Windows).
- **Self-host row**: the machine running CUTOFF appears in the inventory with
  hostname, platform, kernel, machine, Python version and its own addresses; its
  Block action is disabled.
- **Deep scan**: nmap pass for ports, versions, OS and NSE hostnames; responsive
  hosts are synced back into the inventory (`active`, ports, services,
  `sources`), so a host found on the Nmap page is not left "offline" on Devices.
  `-Pn`-only "up" answers and all-filtered targets are *not* treated as live.
- **Bounds**: subnet size checked before sweeping (`CUTOFF_SCAN_MAX_HOSTS`,
  default 1024), thread pool capped (`CUTOFF_SCAN_CONCURRENCY`, 64).
- **Merge semantics**: devices missing from a scan become `offline`, never
  deleted; rich metadata is never downgraded to "Unknown" on a later scan; a
  device seen within `CUTOFF_RECENT_SEC` (300 s) stays online so a sleeping phone
  does not flap.
- **IPv6 join**: the NDP cache (`ip -6 neigh`) is merged by MAC on every scan;
  addresses that rotated away are cleared rather than kept blockable.
- **Scan job** runs in a background thread with a phase (`discovering`,
  `fingerprinting`, `nmap`, `done`/`error`), progress, warnings and elapsed time,
  and refuses concurrent runs.

---

## 3. Fingerprinting (names, model, type)

Unprivileged probes, run in parallel with a per-probe timeout:

| Probe | Data |
|---|---|
| mDNS | instance names (`_airplay._tcp.local`), SRV/PTR hosts, model, services |
| NetBIOS | node name via UDP 137 status query (18-byte entries handled) |
| SSDP/UPnP | `friendlyName`, manufacturer, model, device type from the device XML |
| HTTP | page `<title>` and `Server` header on 80/443/8080/8000/5000/8443 |
| TLS | certificate subject, issuer, SANs and validity via the `openssl` CLI |
| SNMP | `sysName`, `sysDescr`, uptime with community `public` (best effort) |
| Reverse DNS / DHCP leases | hostname fallbacks |

- **Name ladder**: mDNS instance → UPnP friendlyName → NetBIOS → mDNS host
  (strips `.local`) → reverse DNS → DHCP lease; `_gateway`, `_local`,
  `localhost` and `_`-prefixed answers are filtered.
- **Vendor**: bundled offline OUI table (`oui.py`) with a
  `backend/data/oui.csv` override; locally-administered MACs are labelled
  "Private / randomised" instead of guessed.
- **Device type** classification (router, phone, printer, TV, workstation, …)
  from ports, names and OUI.

---

## 4. Enforcement — IPv4

Two tagged chains, hooked at position 1, never touching the operator's rules:

```
CUTOFF_BLOCK   ← INPUT, FORWARD     (MAC + L3 rules)
CUTOFF_OUT     ← OUTPUT             (L3 rules only; xt_mac is invalid here)
```

- **Modes**: `mac` (L2 source drop), `ip` (source + destination drops for the
  current lease), `both` (default).
- **Idempotent + verified**: `-C` before `-A`, `-C` again afterwards; every rule
  carries `CUTOFF:<mac>:<scope>` so removal is precise and never touches an
  untagged rule.
- **ARP black hole** (non-gateway host): forged replies tell the victim the
  gateway IP lives at our MAC, refreshed every 2 s, TTL-capped
  (`CUTOFF_POISON_MAX_MIN`, 120), never enables `ip_forward`, and always sends
  corrective replies on unblock / stop / process exit.
  - `isolation: "internet"` → victim ⇄ gateway pair only.
  - `isolation: "full"` → also every known LAN peer, both directions.
  - If `ip_forward` is already on (Docker/VPN), interception is refused unless
    the L2 `FORWARD` drop is installed and verified — otherwise a block would
    silently become a MITM.
- **Gateway topology**: when the default gateway is one of this host's IPs (or
  hostapd runs), blocks are pure `INPUT`/`FORWARD` drops and cover the whole
  LAN; ARP interception is skipped.
- **Persistence**: blocks are stored and re-applied at startup in live mode,
  with a count of restored/failed; unblock persists too (no resurrection).
- **Panic / "Restore all"**: stops every interceptor, removes every tagged rule,
  flushes and deletes both chains in both families, clears block records.

## 5. Enforcement — IPv6

- **MAC rule** (`-m mac --mac-source`) in `CUTOFF_BLOCK` — survives SLAAC privacy
  addresses.
- **Per-address `-s`/`-d` rules** for every known global / ULA / link-local
  address, in both chains (so our own outbound traffic to the victim is dropped
  too).
- **Prefix block** (`-s`/`-d <prefix>`) to cover address rotation inside a /64.
- **Merged block**: one Block click on Devices blocks IPv4 *and* IPv6 — MAC rule,
  known v6 addresses, and optionally the covering /64. If the inventory has no
  v6 address yet, the enforcer queries the NDP cache directly for that MAC.
- **Unblock** removes both families plus any prefix rule the block installed.
- **Guards**: prefix must be IPv6, not wider than `/16`, not a `/128`, and must
  not contain one of this host's own addresses without `force`; `fe80::/64` is
  never auto-prefix-blocked because it is shared with this host.
- **Display**: rules are de-duplicated per chain (`-s`/`-d` twins collapse) and
  labelled in human terms (`mac · in`, `addr · out`, `prefix · in`).

## 6. Wi-Fi deauthentication (where the hardware allows)

- Path 1: `hostapd_cli deauthenticate <mac>` when this host runs the AP.
- Path 2: raw 802.11 deauth frames (radiotap + `c0 00` + addr1/2/3 + reason 7,
  34 bytes) when a monitor-mode adapter and the BSSID are available.
- Burst capped by seconds (1–60); refuses rather than pretends when neither path
  exists; Windows reports "not supported" and points at Block.
- Honest framing: deauth is a kick, not a ban — the client reconnects unless it
  is also blocked.

---

## 7. Nmap console

- Binary resolution: `CUTOFF_NMAP`, bundled `vendor/nmap` (Linux RPM extract or
  `win32` build), then `PATH`. Version and `NMAPDATADIR` reported in the UI.
- Seven fixed presets (server-side whitelist, never raw args from the browser):
  discover hosts, fast scan + versions, service scan, OS detection, default
  scripts, vulnerability scripts, full TCP + versions.
- Targets restricted to the local subnet / inventoried devices; custom IP or CIDR
  validated server-side.
- Writes `-oX` and `-oN`, polls a status object, parses XML (ports, services,
  versions, OS, NSE output under `<port>` *and* `<hostscript>`), streams raw
  text, supports Stop, and syncs responsive hosts into the inventory.

## 8. Bettercap console

- Bundled bettercap 2.41.7 with a local `libpcap.so.0.8` shim
  (`LD_LIBRARY_PATH`); Npcap's `wpcap.dll` on Windows.
- Four presets: network recon, sniff traffic, full LAN monitor (in-path), HTTP
  proxy.
- REPL driven over pipes with stdin held open, ANSI stripped, output in a ring
  buffer; `quit` + terminate on stop; refuses to start without root rather than
  spawning a session that dies.
- Targets validated against the inventory.

## 9. Monitoring engine (present, not wired into this build)

`backend/monitor.py` implements metadata capture: passive `AF_PACKET` capture,
DNS/SNI/HTTP-Host parsers, per-IP counters, flow records, a domain/keyword
policy that raises alerts, and an opt-in in-path `LanGateway` mode that enables
`ip_forward`, restores it on stop, and stays TTL-limited. It is scoped to the
inventory (remote endpoints never become devices) and stores no payloads. This
build does **not** expose it over HTTP — there is no `/monitor` page or
`/api/monitor*` route; the module is a library you can wire up.

---

## 10. HTTP API

25 routes, all requiring `X-API-Token` (or `?token=`) except `/api/health`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness, no auth |
| GET | `/api/status` | network, counts, topology, capabilities, IPv6 roll-up, scan state |
| GET | `/api/devices` | inventory merged with block state |
| GET | `/api/devices/<mac>` | full record for one device |
| POST | `/api/devices/<mac>/name` | `{name}` rename (64 chars, trimmed) |
| POST | `/api/scan` | start scan, `{deep: true}` adds nmap (202; 409 if running) |
| GET | `/api/scan` | progress/result |
| POST | `/api/block` | `{mac, mode?, isolation?, force?, ip6?, ip6_prefix?}` — both families |
| POST | `/api/unblock` | `{mac}` — removes v4 + v6 + prefix rules, stops interception |
| POST | `/api/wifi/cut` | `{mac, seconds?, bssid?}` |
| POST | `/api/panic` | remove every rule and interceptor |
| GET | `/api/ipv6` | addresses, prefixes, NDP neighbours, v6 rules, capabilities |
| POST | `/api/ipv6/block` | merged block addressed from the IPv6 page |
| POST | `/api/ipv6/unblock` | `{mac}` |
| POST | `/api/ipv6/prefix` | `{prefix, force?}` block a prefix |
| POST | `/api/ipv6/prefix/unblock` | `{prefix}` |
| GET | `/api/nmap` | capabilities, presets, targets, status |
| POST | `/api/nmap/run` · `/api/nmap/stop` | preset run / stop |
| GET | `/api/bettercap` · POST `start`/`stop`/`clear` | session control |
| GET · DELETE | `/api/events` | audit log (`limit`, max 500) / clear |

Errors are JSON with a message; unknown non-API paths return a plain 404 (no SPA
fallback that hides a removed page).

---

## 11. Data, persistence, audit

- `backend/data/devices.json` — atomic write (temp + `fsync` + `rename`), holds
  devices, blocks (incl. `ip6`/`ip6_prefix`) and a schema version; a corrupt file
  is moved aside as `.corrupt` instead of killing the service.
- `backend/data/events.jsonl` — append-only audit log: scan, block, unblock,
  rename, wifi, panic, IPv6 prefix, startup restore; capped reads, clearable.
- `backend/data/api_token` — generated on first run, `0600`, injected into pages
  for loopback clients only (gated on bind address *and* `remote_addr`).
- `backend/data/monitor.json`, `nmap/` — capture policy and nmap output files.
- `backend/data/oui.csv` — optional vendor-table override.

## 12. Safety rails

- Refuses: own MACs, multicast/broadcast, unknown devices, invalid MACs, and the
  gateway MAC without `force` (with an explicit warning about disconnecting the
  whole network).
- Simulation is a first-class mode (`CUTOFF_SIMULATE=on|off|auto`, default auto =
  unprivileged): every response carries `simulated`, a persistent banner says it,
  and the simulated ruleset is modelled so the UI shows what *would* be applied —
  never a silent no-op.
- Every block response lists the layers actually applied and the warnings about
  what it does not cover (IPv6 before this feature, later-discovered peers,
  non-gateway scope).

## 13. Global install and the `cutoff` command

Linux, one command (needs root once):

```bash
sudo ./tools/install-global.sh      # /opt/cutoff + /var/lib/cutoff + cutoff.service
cutoff                              # start | status | logs | stop | restart
```

| Piece | Detail |
|---|---|
| Install dir | `/opt/cutoff` (overridable with `CUTOFF_PREFIX`); app, venv, frontend, docs, tools |
| Data dir | `/var/lib/cutoff`, `0700`, token/log `0600` (overridable with `CUTOFF_DATA_DIR`) |
| Command | `/usr/local/bin/cutoff` → `$PREFIX/bin/cutoff`, pins prefix/data/port |
| Service | hardened `cutoff.service`, `Restart=always`, journal logging |
| First run | `./run.sh` installs automatically, then serves the installed copy (`CUTOFF_NO_INSTALL=1` keeps it local) |
| Upgrade | `sudo ./tools/install-global.sh --force` or `cutoff update` from a checkout |
| Removal | `sudo cutoff uninstall` (service, binary, install dir, data dir) |

CLI commands: `start`, `serve`, `stop`, `restart`, `status`, `logs`, `url`,
`token`, `doctor [--apply]`, `update`, `uninstall`, `version`, `path`, `help`.

Windows: `tools\install-global.bat` copies to `%ProgramData%\CUTOFF`, builds the
venv, writes `cutoff.cmd` / `cutoff-doctor.cmd` and appends the bin dir to the
machine PATH; `run.bat` calls it on first run and falls back to a local run if it
fails.

## 14. Operations

- **Server**: waitress (`threads=8`), with a printed fallback to the Flask dev
  server if waitress is missing.
- **systemd unit** (`cutoff.service`): `Restart=always`, `UMask=0077`,
  `ProtectSystem=strict` + `ReadWritePaths=backend/data`,
  `ProtectHome=read-only`, `ProtectKernelTunables/Modules/ControlGroups`,
  `RestrictNamespaces`, `LockPersonality`, `SystemCallFilter=@system-service`,
  `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE`,
  `AF_UNIX/AF_INET/AF_INET6/AF_PACKET/AF_NETLINK` only, journal logging.
- **`tools/install-service.sh`** — installs and enables the unit; `--unprivileged`
  runs it as a normal user with a `visudo -cf`-validated
  `/etc/sudoers.d/cutoff` (only `iptables`, `ip6tables`, `hostapd_cli`) and
  `cap_net_raw+ep` on the venv interpreter.
- **`tools/backup-data.sh`** — timestamped tar.gz of inventory/events/token/log
  into `data/backups`, retention via `CUTOFF_KEEP` (default 10).
- **Log rotation**: 5 MB × 5.
- **Permissions**: `data/` 0700, sensitive files 0600 at startup.
- **Pinned deps**: `backend/requirements.txt` + `backend/requirements.lock`
  (Flask 3.1.0, Werkzeug 3.1.9, waitress 3.0.2).
- **`backend/doctor.py`** — live self-check: privileges, interface/gateway,
  wireless/monitor/hostapd, iptables + ip6tables, IPv6 stack/addrs/prefixes/NDP/
  forwarding, `ip_forward`; `--apply` installs, verifies and removes a dummy
  IPv4 **and** IPv6 rule (`02:00:00:00:00:01` / `203.0.113.7` / `2001:db8::7`).

## 15. Platform support

| Capability | Linux | Windows |
|---|---|---|
| Discovery | ARP (root) or ping + neigh | scapy/Npcap (`srp`) or ping + `Get-NetNeighbor` |
| Firewall | iptables + ip6tables, tagged chains | Windows Firewall `remoteip` rules (IPv4 + IPv6), MAC only in the rule name |
| L2 cut | ARP black hole (`AF_PACKET`) | ARP black hole via scapy/Npcap; block refused if that layer fails |
| IPv6 | ip6tables MAC/address/prefix rules | IP-level v6 rules only (no MAC match) |
| Wi-Fi deauth | hostapd or monitor mode | not supported (reports so) |
| Bundled tools | nmap (RPM extract), bettercap + libpcap shim | nmap, bettercap via Npcap (`wpcap.dll`) |
| Elevation | `sudo` / root, or sudoers + `cap_net_raw` | `run.bat` self-elevates, silent Npcap install |

## 16. Configuration (`CUTOFF_*`)

| Variable | Default | Meaning |
|---|---|---|
| `CUTOFF_HOST` / `CUTOFF_PORT` | `127.0.0.1` / `8848` | bind address/port (a warning fires if not loopback) |
| `CUTOFF_SIMULATE` | `auto` | `on`, `off`, or auto (= unprivileged) |
| `CUTOFF_TOKEN` / `CUTOFF_TOKEN_INJECTION` | generated / `1` | fixed token; disable page injection |
| `CUTOFF_DATA_DIR` | `backend/data` | inventory, events, token, logs |
| `CUTOFF_LOG_LEVEL` | `INFO` | root log level |
| `CUTOFF_BLOCK_TTL_MIN` | `0` (forever) | published block TTL |
| `CUTOFF_POISON_REFRESH` / `CUTOFF_POISON_MAX_MIN` | `2` / `120` | ARP refresh interval, interception cap |
| `CUTOFF_SCAN_CONCURRENCY` / `CUTOFF_SCAN_MAX_HOSTS` | `64` / `1024` | sweep bounds (refuses larger subnets) |
| `CUTOFF_RECENT_SEC` | `300` | keep a device online this long after last sighting |
| `CUTOFF_NMAP` | — | explicit nmap binary |

## 17. Tests and quality gates

- **95 unittest cases**, no root and no network required: DNS/mDNS/NetBIOS/UPnP
  parsers, nmap XML (+`extraports`), self-host, store merge/persist/removal, ARP
  frame layout, deauth frame offsets, firewall argument construction with a fake
  runner (both families, both chains), guardrails, simulation without kernel
  calls, IPv6 parsing/prefix validation/tag parsing, enforcer merged-block and
  prefix guards, API flows (auth, block/unblock, IPv6 routes, panic), Windows
  rules from fake netsh/PowerShell output.
- `python -m py_compile` clean; every page rendered and clicked in a real browser
  during development.

## 18. Known limits (stated, not hidden)

1. **A workstation is not a gateway.** Without running on the router/AP, a block
   cuts the victim's internet via ARP (IPv4) and filters traffic to this host;
   LAN-to-LAN traffic between other hosts is unaffected, and IPv6 needs the rules
   above rather than ARP.
2. **IPv6 prefix blocking is a /64 weapon.** It covers rotation, but every host in
   that prefix loses IPv6 reachability.
3. **SLAAC addresses not yet seen** are only covered by the MAC rule (where this
   host sees the traffic) or by the prefix option.
4. **ARP interception cannot cross a switch.** It works because the victim's
   gateway entry is poisoned; it does not make this host see unrelated traffic.
5. **No TLS and no user accounts.** The token protects a loopback API; exposing
   it needs a reverse proxy with real auth.
6. **Monitoring/in-path capture exists as a module but has no HTTP surface** in
   this build.
7. **Windows cannot match MAC in the firewall**; reliability depends on
   Npcap/scapy being installed and the ARP layer starting, otherwise the block is
   refused rather than half-applied.
8. **Deauth needs AP control or a monitor-mode adapter** — hardware, not a flag.
