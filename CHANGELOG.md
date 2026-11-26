# Changelog

All notable changes to CUTOFF. Format: [Keep a Changelog](https://keepachangelog.com/),
versioning: [SemVer](https://semver.org/).

## [1.3.0] — 2026-11-26

### Added
- **IPv6 layer-2 blocking (NDP black hole).** Forged Neighbor Advertisements
  claim the default router's link-local address to the victim, each victim
  address to the router, and (complete isolation) every known peer to both
  sides. Off-link IPv6 dies even when the device rotates its source address,
  because the poisoned entry is the router, not the address. Frames are
  checksum-correct NA/NS (next-header 58, hop limit 255, Override flag) and are
  primed with a solicitation first, since a host ignores an NA for a target it
  has never resolved. Refused when IPv6 forwarding is on without a verified
  `FORWARD` drop, and never applied to the router itself.
- **Live peer refresh while a block is active.** Every `CUTOFF_PEER_REFRESH`
  seconds (default 10) the poison loops re-read the peer set from the inventory
  plus the live IPv4/IPv6 neighbour tables, so devices that join or are scanned
  after the block are covered too. New pairs get a forged request frame first:
  a reply alone only updates a cache entry the target already has.
- Block dialog: “cut IPv6 at layer 2 (NDP)” toggle, checked by default whenever
  the device has an IPv6 address.
- Block responses carry `ndp` (router, targets, pair/peer counts); capabilities
  and status expose the NDP interceptors. `unblock` and `Restore all` stop them.

### Changed
- The block warnings now state what started instead of claiming IPv6 and later
  peers need gateway/AP enforcement: “IPv6 layer 2: NDP black-hole over N
  known address(es) + the default router… peer-to-peer v6 is best-effort.”

### Fixed
- `ip -6 route show default dev X` omits the `dev` group from its output, so
  the router link-local silently resolved to nothing and the v6 layer would
  never have started. The parser now treats the device group as optional.
- NDP is skipped (with a warning) when the victim is the IPv6 default router,
  instead of sending the router advertisements about itself.

## [1.2.0] — 2026-11-18

### Added
- **Global install + `cutoff` command.** `tools/install-global.sh` copies the
  app to `/opt/cutoff`, builds its venv, puts the inventory in `/var/lib/cutoff`
  (0700, token 0600) and writes a hardened systemd unit. The `cutoff` CLI
  controls it: `cutoff [start]`, `serve`, `stop`, `restart`, `status`, `logs`,
  `url`, `token`, `doctor`, `update`, `uninstall`, `version`.
- **First-run auto-install.** `./run.sh` installs to `/opt/cutoff` the first
  time it runs, then serves the installed copy. `CUTOFF_NO_INSTALL=1` keeps the
  old checkout-local behaviour for development.
- **Windows global install.** `tools/install-global.bat` copies to
  `%ProgramData%\CUTOFF`, builds the venv, writes `cutoff.cmd`/`cutoff-doctor.cmd`
  and appends the bin dir to the machine PATH; `run.bat` calls it on first run.
- **Off-white light theme + persisted toggle** across all five pages, with an
  OS-preference default and a no-flash bootstrap.
- **Responsive shell:** glass sidebar above 1080px, wrapping bar with a
  scrollable nav below it, uniform 3/2/1-column footer pinned to the page bottom.
- **Merged IPv4+IPv6 blocks** from the Devices page, including optional `/64`
  coverage for SLAAC rotation and NDP-cache fallback when the inventory is stale.
- `/ipv6` console: addresses, prefixes, NDP neighbours, prefix blocks, live rules.
- `VERSION` file as the single source of truth (`config.VERSION`).

### Changed
- Project renamed from N-PENT to CUTOFF (chains `CUTOFF_BLOCK`/`CUTOFF_OUT`,
  rule tags `CUTOFF:`, Windows rules `CUTOFF-*`, env prefix `CUTOFF_*`).
  Legacy `NPENT:` tags, chains, firewall rules and `NPENT_*` env vars are still
  parsed and cleaned up, so upgrades leave no orphans.
- Footer copy is now “Builded for Community by 111”.
- `cutoff.log` replaces `npent.log`; the data dir is created 0700 and sensitive
  files are forced to 0600 at startup.

### Fixed
- `ip -6 neigh` output without the `dev <iface>` part no longer yields an empty
  neighbour table.
- ip6tables rejects MAC rules in a chain reachable from OUTPUT — split into
  `CUTOFF_BLOCK` (INPUT/FORWARD) and `CUTOFF_OUT` (OUTPUT, L3 only).
- Stopping an nmap run reported `nmap exited -15` and logged a bogus XML parse
  warning; it now reports “scan stopped by user”, waits for the worker to settle
  and skips parsing the truncated file.
- `/api/status` no longer shells out to `ip(6)tables -S` on every poll — rule
  listings are cached for 2.5 s and invalidated on every mutation.
- `netinfo.iface_mac` leaked a file handle (ResourceWarning on every call).
- `nmapscan` no longer triggers a DeprecationWarning on a truth-tested Element.
- Table action rail no longer clips at the panel edge; empty table rows are
  centred instead of inheriting the right-aligned action column.
- Small text failed AA on the panel fill (3.39:1) — secondary tokens now measure
  ≥5.36:1 in both themes.

## [1.1.0] — 2026-11-14
### Added
- IPv6 enforcement: MAC rules, per-address rules, prefix blocks, `/ipv6` console,
  guard rails (no own-prefix, no `/0`, no `/128`), NDP inventory join.
- waitress, hardened systemd unit, backup script, log rotation, data-dir
  permissions, pinned `requirements.lock`, doctor IPv6 checks.

## [1.0.0] — 2026-10-31
- Initial release: discovery, fingerprinting, IPv4 enforcement, ARP black hole,
  Wi-Fi deauth where supported, bundled nmap/bettercap consoles, network map,
  token-gated API, simulation mode.
