"""IPv6 inventory: addresses, neighbours, prefixes and NDP state.

Read-only by design. Everything that changes the kernel lives in
:mod:`firewall`; this module answers one question — *what IPv6 exists on this
link, and which MAC owns it* — so discovery, the enforcer and the `/ipv6` page
all read the same facts.

Parsing is split from execution (``parse_*`` functions take raw text) so the
whole module is unit-testable without root.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket

import netinfo
import platform_ops

log = logging.getLogger("cutoff.ipv6")

# Any IPv6 address inside these ranges is not a host we can meaningfully block.
_ULA = ipaddress.ip_network("fc00::/7")
_LINK_LOCAL = ipaddress.ip_network("fe80::/10")
_DOC = ipaddress.ip_network("2001:db8::/32")
SCOPES = ("global", "ula", "link-local", "loopback", "multicast", "unspecified")
MAX_ADDRS_PER_DEVICE = 8


# ---------------------------------------------------------------------------
# classification / validation
# ---------------------------------------------------------------------------
def classify(addr: str) -> str:
    """Display scope for an IPv6 address: global / ula / link-local / ..."""
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return "invalid"
    if ip.version != 6:
        return "ipv4"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    if ip in _ULA:
        return "ula"
    return "global"


def normalize(addr: str) -> str:
    """Canonical form without a zone id; raises ValueError on junk."""
    return str(ipaddress.ip_address((addr or "").strip().split("%", 1)[0]))


def is_host(addr: str) -> bool:
    """True for an address we could actually put in a rule."""
    try:
        ip = ipaddress.ip_address((addr or "").strip().split("%", 1)[0])
    except ValueError:
        return False
    if ip.version != 6:
        return False
    return not (ip.is_multicast or ip.is_unspecified or ip.is_loopback)


def valid_prefix(text: str) -> ipaddress.IPv6Network:
    """Parse and validate a prefix we are willing to block.

    Refuses anything wider than /16, which is not a LAN and would take the
    link (or the internet) down rather than a device.
    """
    try:
        net = ipaddress.ip_network((text or "").strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid IPv6 prefix: {text!r}") from exc
    if net.version != 6:
        raise ValueError("prefix must be IPv6 (use the IPv4 block for v4 ranges)")
    if net.prefixlen < 16:
        raise ValueError("refusing to block a prefix wider than /16 — scope the rule to the LAN")
    if net.prefixlen == 128:
        raise ValueError("a /128 is a single address — block the device instead")
    return net


def prefix_for(addr: str, prefixlen: int = 64) -> str | None:
    """Enclosing /64 (or given length) for an address."""
    try:
        net = ipaddress.ip_network(f"{normalize(addr)}/{prefixlen}", strict=False)
    except ValueError:
        return None
    return str(net)


# ---------------------------------------------------------------------------
# parsing (pure, unit-testable)
# ---------------------------------------------------------------------------
_ADDR_RE = re.compile(r"^\s*inet6\s+([0-9a-fA-F:]+)/(\d+)\s+scope\s+(\w+)\s*(.*)$")
_LIFE_RE = re.compile(r"valid_lft\s+(\S+)\s+preferred_lft\s+(\S+)")
# `ip -6 neigh show dev X` omits the "dev X" part in its output, so it has to
# be optional or every neighbour is silently dropped.
_NEIGH_RE = re.compile(
    r"^(\S+)\s+(?:dev\s+(\S+)\s+)?(?:lladdr\s+([0-9a-fA-F:]{17}))?(.*)$")


def parse_addresses(text: str) -> list[dict]:
    """Parse ``ip -6 addr show dev X`` into address records."""
    out: list[dict] = []
    current: dict | None = None
    for line in (text or "").splitlines():
        match = _ADDR_RE.match(line)
        if match:
            addr, plen, scope, rest = match.groups()
            flags = rest.split()
            try:
                net = str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))
            except ValueError:
                net = ""
            current = {
                "address": str(ipaddress.ip_address(addr)),
                "prefix": int(plen),
                "scope": scope,
                "class": classify(addr),
                "network": net,
                "dynamic": "dynamic" in flags,
                "temporary": "temporary" in flags,
                "deprecated": "deprecated" in flags,
                "valid_lft": "",
                "preferred_lft": "",
            }
            out.append(current)
            continue
        life = _LIFE_RE.search(line or "")
        if life and current is not None:
            current["valid_lft"] = life.group(1)
            current["preferred_lft"] = life.group(2)
            if life.group(2).startswith("0"):
                current["deprecated"] = True
    return out


def parse_neighbours(text: str) -> list[dict]:
    """Parse ``ip -6 neigh show`` into neighbour records (MAC optional)."""
    out: list[dict] = []
    for line in (text or "").splitlines():
        match = _NEIGH_RE.match(line.strip())
        if not match:
            continue
        addr, dev, mac, rest = match.groups()
        dev = dev or ""
        if not is_host(addr):
            continue
        flags = rest.split()
        state = next((f for f in flags if f.isupper()), "UNKNOWN")
        if state == "FAILED":
            # No lladdr means the kernel could not resolve it: nothing to block.
            continue
        out.append({
            "ip": normalize(addr),
            "mac": (mac or "").lower(),
            "iface": dev,
            "state": state,
            "router": "router" in flags,
            "class": classify(addr),
        })
    return out


# ---------------------------------------------------------------------------
# live probes
# ---------------------------------------------------------------------------
def _run(cmd: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    return netinfo.run(cmd, timeout=timeout)


def supported() -> bool:
    """Is IPv6 on this host at all?"""
    if platform_ops.IS_WINDOWS:
        return True
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
        return True
    except OSError:
        return False


def local_addresses(iface: str) -> list[dict]:
    """Every IPv6 address on the interface, loopback included."""
    if not iface:
        return []
    if platform_ops.IS_WINDOWS:
        data = netinfo._win_json(  # noqa: SLF001 - shared powershell helper
            f"Get-NetIPAddress -AddressFamily IPv6 -InterfaceAlias {netinfo._ps_quote(iface)} "  # noqa: SLF001
            "-ErrorAction SilentlyContinue | Select-Object IPAddress,PrefixLength | "
            "ConvertTo-Json -Compress")
        rows = data if isinstance(data, list) else [data] if data else []
        out = []
        for row in rows:
            addr = str(row.get("IPAddress") or "")
            if not addr:
                continue
            plen = int(row.get("PrefixLength") or 64)
            out.append({"address": addr, "prefix": plen, "scope": classify(addr),
                        "class": classify(addr),
                        "network": prefix_for(addr, plen) or "", "dynamic": True,
                        "temporary": False, "deprecated": False,
                        "valid_lft": "", "preferred_lft": ""})
        return out
    rc, out, _ = _run(["ip", "-6", "addr", "show", "dev", iface])
    return parse_addresses(out) if rc == 0 else []


def neighbours(iface: str) -> list[dict]:
    """NDP cache for the interface: IPv6 address -> MAC."""
    if platform_ops.IS_WINDOWS:
        scope = f"-InterfaceAlias {netinfo._ps_quote(iface)} " if iface else ""  # noqa: SLF001
        data = netinfo._win_json(  # noqa: SLF001
            f"Get-NetNeighbor {scope}-AddressFamily IPv6 -ErrorAction SilentlyContinue | "
            "Where-Object {$_.LinkLayerAddress} | Select-Object IPAddress,LinkLayerAddress,State | "
            "ConvertTo-Json -Compress")
        rows = data if isinstance(data, list) else [data] if data else []
        out = []
        for row in rows:
            addr = str(row.get("IPAddress") or "")
            if not is_host(addr):
                continue
            mac = (row.get("LinkLayerAddress") or "").lower().replace("-", ":")
            out.append({"ip": normalize(addr), "mac": mac, "iface": iface,
                        "state": str(row.get("State") or "UNKNOWN").upper(),
                        "router": False, "class": classify(addr)})
        return out
    cmd = ["ip", "-6", "neigh", "show"] + (["dev", iface] if iface else [])
    rc, out, _ = _run(cmd)
    if rc != 0:
        return []
    records = parse_neighbours(out)
    for record in records:
        record["iface"] = record.get("iface") or iface
    return records


def _read_sysctl(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


def forwarding() -> bool:
    value = _read_sysctl("/proc/sys/net/ipv6/conf/all/forwarding")
    return value == "1"


def accept_ra(iface: str) -> int | None:
    if not iface:
        return None
    value = _read_sysctl(f"/proc/sys/net/ipv6/conf/{iface}/accept_ra")
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _enabled(iface: str) -> bool:
    if platform_ops.IS_WINDOWS:
        return True
    value = _read_sysctl(f"/proc/sys/net/ipv6/conf/{iface}/disable_ipv6") if iface else None
    return value != "1"


def status(iface: str) -> dict:
    """One snapshot for the UI: addresses, prefixes, neighbours, link state."""
    addrs = local_addresses(iface)
    neigh = neighbours(iface)
    prefixes: list[str] = []
    for record in addrs:
        net = record.get("network") or ""
        if not net or net in prefixes:
            continue
        if record["class"] in ("global", "ula"):
            prefixes.append(net)
    own = [a["address"] for a in addrs]
    hosts_by_prefix: dict[str, int] = {}
    for record in neigh:
        net = prefix_for(record["ip"]) or ""
        if net:
            hosts_by_prefix[net] = hosts_by_prefix.get(net, 0) + 1
    return {
        "supported": supported(),
        "enabled": _enabled(iface) if iface else False,
        "interface": iface,
        "addresses": addrs,
        "own_addresses": own,
        "prefixes": sorted(prefixes),
        "neighbours": sorted(neigh, key=lambda n: (n["class"] != "global", n["ip"])),
        "guest_prefixes": hosts_by_prefix,
        # Prefixes that contain one of our own addresses: blocking those cuts
        # the console off the link, so the UI disables the action.
        "own_prefixes": sorted({a.get("network") or "" for a in addrs if a.get("network")}),
        "forwarding": forwarding(),
        "accept_ra": accept_ra(iface),
        "has_global": any(a["class"] == "global" for a in addrs),
        "has_link_local": any(a["class"] == "link-local" for a in addrs),
        "note": (
            "this link has no global IPv6 address — peers can still use link-local, "
            "but nothing routes off-link"
            if not any(a["class"] == "global" for a in addrs) else ""
        ),
    }


# ---------------------------------------------------------------------------
# inventory merge
# ---------------------------------------------------------------------------
def attach(devices: list[dict], iface: str) -> dict:
    """Attach ``ip6`` address lists to inventory devices, joined by MAC.

    The NDP cache is the only mapping from IPv6 to hardware address; devices
    that never used IPv6 simply keep an empty list. Link-local addresses are
    kept because that is what a v6-only peer actually talks over on the LAN.
    """
    by_mac: dict[str, list[dict]] = {}
    for record in neighbours(iface):
        mac = record.get("mac") or ""
        if not mac:
            continue
        by_mac.setdefault(mac, []).append(record)

    own = local_addresses(iface)
    attached = 0
    addresses = 0
    for device in devices:
        mac = (device.get("mac") or "").lower()
        records = own if device.get("is_self") else by_mac.get(mac, [])
        seen: list[str] = []
        for record in records:
            addr = record.get("address") or record.get("ip") or ""
            if not addr or addr in seen:
                continue
            seen.append(addr)
        # Global/ULA first: those are the addresses that route off-link.
        seen.sort(key=lambda a: (classify(a) != "global", classify(a) != "ula", a))
        # Always set the key — an address that rotated away must not survive in
        # the inventory as a blockable value.
        device["ip6"] = seen[:MAX_ADDRS_PER_DEVICE]
        if seen:
            device["ip6_scopes"] = sorted({classify(a) for a in seen})
            attached += 1
            addresses += len(device["ip6"])
    return {"devices_with_ipv6": attached, "addresses": addresses,
            "neighbours": len(by_mac)}
