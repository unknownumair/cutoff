"""Interface, route and neighbour-table helpers (no third-party deps)."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
from dataclasses import dataclass, asdict

import platform_ops


def run(cmd: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    return platform_ops.run(cmd, timeout=timeout)


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _win_json(script: str, timeout: float = 12.0):
    rc, out, _ = platform_ops.powershell(script, timeout=timeout)
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out.lstrip("\ufeff"))
    except ValueError:
        return None


@dataclass
class Interface:
    name: str
    ip: str
    prefix: int
    mac: str
    gateway: str | None
    gateway_mac: str | None
    wireless: bool

    @property
    def network(self) -> str:
        return str(ipaddress.ip_interface(f"{self.ip}/{self.prefix}").network)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["network"] = self.network
        return d


def default_route() -> tuple[str | None, str | None]:
    """Return (iface, gateway) for the default IPv4 route."""
    if platform_ops.IS_WINDOWS:
        rc, out, _ = platform_ops.powershell(
            "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
            "-ErrorAction SilentlyContinue | Sort-Object RouteMetric | "
            "Select-Object -First 1; if ($r) { "
            "\"$($r.InterfaceAlias)|$($r.NextHop)\" }")
        if rc == 0 and "|" in out:
            name, gw = out.split("|", 1)
            return name.strip(), gw.strip() or None
        return None, None
    rc, out, _ = run(["ip", "-4", "route", "show", "default"])
    if rc == 0:
        m = re.search(r"default via (\S+) dev (\S+)", out)
        if m:
            return m.group(2), m.group(1)
    # fallback: /proc/net/route (hex, little endian)
    try:
        with open("/proc/net/route", encoding="utf-8") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    gw = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
                    return parts[0], gw
    except OSError:
        pass
    return None, None


def iface_ipv4(name: str) -> tuple[str | None, int]:
    if platform_ops.IS_WINDOWS:
        rc, out, _ = platform_ops.powershell(
            f"$a = Get-NetIPAddress -InterfaceAlias {_ps_quote(name)} "
            "-AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object {$_.PrefixOrigin -ne 'WellKnown'} | Select-Object -First 1; "
            "if ($a) { \"$($a.IPAddress)|$($a.PrefixLength)\" }")
        if rc == 0 and "|" in out:
            ip, prefix = out.split("|", 1)
            try:
                return ip.strip(), int(prefix.strip())
            except ValueError:
                return ip.strip(), 24
        return None, 0
    rc, out, _ = run(["ip", "-4", "-o", "addr", "show", "dev", name])
    if rc == 0:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if m:
            return m.group(1), int(m.group(2))
    return None, 0


def iface_mac(name: str) -> str | None:
    if platform_ops.IS_WINDOWS:
        rc, out, _ = platform_ops.powershell(
            f"(Get-NetAdapter -Name {_ps_quote(name)} -ErrorAction SilentlyContinue).MacAddress")
        return out.strip().lower().replace("-", ":") or None
    try:
        with open(f"/sys/class/net/{name}/address", encoding="utf-8") as fh:
            mac = fh.read().strip()
        return mac if mac and mac != "00:00:00:00:00:00" else None
    except OSError:
        return None


def is_wireless(name: str) -> bool:
    if platform_ops.IS_WINDOWS:
        rc, out, _ = platform_ops.powershell(
            f"(Get-NetAdapter -Name {_ps_quote(name)} -ErrorAction SilentlyContinue)"
            ".PhysicalMediaType")
        return "802.11" in out or "wireless" in out.lower()
    import os

    return os.path.isdir(f"/sys/class/net/{name}/wireless") or os.path.exists(
        f"/sys/class/net/{name}/phy80211"
    )


def local_macs() -> dict[str, str]:
    """mac -> interface for every interface on this host."""
    out: dict[str, str] = {}
    if platform_ops.IS_WINDOWS:
        data = _win_json("Get-NetAdapter | Where-Object {$_.MacAddress} | "
                         "Select-Object Name,MacAddress | ConvertTo-Json -Compress")
        for row in (data if isinstance(data, list) else [data] if data else []):
            mac = (row.get("MacAddress") or "").lower().replace("-", ":")
            if mac and mac != "00:00:00:00:00:00":
                out[mac] = row.get("Name") or ""
        return out
    rc, ifaces, _ = run(["ip", "-o", "link", "show"])
    if rc != 0:
        return out
    for line in ifaces.splitlines():
        m = re.match(r"\d+:\s+([^:@]+)[:@]", line)
        if not m:
            continue
        name = m.group(1)
        mac = iface_mac(name)
        if mac:
            out[mac.lower()] = name
    return out


def local_ipv4s() -> set[str]:
    """Every IPv4 address configured on this host."""
    if platform_ops.IS_WINDOWS:
        data = _win_json("Get-NetIPAddress -AddressFamily IPv4 | "
                         "Select-Object -ExpandProperty IPAddress | ConvertTo-Json -Compress")
        if isinstance(data, str):
            return {data}
        return set(data or [])
    rc, out, _ = run(["ip", "-4", "-o", "addr", "show"])
    if rc != 0:
        return set()
    return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out))


def neighbour(iface: str, ip: str) -> str | None:
    if platform_ops.IS_WINDOWS:
        return neighbour_table(iface).get(ip)
    rc, out, _ = run(["ip", "neigh", "show", "dev", iface, "to", ip])
    if rc == 0:
        m = re.search(r"lladdr ([0-9a-f:]{17})", out, re.I)
        if m:
            return m.group(1).lower()
    # /proc/net/arp fallback
    try:
        with open("/proc/net/arp", encoding="utf-8") as fh:
            for line in fh.readlines()[1:]:
                p = line.split()
                if len(p) >= 4 and p[0] == ip and p[3] != "00:00:00:00:00:00":
                    return p[3].lower()
    except OSError:
        pass
    return None


def neighbour_table(iface: str) -> dict[str, str]:
    """ip -> mac from the kernel neighbour table."""
    table: dict[str, str] = {}
    if platform_ops.IS_WINDOWS:
        scope = f"-InterfaceAlias {_ps_quote(iface)} " if iface else ""
        data = _win_json(
            f"Get-NetNeighbor {scope}-AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object {$_.LinkLayerAddress -and "
            "$_.LinkLayerAddress -ne '00-00-00-00-00-00'} | "
            "Select-Object IPAddress,LinkLayerAddress | ConvertTo-Json -Compress")
        for row in (data if isinstance(data, list) else [data] if data else []):
            ip = row.get("IPAddress") or ""
            mac = (row.get("LinkLayerAddress") or "").lower().replace("-", ":")
            if re.match(r"\d+\.\d+\.\d+\.\d+$", ip) and re.match(
                    r"([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                table[ip] = mac
        return table
    rc, out, _ = run(["ip", "-4", "neigh", "show", "dev", iface])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            m = re.search(r"lladdr ([0-9a-f:]{17})", line, re.I)
            if m and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                table[parts[0]] = m.group(1).lower()
    if not table:
        try:
            with open("/proc/net/arp", encoding="utf-8") as fh:
                for line in fh.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                        table[p[0]] = p[3].lower()
        except OSError:
            pass
    return table


def current_interface() -> Interface | None:
    name, gw = default_route()
    if not name:
        return None
    ip, prefix = iface_ipv4(name)
    if not ip:
        return None
    return Interface(
        name=name,
        ip=ip,
        prefix=prefix,
        mac=iface_mac(name) or "",
        gateway=gw,
        gateway_mac=neighbour(name, gw) if gw else None,
        wireless=is_wireless(name),
    )


LEASE_GLOBS = (
    "/var/lib/dnsmasq/dnsmasq.leases",
    "/var/lib/NetworkManager/dnsmasq-*.leases",
    "/var/lib/misc/dnsmasq.leases",
    "/tmp/dhcp.leases",
)


def lease_hostnames() -> dict[str, str]:
    """ip -> hostname from local DHCP leases, when readable."""
    if platform_ops.IS_WINDOWS:
        return {}
    import glob

    names: dict[str, str] = {}
    for pattern in LEASE_GLOBS:
        for path in glob.glob(pattern):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        parts = line.split()
                        if len(parts) >= 4 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[2]):
                            host = parts[3]
                            if host and host != "*":
                                names[parts[2]] = host
            except OSError:
                continue
    return names
