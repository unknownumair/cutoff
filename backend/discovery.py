"""LAN host discovery: ARP sweep (root) with an unprivileged ping fallback."""
from __future__ import annotations

import ipaddress
import logging
import platform
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
import fingerprint
import ipv6
import platform_ops
import netinfo
import nmapscan
from netinfo import neighbour_table
from oui import vendor_for

log = logging.getLogger("cutoff.discovery")

ETH_P_ARP = 0x0806
BROADCAST = b"\xff" * 6
OUI_OVERRIDE = config.DATA_DIR / "oui.csv"


class DiscoveryError(RuntimeError):
    pass


def _arp_request(src_mac: bytes, src_ip: str, dst_ip: str) -> bytes:
    eth = struct.pack("!6s6sH", BROADCAST, src_mac, ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, 1,                      # Ethernet/IPv4, request
        src_mac, socket.inet_aton(src_ip),
        b"\x00" * 6, socket.inet_aton(dst_ip),
    )
    return eth + arp


def arp_sweep(iface: str, src_ip: str, network: ipaddress.IPv4Network,
              timeout: float = 2.5) -> dict[str, str]:
    """Broadcast ARP requests and collect replies. Requires CAP_NET_RAW."""
    if platform_ops.IS_WINDOWS:
        try:
            from scapy.all import ARP, Ether, conf, srp  # type: ignore
        except ImportError as exc:
            raise DiscoveryError(
                "scapy/Npcap missing — run the Windows setup (run.bat) once"
            ) from exc
        iface_arg = iface
        try:
            iface_arg = conf.ifaces.dev_from_name(iface)
        except Exception:  # noqa: BLE001 - friendly name may not map on old scapy
            pass
        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                iface=iface_arg, timeout=timeout, verbose=0,
            )
        except Exception as exc:  # noqa: BLE001 - Npcap/driver errors vary
            raise DiscoveryError(f"ARP sweep failed: {exc}") from exc
        return {rcv.psrc: rcv.hwsrc.lower() for _, rcv in answered}
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    except PermissionError as exc:
        raise DiscoveryError(
            "ARP sweep needs root (raw socket denied). Run with sudo, or use the "
            "unprivileged ping fallback."
        ) from exc
    sock.bind((iface, ETH_P_ARP))
    found: dict[str, str] = {}
    try:
        src_hw = bytes.fromhex(
            open(f"/sys/class/net/{iface}/address", encoding="utf-8").read().strip().replace(":", "")
        )
        hosts = [str(h) for h in network.hosts() if str(h) != src_ip][: config.SCAN_MAX_HOSTS]
        for host in hosts:
            try:
                sock.send(_arp_request(src_hw, src_ip, host))
            except OSError:
                continue
        deadline = time.monotonic() + timeout
        sock.settimeout(0.15)
        while time.monotonic() < deadline:
            try:
                frame = sock.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(frame) < 42:
                continue
            eth_type = struct.unpack("!H", frame[12:14])[0]
            if eth_type != ETH_P_ARP:
                continue
            oper = struct.unpack("!H", frame[20:22])[0]
            if oper != 2:  # reply only
                continue
            sha = frame[22:28]
            spa = socket.inet_ntoa(frame[28:32])
            found[spa] = ":".join(f"{b:02x}" for b in sha)
    finally:
        sock.close()
    return found


def _ping(ip: str) -> bool:
    if platform_ops.IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-n", "-q", "-c", "1", "-W", "1", ip]
    kwargs: dict = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                    "timeout": 3}
    if platform_ops.IS_WINDOWS:
        kwargs["creationflags"] = platform_ops.CREATE_NO_WINDOW
    cp = subprocess.run(cmd, **kwargs)
    return cp.returncode == 0


def ping_sweep(hosts: list[str]) -> list[str]:
    """Unprivileged fallback: ICMP each host, keep the responders."""
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=config.SCAN_CONCURRENCY) as pool:
        futures = {pool.submit(_ping, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            try:
                if fut.result():
                    alive.append(futures[fut])
            except (subprocess.SubprocessError, OSError):
                continue
    return alive


def _has_ping() -> bool:
    import shutil

    return bool(shutil.which("ping"))


def resolve_hostnames(ips: list[str], workers: int = 32) -> dict[str, str]:
    """Reverse-DNS with a bounded wait; failures are silent."""
    out: dict[str, str] = {}

    def one(ip: str) -> tuple[str, str]:
        try:
            name = socket.gethostbyaddr(ip)[0]
            short = name.split(".")[0] if name else ""
            # systemd-resolved answers "_gateway" for the router; not a device name.
            if not short or short.startswith("_") or short.lower() == "localhost":
                return ip, ""
            return ip, short
        except (OSError, socket.herror):
            return ip, ""

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, name in pool.map(one, ips):
            if name:
                out[ip] = name
    return out


def self_device(iface: str, ip: str) -> dict | None:
    """The host running CUTOFF, included in the inventory like any other device."""
    mac = netinfo.iface_mac(iface)
    if not mac:
        return None
    hostname = socket.gethostname() or "this-host"
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor_for(mac, OUI_OVERRIDE),
        "hostname": hostname,
        "model": platform.machine(),
        "manufacturer": platform.system(),
        "os": platform.platform(),
        "device_type": "workstation",
        "is_self": True,
        "sources": ["self"],
        "info": {
            "self": {
                "hostname": hostname,
                "platform": platform.platform(),
                "kernel": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "addresses": sorted(netinfo.local_ipv4s()),
            }
        },
    }


def apply_nmap(devices: list[dict], hosts: dict[str, dict]) -> None:
    """Merge nmap host records into the inventoried devices (in place)."""
    import re

    by_ip = {dev.get("ip"): dev for dev in devices}
    for ip, host in hosts.items():
        dev = by_ip.get(ip)
        if dev is None:
            continue
        names = [n for n in host.get("hostnames", []) if n and not n.startswith("_")]
        if names:
            dev["hostname"] = dev.get("hostname") or names[0]
        if host.get("mac") and not dev.get("mac"):
            dev["mac"] = host["mac"]
        if host.get("ports"):
            dev["ports"] = host["ports"]
            dev["services"] = host.get("services", [])
        if host.get("os"):
            dev["os"] = host["os"][0].get("name", "") or dev.get("os", "")
        scripts = host.get("scripts", {})
        info = dev.setdefault("info", {})
        info["nmap"] = {"scripts": scripts, "os": host.get("os", []),
                        "ports": host.get("ports", [])}
        netbios = re.search(r"NetBIOS name: ([^,\s]+)", scripts.get("nbstat", ""))
        if netbios and not dev.get("hostname"):
            dev["hostname"] = netbios.group(1)
        cert = re.search(r"commonName=([^/\n]+)", scripts.get("ssl-cert", ""))
        if cert:
            common_name = cert.group(1).strip()
            info.setdefault("tls", {})["cn"] = common_name
            first_word = re.split(r"[\s,]+", common_name)[0]
            if first_word and dev.get("vendor") in (None, "", "Unknown"):
                dev["vendor"] = first_word
            if common_name and not dev.get("manufacturer"):
                dev["manufacturer"] = common_name
        title = re.search(r"Title: (.+)", scripts.get("http-title", ""))
        if title:
            dev["title"] = title.group(1).strip()[:140]
        dev["sources"] = sorted(set(dev.get("sources", [])) | {"nmap"})
        dev["device_type"] = fingerprint.classify(dev)


def scan(iface: str, ip: str, prefix: int, timeout: float = 2.5,
         deep: bool = False, progress=None) -> dict:
    """Discover active devices and fingerprint them.

    ``deep`` adds an nmap service/OS/NSE pass. ``progress`` is called with
    phase names so the UI can show what is happening.
    """
    def report(phase: str) -> None:
        if progress:
            try:
                progress(phase)
            except Exception:  # noqa: BLE001 - progress must never break a scan
                pass

    started = time.monotonic()
    network = ipaddress.ip_interface(f"{ip}/{prefix}").network
    if network.num_addresses - 2 > config.SCAN_MAX_HOSTS:
        raise DiscoveryError(
            f"network {network} is too large to sweep safely "
            f"({network.num_addresses - 2} hosts > {config.SCAN_MAX_HOSTS}); "
            "set CUTOFF_SCAN_MAX_HOSTS to override"
        )
    hosts = [str(h) for h in network.hosts() if str(h) != ip]
    warnings: list[str] = []
    method = "arp"
    report("discovering")
    try:
        table = arp_sweep(iface, ip, network, timeout=timeout)
    except DiscoveryError as exc:
        warnings.append(str(exc))
        method = "ping"
        if _has_ping():
            ping_sweep(hosts)
        else:
            warnings.append("ping not found; using the kernel neighbour table only")
        table = neighbour_table(iface)

    table.pop(ip, None)
    devices = [
        {"ip": host, "mac": mac, "vendor": vendor_for(mac, OUI_OVERRIDE),
         "sources": ["arp" if method == "arp" else "neigh"]}
        for host, mac in table.items()
        if mac
    ]
    names = resolve_hostnames([d["ip"] for d in devices])
    leases = netinfo.lease_hostnames()
    for dev in devices:
        host_name = names.get(dev["ip"]) or leases.get(dev["ip"], "")
        if host_name:
            dev["hostname"] = host_name
            dev.setdefault("names", {})["dns" if names.get(dev["ip"]) else "dhcp"] = host_name

    me = self_device(iface, ip)
    if me:
        devices.append(me)

    report("fingerprinting")
    fingerprint_stats: dict = {}
    try:
        fingerprint_stats = fingerprint.enrich(devices, timeout=min(2.5, max(1.0, timeout)))
    except Exception as exc:  # noqa: BLE001
        log.warning("fingerprinting failed: %s", exc)
        warnings.append(f"fingerprinting failed: {exc}")

    nmap_result: dict = {"available": bool(nmapscan.locate()), "ok": False,
                         "error": "", "hosts": 0}
    if deep:
        report("nmap")
        if not nmap_result["available"]:
            nmap_result["error"] = "nmap not installed"
            warnings.append("deep scan skipped: nmap not installed")
        else:
            result = nmapscan.scan([d["ip"] for d in devices if d.get("ip")])
            nmap_result.update({
                "ok": result.get("ok", False),
                "error": result.get("error", ""),
                "hosts": len(result.get("hosts", {})),
            })
            if result.get("ok"):
                apply_nmap(devices, result["hosts"])
                seen = {d["ip"] for d in devices}
                for extra_ip, extra_mac in neighbour_table(iface).items():
                    if extra_ip in seen or not extra_mac or extra_ip == ip:
                        continue
                    devices.append({
                        "ip": extra_ip, "mac": extra_mac,
                        "vendor": vendor_for(extra_mac, OUI_OVERRIDE),
                        "sources": ["nmap", "neigh"],
                    })
            elif result.get("error"):
                warnings.append(f"nmap: {result['error']}")

    for dev in devices:
        dev.setdefault("device_type", fingerprint.classify(dev))

    # IPv6 is a separate address space with its own neighbour cache; join it on
    # the MAC so the inventory carries both families for the same device.
    ipv6_stats: dict = {"devices_with_ipv6": 0, "addresses": 0, "neighbours": 0}
    try:
        ipv6_stats = ipv6.attach(devices, iface)
    except Exception as exc:  # noqa: BLE001 - never fail a scan over IPv6
        log.warning("ipv6 discovery failed: %s", exc)
        warnings.append(f"ipv6 discovery failed: {exc}")

    devices.sort(key=lambda d: (0 if d.get("is_self") else 1,
                                tuple(int(p) for p in d["ip"].split(".")) if d.get("ip") else (999,)))
    return {
        "devices": devices,
        "method": method,
        "warnings": warnings,
        "hosts_scanned": len(hosts),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "network": str(network),
        "deep": deep,
        "nmap": nmap_result,
        "fingerprint": fingerprint_stats,
        "ipv6": ipv6_stats,
    }

