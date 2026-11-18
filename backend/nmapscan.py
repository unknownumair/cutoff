"""Nmap adapter.

CUTOFF prefers a local, unprivileged nmap build under ``vendor/nmap`` (an RPM
extracted without installing anything), then ``CUTOFF_NMAP``, then ``$PATH``.
Unprivileged runs use TCP connect scans; root enables SYN + OS detection.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

import platform_ops

log = logging.getLogger("cutoff.nmap")

PROJECT = Path(__file__).resolve().parent.parent
VENDOR_BIN = PROJECT / "vendor" / "nmap" / "usr" / "bin" / "nmap"
VENDOR_DATA = PROJECT / "vendor" / "nmap" / "usr" / "share" / "nmap"
WIN_VENDOR = PROJECT / "vendor" / "nmap" / "win32"
_WIN_BIN: str | None = None

DEFAULT_SCRIPTS = "nbstat,http-title,ssl-cert,smb-os-discovery,upnp-info,snmp-sysdescr"


def _win_binary() -> str | None:
    global _WIN_BIN
    if _WIN_BIN is not None:
        return _WIN_BIN
    found = next(WIN_VENDOR.rglob("nmap.exe"), None) if WIN_VENDOR.is_dir() else None
    _WIN_BIN = str(found) if found else ""
    return _WIN_BIN or None


def locate() -> str | None:
    candidates = [
        os.environ.get("CUTOFF_NMAP"),
        _win_binary() if platform_ops.IS_WINDOWS else None,
        str(VENDOR_BIN) if VENDOR_BIN.is_file() else None,
        shutil.which("nmap"),
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
    ]
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file():
            continue
        if platform_ops.IS_WINDOWS or os.access(candidate, os.X_OK):
            return candidate
    return None


def data_dir() -> str | None:
    if platform_ops.IS_WINDOWS:
        binary = locate()
        if binary:
            folder = Path(binary).parent
            if (folder / "nmap-service-probes").is_file():
                return str(folder)
    if VENDOR_DATA.is_dir():
        return str(VENDOR_DATA)
    for candidate in ("/usr/share/nmap", "/usr/local/share/nmap"):
        if Path(candidate).is_dir():
            return candidate
    return None


@lru_cache(maxsize=1)
def version() -> str:
    binary = locate()
    if not binary:
        return ""
    try:
        cp = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10)
        first = (cp.stdout or cp.stderr).splitlines()
        return first[0].strip() if first else ""
    except (OSError, subprocess.SubprocessError):
        return ""


@lru_cache(maxsize=1)
def capabilities() -> dict:
    binary = locate()
    return {
        "available": bool(binary),
        "path": binary or "",
        "version": version() if binary else "",
        "datadir": data_dir() or "",
        "privileged": platform_ops.is_admin(),
        "note": "" if binary else "nmap not found; run run.bat / tools/install-nmap-rpm.sh",
    }


def _parse_scripts(node: ET.Element) -> dict[str, str]:
    out: dict[str, str] = {}
    for script in node.findall("script"):
        sid = script.get("id") or "script"
        out[sid] = (script.get("output") or "").strip()
    return out


def parse_xml(xml_text: str) -> dict[str, dict]:
    """Parse ``nmap -oX -`` output into {ip: info}."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        log.warning("cannot parse nmap XML: %s", exc)
        return {}
    hosts: dict[str, dict] = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        status_reason = status.get("reason", "") if status is not None else ""
        addrs = {a.get("addrtype"): a.get("addr") for a in host.findall("address")}
        ip = addrs.get("ipv4") or addrs.get("ipv6")
        if not ip:
            continue
        hostnames = [
            h.get("name") for h in host.findall("hostnames/hostname")
            if h.get("name") and not h.get("name", "").startswith("_")
        ]
        ports: list[dict] = []
        port_states: list[str] = []
        port_scripts: dict[str, str] = {}
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None:
                port_states.append(state.get("state", ""))
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            entry = {
                "port": int(port.get("portid", 0)),
                "proto": port.get("protocol", "tcp"),
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "extrainfo": service.get("extrainfo", "") if service is not None else "",
            }
            if service is not None:
                entry_scripts = _parse_scripts(port)
                if entry_scripts:
                    entry["scripts"] = entry_scripts
                    port_scripts.update(entry_scripts)
            ports.append(entry)
        os_matches = [
            {"name": m.get("name", ""), "accuracy": int(m.get("accuracy", 0) or 0)}
            for m in host.findall("os/osmatch")
        ][:3]
        extra_states = [e.get("state", "") for e in host.findall("ports/extraports")]
        responsive = (bool(ports) or "closed" in port_states
                      or "closed" in extra_states
                      or status_reason not in ("user-set", "localhost-response", "unknown", ""))
        info = {
            "ip": ip,
            "mac": addrs.get("mac", ""),
            "hostnames": hostnames,
            "status_reason": status_reason,
            "responsive": responsive,
            "ports": ports,
            "services": sorted({p["service"] for p in ports if p["service"]}),
            "os": os_matches,
            "scripts": {
                **port_scripts,
                **_parse_scripts(host.find("hostscript") if host.find("hostscript") is not None
                                 else ET.Element("hostscript")),
            },
        }
        hosts[ip] = info
    return hosts


def scan(ips: list[str], top_ports: int = 100, timeout: int = 240,
         scripts: str | None = DEFAULT_SCRIPTS) -> dict:
    """Run nmap against explicit hosts. Returns {ok, hosts, error, command}."""
    binary = locate()
    if not binary:
        return {"ok": False, "hosts": {}, "error": "nmap not installed"}
    if not ips:
        return {"ok": True, "hosts": {}, "error": ""}
    raw_ok = platform_ops.is_admin() and platform_ops.npcap_installed()
    if platform_ops.IS_WINDOWS and not raw_ok:
        raw_ok = False
    args = [
        binary, "-oX", "-", "-T4", "-Pn",
        "-sS" if raw_ok else "-sT",
        "-sV", "--version-light",
        "--top-ports", str(max(1, min(top_ports, 1000))),
        "--host-timeout", "45s",
    ]
    if raw_ok:
        args += ["-O", "--osscan-guess"]
    if scripts:
        args += ["--script", scripts]
    env = os.environ.copy()
    datadir = data_dir()
    if datadir:
        env["NMAPDATADIR"] = datadir
        args += ["--datadir", datadir]
    args += sorted(set(ips))
    try:
        kwargs = {"capture_output": True, "text": True, "timeout": timeout, "env": env}
        if platform_ops.IS_WINDOWS:
            kwargs["creationflags"] = platform_ops.CREATE_NO_WINDOW
        cp = subprocess.run(args, **kwargs)
    except subprocess.TimeoutExpired:
        return {"ok": False, "hosts": {}, "error": f"nmap timed out after {timeout}s",
                "command": " ".join(args)}
    except OSError as exc:
        return {"ok": False, "hosts": {}, "error": str(exc), "command": " ".join(args)}
    if cp.returncode != 0 and not cp.stdout.strip():
        return {"ok": False, "hosts": {}, "error": cp.stderr.strip()[:400],
                "command": " ".join(args)}
    return {
        "ok": True,
        "hosts": parse_xml(cp.stdout),
        "error": "",
        "command": " ".join(args),
        "stderr": cp.stderr.strip()[:400],
    }
