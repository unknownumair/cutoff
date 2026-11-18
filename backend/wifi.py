"""Wi-Fi disassociation helpers.

Kicking a wireless client is only possible from a position of authority:
  1. This host runs the AP (hostapd) -> ask hostapd to deauthenticate the client.
  2. A monitor-mode adapter is available and the AP BSSID is known -> inject
     802.11 deauthentication frames.
Anything else is reported honestly as unavailable; blocking (firewall/ARP) is
the fallback that always works.
"""
from __future__ import annotations

import logging
import os
import shutil
import socket
import struct
import subprocess
import time

import platform_ops

log = logging.getLogger("cutoff.wifi")

ETH_P_ALL = 0x0003
MONITOR_TYPE = 803


def _ifaces() -> list[str]:
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


def _is_wireless(name: str) -> bool:
    return os.path.isdir(f"/sys/class/net/{name}/wireless") or os.path.exists(
        f"/sys/class/net/{name}/phy80211"
    )


def wireless_ifaces() -> list[str]:
    return [n for n in _ifaces() if _is_wireless(n)]


def monitor_ifaces() -> list[str]:
    out: list[str] = []
    for name in wireless_ifaces():
        try:
            with open(f"/sys/class/net/{name}/type", encoding="utf-8") as fh:
                if int(fh.read().strip()) == MONITOR_TYPE:
                    out.append(name)
        except (OSError, ValueError):
            continue
    if not out and shutil.which("iw"):
        try:
            res = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            current = None
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    current = line.split()[-1]
                elif line.startswith("type monitor") and current:
                    out.append(current)
        except (OSError, subprocess.SubprocessError):
            pass
    return out


def capabilities() -> dict:
    if platform_ops.IS_WINDOWS:
        return {
            "wireless_interfaces": [],
            "monitor_interfaces": [],
            "hostapd_cli": False,
            "can_deauth": False,
            "note": ("Wi-Fi deauth is not available on Windows; use Block "
                     "(ARP + Windows Firewall)."),
        }
    hostapd = shutil.which("hostapd_cli")
    return {
        "wireless_interfaces": wireless_ifaces(),
        "monitor_interfaces": monitor_ifaces(),
        "hostapd_cli": bool(hostapd),
        "can_deauth": bool(hostapd or monitor_ifaces()),
        "note": (
            "Deauth needs hostapd control or a monitor-mode adapter + AP BSSID. "
            "Without those, use Block — it cuts all traffic instead."
        ),
    }


def _deauth_frame(dst: str, bssid: str) -> bytes:
    def mac(value: str) -> bytes:
        return bytes.fromhex(value.replace(":", "").replace("-", ""))

    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    fc = struct.pack("<BB", 0xC0, 0x00)          # management, deauth
    duration = struct.pack("<H", 0)
    seq = struct.pack("<H", 0)
    reason = struct.pack("<H", 7)                # class-3 frame from unassociated STA
    return radiotap + fc + duration + mac(dst) + mac(bssid) + mac(bssid) + seq + reason


def deauth(mac: str, bssid: str | None = None, seconds: int = 8,
           iface: str | None = None) -> dict:
    """Best-effort deauthentication. Never raises."""
    caps = capabilities()
    if shutil.which("hostapd_cli"):
        for wi in caps["wireless_interfaces"] or [iface]:
            if not wi:
                continue
            try:
                cp = subprocess.run(
                    ["hostapd_cli", "-i", wi, "deauthenticate", mac],
                    capture_output=True, text=True, timeout=8,
                )
                if cp.returncode == 0 and "FAIL" not in cp.stdout.upper():
                    return {"ok": True, "method": "hostapd", "detail": cp.stdout.strip() or "sent"}
            except (OSError, subprocess.SubprocessError) as exc:
                log.info("hostapd_cli failed on %s: %s", wi, exc)

    mon = iface or (caps["monitor_interfaces"][0] if caps["monitor_interfaces"] else None)
    if not mon:
        return {"ok": False, "method": "none", "error":
                "no monitor-mode interface — create one (airmon-ng start <iface>) "
                "or run CUTOFF on the AP itself"}
    if not bssid:
        return {"ok": False, "method": "none", "error":
                "AP BSSID required for frame injection; pass it explicitly"}
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((mon, ETH_P_ALL))
    except (PermissionError, OSError) as exc:
        return {"ok": False, "method": "none", "error": f"raw socket denied: {exc}"}
    frame = _deauth_frame(mac, bssid)
    sent = 0
    deadline = time.time() + max(1, min(seconds, 60))
    try:
        while time.time() < deadline:
            try:
                sock.send(frame)
                sent += 1
            except OSError:
                break
            time.sleep(0.05)
    finally:
        sock.close()
    return {"ok": sent > 0, "method": "injection", "sent": sent,
            "error": "" if sent else "no frames could be injected"}
