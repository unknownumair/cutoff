"""LAN activity monitor — bettercap-style metadata capture, no payload storage.

Passive mode only sees broadcast/multicast and traffic addressed to this host
(a switched LAN hides the rest). Gateway mode puts CUTOFF in-path with ARP
spoofing so capture and blocking cover every client; it is opt-in, TTL-limited
and restored on stop.

Captured metadata: DNS queries, TLS SNI, HTTP Host, per-IP byte counters and
flows. Payloads are never written to disk.
"""
from __future__ import annotations

import collections
import json
import logging
import socket
import struct
import threading
import time

import arpguard
import config
from fingerprint import read_name

log = logging.getLogger("cutoff.monitor")

ETH_P_ALL = 0x0003
SOL_PACKET = getattr(socket, "SOL_PACKET", 263)  # Linux AF_PACKET level
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
MAX_DNS = 400
MAX_ALERTS = 200
MAX_FLOWS = 600
POLICY_FILE = config.DATA_DIR / "monitor.json"


# ------------------------------------------------------------------ parsers
def parse_dns_question(payload: bytes) -> tuple[str, int] | None:
    if len(payload) < 12:
        return None
    flags, qd = struct.unpack("!HH", payload[2:6])
    if qd < 1:
        return None
    try:
        name, offset = read_name(payload, 12)
        qtype = struct.unpack("!H", payload[offset:offset + 2])[0]
    except (ValueError, struct.error):
        return None
    return (name.rstrip("."), qtype)


def parse_tls_sni(payload: bytes) -> str:
    """Extract server_name from a TLS ClientHello, or ''."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
            return ""
        record_len = struct.unpack("!H", payload[3:5])[0]
        body = payload[5:5 + record_len]
        if not body or body[0] != 0x01:
            return ""
        pos = 4  # handshake type + length
        pos += 2 + 32  # version + random
        sid_len = body[pos]
        pos += 1 + sid_len
        cipher_len = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2 + cipher_len
        comp_len = body[pos]
        pos += 1 + comp_len
        if pos + 2 > len(body):
            return ""
        ext_total = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        end = min(len(body), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", body[pos:pos + 4])
            pos += 4
            ext = body[pos:pos + ext_len]
            pos += ext_len
            if ext_type != 0x0000 or len(ext) < 5:
                continue
            list_len = struct.unpack("!H", ext[:2])[0]
            inner = 2
            while inner + 3 <= min(len(ext), 2 + list_len):
                name_type = ext[inner]
                name_len = struct.unpack("!H", ext[inner + 1:inner + 3])[0]
                name = ext[inner + 3:inner + 3 + name_len]
                if name_type == 0 and name:
                    try:
                        decoded = name.decode("idna")
                    except UnicodeError:
                        decoded = name.decode("latin-1", "ignore")
                    return decoded.rstrip(".")
                inner += 3 + name_len
        return ""
    except (struct.error, IndexError, UnicodeError):
        return ""


def parse_http_host(payload: bytes) -> str:
    head = payload[:2048]
    if not head or head[:4] not in (b"GET ", b"POST", b"PUT ", b"HEAD", b"OPTI"):
        return ""
    for line in head.splitlines():
        if line.lower().startswith(b"host:"):
            return line.split(b":", 1)[1].strip().decode("latin-1", "ignore")[:120]
    return ""


# ------------------------------------------------------------------ capture
class PacketCapture:
    def __init__(self, iface: str, policy: dict, allowed_ips: set[str] | None = None):
        self.iface = iface
        self.policy = policy
        self.allowed_ips: set[str] = set(allowed_ips or ())
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.started_at = 0.0
        self.packets = 0
        self.bytes = 0
        self.dropped = 0
        self.counters: dict[str, dict] = {}      # ip -> {tx, rx, packets, last, domains:set}
        self.flows: collections.OrderedDict = collections.OrderedDict()
        self.dns: collections.deque = collections.deque(maxlen=MAX_DNS)
        self.alerts: collections.deque = collections.deque(maxlen=MAX_ALERTS)
        self._alert_seen: dict[tuple[str, str], float] = {}

    # lifecycle ------------------------------------------------------------
    def start(self) -> tuple[bool, str]:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(ETH_P_ALL))
            sock.bind((self.iface, ETH_P_ALL))
            try:
                mreq = struct.pack("iHH8s", socket.if_nametoindex(self.iface),
                                   PACKET_MR_PROMISC, 0, b"")
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            except (OSError, AttributeError):
                pass  # not promiscuous, but unicast/broadcast still visible
            sock.settimeout(0.4)
        except (PermissionError, OSError) as exc:
            return False, f"raw packet capture needs root: {exc}"
        self._sock = sock
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="cutoff-capture")
        self._thread.start()
        return True, "capture started"

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def set_allowed(self, ips: set[str]) -> None:
        with self._lock:
            self.allowed_ips = set(ips)

    # loop -----------------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                frame = self._sock.recv(65535) if self._sock else b""
            except socket.timeout:
                continue
            except OSError:
                break
            if not frame:
                continue
            try:
                self._handle(frame)
            except Exception:  # noqa: BLE001 - a malformed frame must not kill capture
                self.dropped += 1

    def _handle(self, frame: bytes) -> None:
        if len(frame) < 14:
            return
        eth_type = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        if eth_type == 0x8100 and len(frame) >= 18:
            eth_type = struct.unpack("!H", frame[16:18])[0]
            offset = 18
        if eth_type == 0x0800:
            self._ipv4(frame, offset)
        elif eth_type == 0x86DD:
            self._ipv6(frame, offset)

    def _ipv4(self, frame: bytes, offset: int) -> None:
        if len(frame) < offset + 20:
            return
        ihl = (frame[offset] & 0x0F) * 4
        total = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        proto = frame[offset + 9]
        src = socket.inet_ntoa(frame[offset + 12:offset + 16])
        dst = socket.inet_ntoa(frame[offset + 16:offset + 20])
        end = min(len(frame), offset + max(total, ihl))
        self._transport(frame, offset + ihl, end, src, dst, proto, max(total, ihl))

    def _ipv6(self, frame: bytes, offset: int) -> None:
        if len(frame) < offset + 40:
            return
        proto = frame[offset + 6]
        src = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        plen = struct.unpack("!H", frame[offset + 4:offset + 6])[0]
        end = min(len(frame), offset + 40 + plen)
        self._transport(frame, offset + 40, end, src, dst, proto, 40 + plen)

    def _transport(self, frame: bytes, offset: int, end: int,
                   src: str, dst: str, proto: int, size: int) -> None:
        sport = dport = 0
        payload = b""
        if proto == 6 and offset + 20 <= end:
            sport, dport = struct.unpack("!HH", frame[offset:offset + 4])
            data_off = (frame[offset + 12] >> 4) * 4
            payload = frame[offset + data_off:end]
        elif proto == 17 and offset + 8 <= end:
            sport, dport = struct.unpack("!HH", frame[offset:offset + 4])
            payload = frame[offset + 8:end]
        else:
            return

        src_local = src in self.allowed_ips
        dst_local = dst in self.allowed_ips
        if not src_local and not dst_local:
            return  # remote-to-remote or traffic outside the inventoried LAN

        with self._lock:
            self.packets += 1
            self.bytes += size
            if src_local:
                entry = self.counters.setdefault(src, {
                    "tx": 0, "rx": 0, "packets": 0, "domains": set(),
                    "last": 0.0,
                })
                entry["tx"] += size
                entry["packets"] += 1
                entry["last"] = time.time()
            if dst_local:
                entry = self.counters.setdefault(dst, {
                    "tx": 0, "rx": 0, "packets": 0, "domains": set(),
                    "last": 0.0,
                })
                entry["rx"] += size
                entry["packets"] += 1
                entry["last"] = time.time()
            key = (src, dst, dport, proto)
            flow = self.flows.get(key)
            if flow is None:
                flow = {"src": src, "dst": dst, "sport": sport, "dport": dport,
                        "proto": proto, "bytes": 0, "packets": 0,
                        "first": time.time(), "last": time.time(), "domain": ""}
                self.flows[key] = flow
            flow["bytes"] += size
            flow["packets"] += 1
            flow["last"] = time.time()
            while len(self.flows) > MAX_FLOWS:
                self.flows.popitem(last=False)

        if dport == 53 and payload and src_local:
            self._dns(src, payload)
        elif dport == 443 and payload and src_local:
            sni = parse_tls_sni(payload)
            if sni:
                self._observe(src, dst, sni, "sni", dport)
        elif dport == 80 and payload and src_local:
            host = parse_http_host(payload)
            if host:
                self._observe(src, dst, host, "http", dport)

    def _dns(self, src: str, payload: bytes) -> None:
        question = parse_dns_question(payload)
        if not question:
            return
        name, qtype = question
        if not name:
            return
        with self._lock:
            self.dns.append({"ts": time.time(), "ip": src, "name": name,
                             "type": qtype})
            entry = self.counters.setdefault(src, {
                "tx": 0, "rx": 0, "packets": 0, "domains": set(), "last": 0.0,
            })
            entry["domains"].add(name)
            if len(entry["domains"]) > 40:
                entry["domains"] = set(list(entry["domains"])[-40:])
        self._match_policy(src, name, "dns")

    def _observe(self, src: str, dst: str, name: str, kind: str, port: int) -> None:
        with self._lock:
            entry = self.counters.setdefault(src, {
                "tx": 0, "rx": 0, "packets": 0, "domains": set(), "last": 0.0,
            })
            entry["domains"].add(name)
            flow = self.flows.get((src, dst, port, 6))
            if flow is not None and not flow.get("domain"):
                flow["domain"] = name
        self._match_policy(src, name, kind)

    def _match_policy(self, ip: str, name: str, kind: str) -> None:
        policy = self.policy or {}
        lowered = name.lower()
        hit = ""
        for domain in policy.get("domains", []):
            if domain and domain.lower() in lowered:
                hit = domain
                break
        if not hit:
            for keyword in policy.get("keywords", []):
                if keyword and keyword.lower() in lowered:
                    hit = keyword
                    break
        if not hit:
            return
        key = (ip, name)
        now = time.time()
        if now - self._alert_seen.get(key, 0) < 60:
            return
        self._alert_seen[key] = now
        alert = {"ts": now, "ip": ip, "kind": kind, "value": name, "match": hit}
        with self._lock:
            self.alerts.append(alert)

    # snapshot -------------------------------------------------------------
    def snapshot(self, flow_limit: int = 80, dns_limit: int = 80) -> dict:
        with self._lock:
            devices = []
            for ip, entry in self.counters.items():
                devices.append({
                    "ip": ip,
                    "tx": entry["tx"],
                    "rx": entry["rx"],
                    "packets": entry["packets"],
                    "last": entry["last"],
                    "domains": sorted(entry["domains"])[:12],
                })
            devices.sort(key=lambda d: d["tx"] + d["rx"], reverse=True)
            flows = sorted(self.flows.values(), key=lambda f: f["bytes"],
                           reverse=True)[:flow_limit]
            return {
                "running": self.running,
                "started_at": self.started_at,
                "scope": len(self.allowed_ips),
                "packets": self.packets,
                "bytes": self.bytes,
                "dropped": self.dropped,
                "devices": devices,
                "flows": flows,
                "dns": list(self.dns)[-dns_limit:][::-1],
                "alerts": list(self.alerts)[-dns_limit:][::-1],
            }


# ------------------------------------------------------------------ monitor
class NetworkMonitor:
    def __init__(self, store):
        self.store = store
        self.capture: PacketCapture | None = None
        self.gateway: arpguard.LanGateway | None = None
        self.mode = "idle"
        self.started_at = 0.0
        self.iface = None
        self._timer: threading.Timer | None = None
        self.policy = self._load_policy()
        self.on_stop = None
        self.scope: set[str] = set()

    def _load_policy(self) -> dict:
        policy = {"domains": [], "keywords": []}
        try:
            if POLICY_FILE.exists():
                raw = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
                policy["domains"] = [str(v) for v in raw.get("domains", [])][:200]
                policy["keywords"] = [str(v) for v in raw.get("keywords", [])][:200]
        except (OSError, json.JSONDecodeError):
            pass
        return policy

    def _save_policy(self) -> None:
        try:
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            POLICY_FILE.write_text(json.dumps(self.policy, indent=2), encoding="utf-8")
            POLICY_FILE.chmod(0o600)
        except OSError as exc:
            log.warning("cannot save monitor policy: %s", exc)

    def set_policy(self, domains: list[str], keywords: list[str]) -> dict:
        self.policy = {
            "domains": [str(d).strip().lower() for d in domains if str(d).strip()][:200],
            "keywords": [str(k).strip().lower() for k in keywords if str(k).strip()][:200],
        }
        if self.capture:
            self.capture.policy = self.policy
        self._save_policy()
        return self.policy

    # lifecycle -----------------------------------------------------------
    def start(self, mode: str, duration_min: int, iface) -> tuple[bool, str]:
        if self.mode != "idle":
            return False, "monitor already running"
        if mode not in ("passive", "gateway"):
            return False, "mode must be passive or gateway"
        if iface is None:
            return False, "no network interface"
        allowed = self._scope_ips(iface)
        if not allowed:
            return False, "no online devices on this network — run a scan first"
        self.iface = iface
        self.scope = allowed
        self.capture = PacketCapture(iface.name, self.policy, allowed)
        if mode == "gateway":
            devices = [d for d in self.store.devices()
                       if d.get("active") and d.get("ip") and d.get("mac")]
            self.gateway = arpguard.LanGateway(
                iface=iface.name, our_ip=iface.ip, our_mac=iface.mac,
                gateway_ip=iface.gateway, gateway_mac=iface.gateway_mac,
                clients=[(d["ip"], d["mac"]) for d in devices],
                refresh=config.POISON_REFRESH_SEC,
                max_minutes=max(1, duration_min),
            )
            ok, msg = self.gateway.start()
            if not ok:
                self.gateway = None
                return False, msg
        try:
            ok, msg = self.capture.start()
        except Exception as exc:  # noqa: BLE001 - never turn a start failure into HTTP 500
            log.exception("capture start failed")
            ok, msg = False, f"capture start failed: {exc}"
        if not ok:
            if self.gateway:
                self.gateway.stop()
                self.gateway = None
            self.capture = None
            return False, msg
        self.mode = mode
        self.started_at = time.time()
        self._timer = threading.Timer(max(1, duration_min) * 60, self.stop)
        self._timer.daemon = True
        self._timer.start()
        return True, msg

    def stop(self) -> dict:
        if self._timer:
            self._timer.cancel()
            self._timer = None
        if self.capture:
            self.capture.stop()
        if self.gateway:
            self.gateway.stop()
        self.mode = "idle"
        self.started_at = 0.0
        self.gateway = None
        if self.on_stop:
            try:
                self.on_stop()
            except Exception:  # noqa: BLE001
                pass
        return {"ok": True}

    def _scope_ips(self, iface) -> set[str]:
        import ipaddress

        try:
            network = ipaddress.ip_interface(f"{iface.ip}/{iface.prefix}").network
        except (ValueError, TypeError):
            return set()
        scope: set[str] = set()
        for device in self.store.devices():
            if not device.get("active"):
                continue  # only devices online in the latest scan
            ip = device.get("ip") or ""
            try:
                if ip and ipaddress.ip_address(ip) in network:
                    scope.add(ip)
            except ValueError:
                continue
        return scope

    def refresh_scope(self, iface) -> set[str]:
        scope = self._scope_ips(iface) if iface else set()
        self.scope = scope
        if self.capture:
            self.capture.set_allowed(scope)
        return scope

    # snapshot ------------------------------------------------------------
    def snapshot(self) -> dict:
        base = {"mode": self.mode, "started_at": self.started_at,
                "policy": self.policy, "gateway": None, "scope": len(self.scope),
                "running": bool(self.capture and self.capture.running)}
        if self.capture:
            base.update(self.capture.snapshot())
        else:
            base.update({"packets": 0, "bytes": 0, "devices": [], "flows": [],
                         "dns": [], "alerts": [], "dropped": 0})
        if self.gateway:
            base["gateway"] = self.gateway.status()
        return base
