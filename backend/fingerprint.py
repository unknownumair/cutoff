"""Active LAN fingerprinting without third-party packages.

Probes used (all unprivileged, all against the local subnet only):
  * mDNS  — service/instance names, models, hosts (UDP/5353)
  * NetBIOS node status — Windows computer names (UDP/137)
  * SSDP/UPnP — friendlyName, manufacturer, model (UDP/1900 + HTTP)
  * HTTP — page title and Server header on common ports
  * TLS — certificate subject/issuer/SAN via the openssl CLI
  * SNMP v2c — sysName/sysDescr with community "public"

The result is merged into each device's ``info`` dict; names are ranked
mDNS/UPnP > NetBIOS > DNS/DHCP so the dashboard shows a human name whenever
one device advertises it.
"""
from __future__ import annotations

import html
import ipaddress
import logging
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen

log = logging.getLogger("cutoff.fingerprint")

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
COMMON_HTTP_PORTS = (80, 443, 8080, 8000, 5000, 8443)
SERVICE_QUERIES = (
    "_services._dns-sd._udp.local",
    "_device-info._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_http._tcp.local",
    "_smb._tcp.local",
    "_workstation._tcp.local",
    "_ssh._tcp.local",
)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------- mDNS
def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a DNS name with compression pointers."""
    if depth > 20:
        raise ValueError("compression loop")
    labels: list[str] = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = read_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            return ".".join(labels), offset + 2
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), offset


def build_query(name: str, qtype: int = 12, unicast: bool = True) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    qclass = 0x8001 if unicast else 0x0001
    return header + encode_name(name) + struct.pack("!HH", qtype, qclass)


def parse_dns(data: bytes) -> list[dict]:
    if len(data) < 12:
        return []
    _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x8000 == 0:  # a query, not a response
        return []
    offset = 12
    try:
        for _ in range(qd):
            _, offset = read_name(data, offset)
            offset += 4
        records: list[dict] = []
        for _ in range(an + ns + ar):
            name, offset = read_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata_off = offset
            end = offset + rdlen
            if end > len(data):
                break
            if rtype in (2, 5, 12):
                value, _ = read_name(data, rdata_off)
            elif rtype == 33:
                prio, weight, port = struct.unpack("!HHH", data[rdata_off:rdata_off + 6])
                target, _ = read_name(data, rdata_off + 6)
                value = {"priority": prio, "weight": weight, "port": port, "target": target}
            elif rtype == 16:
                strings: list[str] = []
                pos = rdata_off
                while pos < end:
                    size = data[pos]
                    pos += 1
                    strings.append(data[pos:pos + size].decode("utf-8", "replace"))
                    pos += size
                value = strings
            elif rtype == 1 and rdlen == 4:
                value = socket.inet_ntoa(data[rdata_off:end])
            elif rtype == 28 and rdlen == 16:
                value = socket.inet_ntop(socket.AF_INET6, data[rdata_off:end])
            else:
                value = data[rdata_off:end]
            records.append({"name": name, "type": rtype, "ttl": ttl, "value": value})
            offset = end
        return records
    except (ValueError, struct.error):
        return []


def _reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def mdns_discover(ips: list[str], timeout: float = 2.0) -> dict[str, dict]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bound = False
    try:
        try:
            sock.bind(("", MDNS_PORT))
            bound = True
        except OSError:
            sock.bind(("", 0))
        try:
            membership = socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        except OSError:
            pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        queries = [build_query(name, 12, unicast=not bound) for name in SERVICE_QUERIES]
        queries += [build_query(_reverse_name(ip), 12, unicast=not bound) for ip in ips]
        for query in queries:
            try:
                sock.sendto(query, (MDNS_GROUP, MDNS_PORT))
            except OSError:
                pass
        deadline = time.monotonic() + max(0.5, timeout)
        sock.settimeout(0.2)
        found: dict[str, dict] = {}
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            records = parse_dns(data)
            if not records:
                continue
            targets = {addr[0]}
            for record in records:
                if record["type"] == 1 and isinstance(record["value"], str):
                    targets.add(record["value"])
            for ip in targets:
                entry = found.setdefault(ip, {"names": [], "host": "", "model": "",
                                              "services": [], "txt": {}})
                _merge_mdns(entry, records)
        return {ip: entry for ip, entry in found.items() if ip in ips or entry["names"]}
    finally:
        sock.close()


def _merge_mdns(entry: dict, records: list[dict]) -> None:
    for record in records:
        name = record["name"]
        value = record["value"]
        if record["type"] == 12 and isinstance(value, str):
            if name == "_services._dns-sd._udp.local":
                entry["services"].append(value.replace(".local", ""))
            elif name.endswith(".in-addr.arpa"):
                entry["host"] = value.rstrip(".")
            elif "._" in value:
                instance = value.split("._", 1)[0]
                if instance and not instance.startswith("_"):
                    if instance not in entry["names"]:
                        entry["names"].append(instance)
                tail = value.split("._", 1)[1]
                entry["services"].append("_" + tail.split("._")[0])
        elif record["type"] == 33 and isinstance(value, dict):
            entry["host"] = value.get("target", "").rstrip(".")
        elif record["type"] == 16 and isinstance(value, list):
            for item in value:
                if "=" in item:
                    key, val = item.split("=", 1)
                    entry["txt"][key.strip()] = val.strip()
    txt = entry["txt"]
    entry["model"] = txt.get("model") or txt.get("md") or txt.get("am") or txt.get("ty") or ""
    entry["services"] = sorted({s for s in entry["services"] if s and not s.startswith("._")})


# ------------------------------------------------------------------ NetBIOS
NB_QUERY = (
    b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    b"\x00\x21\x00\x01"
)


def parse_netbios_response(data: bytes) -> dict:
    try:
        _, _, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            _, offset = read_name(data, offset)
            offset += 4
        if an < 1:
            return {}
        _, offset = read_name(data, offset)
        if offset + 10 > len(data):
            return {}
        _, _, _, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if not rdata:
            return {}
        count = rdata[0]
        names: list[dict] = []
        for index in range(count):
            raw = rdata[1 + index * 18: 1 + index * 18 + 18]
            if len(raw) < 16:
                break
            names.append({
                "name": raw[:15].decode("ascii", "replace").strip("\x00 "),
                "suffix": raw[15],
            })
        mac_bytes = rdata[1 + count * 18: 1 + count * 18 + 6]
        mac = ":".join(f"{b:02x}" for b in mac_bytes) if len(mac_bytes) == 6 else ""
        primary = next((n["name"] for n in names
                        if n["suffix"] == 0 and n["name"] and n["name"] != "*"), "")
        return {"name": primary, "names": names, "mac": mac}
    except (ValueError, struct.error, IndexError):
        return {}


def netbios_status(ip: str, timeout: float = 0.7) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(NB_QUERY, (ip, 137))
        data, _ = sock.recvfrom(4096)
        return parse_netbios_response(data)
    except (OSError, socket.timeout):
        return {}
    finally:
        sock.close()


# -------------------------------------------------------------------- SSDP
def ssdp_discover(timeout: float = 2.0, max_fetches: int = 12) -> dict[str, dict]:
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_GROUP}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.25)
    responses: dict[str, list[str]] = {}
    try:
        for _ in range(3):
            sock.sendto(request, (SSDP_GROUP, SSDP_PORT))
            time.sleep(0.12)
        deadline = time.monotonic() + max(0.5, timeout)
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode("latin-1", "replace")
            location = ""
            for line in text.splitlines():
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
                    break
            if location:
                sites = responses.setdefault(addr[0], [])
                if location not in sites and len(sites) < 3:
                    sites.append(location)
    finally:
        sock.close()

    out: dict[str, dict] = {}
    fetches = 0
    for ip, locations in responses.items():
        for location in locations:
            if fetches >= max_fetches:
                break
            fetches += 1
            info = fetch_upnp(location)
            if info:
                out[ip] = info
                break
    return out


def parse_upnp_xml(xml_text: str) -> dict:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    wanted = ("friendlyName", "manufacturer", "modelName", "modelDescription",
              "deviceType", "UDN", "serialNumber")
    out: dict[str, str] = {}
    for tag in wanted:
        for element in root.iter():
            if element.tag.split("}")[-1] == tag and (element.text or "").strip():
                out[tag] = element.text.strip()
                break
    if out.get("deviceType"):
        out["deviceClass"] = out["deviceType"].split(":")[-2] if ":" in out["deviceType"] else ""
    return out


def fetch_upnp(location: str) -> dict:
    if not location.startswith(("http://", "https://")):
        return {}
    try:
        request = Request(location, headers={"User-Agent": "CUTOFF/1.0"})
        with urlopen(request, timeout=1.5) as response:  # noqa: S310 - LAN URL
            body = response.read(65536).decode("utf-8", "replace")
        return parse_upnp_xml(body)
    except Exception:  # noqa: BLE001 - a failed fetch is normal
        return {}


# -------------------------------------------------------------------- HTTP
def http_probe(ip: str, timeout: float = 0.6) -> dict:
    for port in COMMON_HTTP_PORTS:
        secure = port in (443, 8443)
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            if secure:
                context = ssl._create_unverified_context()  # noqa: S323 - LAN probe
                sock = context.wrap_socket(sock, server_hostname=ip)
            sock.sendall(
                f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: CUTOFF/1.0\r\n"
                "Connection: close\r\n\r\n".encode()
            )
            chunks: list[bytes] = []
            total = 0
            while total < 8192:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            raw = b"".join(chunks)
        except (OSError, ssl.SSLError):
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if not raw:
            continue
        text = raw.decode("latin-1", "replace")
        head, _, body = text.partition("\r\n\r\n")
        lines = head.splitlines()
        status = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        title = ""
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if match:
            title = re.sub(r"\s+", " ", html.unescape(re.sub("<[^>]+>", "", match.group(1)))).strip()[:140]
        return {
            "port": port,
            "secure": secure,
            "status": status,
            "server": headers.get("server", ""),
            "title": title,
            "location": headers.get("location", ""),
        }
    return {}


def tls_probe(ip: str, port: int = 443, timeout: float = 3.0) -> dict:
    if not shutil.which("openssl"):
        return {}
    try:
        handshake = subprocess.run(
            ["openssl", "s_client", "-connect", f"{ip}:{port}", "-servername", ip],
            input=b"", capture_output=True, timeout=timeout,
        )
        if not handshake.stdout:
            return {}
        cert = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-ext", "subjectAltName"],
            input=handshake.stdout, capture_output=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    text = (cert.stdout + cert.stderr).decode("utf-8", "replace")
    out: dict = {}
    for key, label in (("subject", "subject="), ("issuer", "issuer=")):
        for line in text.splitlines():
            if line.lower().startswith(label):
                out[key] = line.split("=", 1)[1].strip()
                break
    match = re.search(r"CN\s*=\s*([^,\n]+)", out.get("subject", ""))
    if match:
        out["cn"] = match.group(1).strip()
    sans: list[str] = []
    for line in text.splitlines():
        if "DNS:" in line or "IP Address:" in line:
            sans += [part.strip() for part in line.split(",") if "DNS:" in part or "IP Address:" in part]
    if sans:
        out["san"] = sans[:12]
    return out


# -------------------------------------------------------------------- SNMP
def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(number: int) -> bytes:
    if number == 0:
        return _tlv(0x02, b"\x00")
    raw = number.to_bytes((number.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(0x02, raw)


def _ber_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 128:
            out += bytes([part])
            continue
        chunks: list[int] = []
        while part:
            chunks.append(part & 0x7F)
            part >>= 7
        chunks.reverse()
        for index, chunk in enumerate(chunks):
            out += bytes([chunk | (0x80 if index < len(chunks) - 1 else 0)])
    return _tlv(0x06, out)


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def snmp_get(ip: str, oid: str, community: str = "public", timeout: float = 0.8) -> str:
    request_id = random.randint(1, 0x7FFFFFFF)
    varbind = _tlv(0x30, _ber_oid(oid) + _tlv(0x05, b""))
    pdu = _tlv(0xA0, _ber_int(request_id) + _ber_int(0) + _ber_int(0) + _tlv(0x30, varbind))
    message = _tlv(0x30, _ber_int(1) + _tlv(0x04, community.encode()) + pdu)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(message, (ip, 161))
        data, _ = sock.recvfrom(4096)
        _, body, _ = _read_tlv(data, 0)
        offset = 0
        _, _, offset = _read_tlv(body, offset)          # version
        _, _, offset = _read_tlv(body, offset)          # community
        _, pdu_body, _ = _read_tlv(body, offset)        # PDU
        inner = 0
        for _ in range(3):
            _, _, inner = _read_tlv(pdu_body, inner)    # req id, err, err index
        _, varbinds, _ = _read_tlv(pdu_body, inner)
        _, first, _ = _read_tlv(varbinds, 0)
        _, _, value_offset = _read_tlv(first, 0)        # OID
        tag, value, _ = _read_tlv(first, value_offset)
        if tag == 0x04:
            return value.decode("utf-8", "replace").strip()
        if tag == 0x02:
            return str(int.from_bytes(value, "big", signed=True))
        return ""
    except (OSError, ValueError, IndexError, socket.timeout):
        return ""
    finally:
        sock.close()


def snmp_probe(ip: str) -> dict:
    name = snmp_get(ip, "1.3.6.1.2.1.1.5.0")
    if not name:
        return {}
    description = snmp_get(ip, "1.3.6.1.2.1.1.1.0")
    return {"sysName": name, "sysDescr": description[:200]}


# ------------------------------------------------------------- orchestration
def _pick_name(device: dict) -> str:
    info = device.get("info", {})
    mdns = info.get("mdns", {})
    upnp = info.get("upnp", {})
    netbios = info.get("netbios", {})
    mdns_host = (mdns.get("host") or "").split(".")[0]
    for candidate in (
        (mdns.get("names") or [""])[0],
        upnp.get("friendlyName", ""),
        netbios.get("name", ""),
        mdns_host,
        device.get("hostname", ""),
    ):
        candidate = (candidate or "").strip()
        if candidate and not candidate.startswith("_"):
            return candidate[:64]
    return device.get("hostname", "")


def classify(device: dict) -> str:
    if device.get("is_self"):
        return "workstation"
    info = device.get("info", {})
    text = " ".join(str(part) for part in (
        device.get("vendor", ""),
        device.get("model", ""),
        device.get("hostname", ""),
        device.get("title", ""),
        info.get("upnp", {}).get("deviceClass", ""),
        info.get("upnp", {}).get("modelName", ""),
        info.get("snmp", {}).get("sysDescr", ""),
    )).lower()
    ports = {p.get("port") for p in device.get("ports", [])}
    if any(word in text for word in ("router", "gateway", "broadband", "access point")):
        return "router"
    if any(word in text for word in ("iphone", "android", "phone", "galaxy", "pixel", "redmi")):
        return "phone"
    if any(word in text for word in ("ipad", "tablet", "tab ")):
        return "tablet"
    if any(word in text for word in ("printer", "laserjet", "officejet", "epson", "brother", "scanner")):
        return "printer"
    if any(word in text for word in ("camera", "ipcam", "hikvision", "dahua", "webcam")):
        return "camera"
    if any(word in text for word in ("tv", "bravia", "roku", "chromecast", "apple tv", "fire tv", "mediarenderer")):
        return "tv"
    if any(word in text for word in ("raspberry", "espressif", "sonoff", "tasmota", "iot", "smart")):
        return "iot"
    if {9100, 631, 515} & ports:
        return "printer"
    if {554, 8554} & ports:
        return "camera"
    if {22, 445, 3389, 139} & ports:
        return "computer"
    return "device"


def enrich(devices: list[dict], timeout: float = 2.0) -> dict:
    ips = [d["ip"] for d in devices if _valid_ip(d.get("ip", ""))]
    if not ips:
        return {"probed": 0, "errors": []}

    mdns = mdns_discover(ips, timeout=timeout)
    ssdp = ssdp_discover(timeout=timeout)

    def probe(device: dict) -> dict:
        ip = device["ip"]
        result: dict = {}
        result["netbios"] = netbios_status(ip)
        http = http_probe(ip)
        if http:
            result["http"] = http
            if http.get("secure"):
                tls = tls_probe(ip, http["port"])
                if tls:
                    result["tls"] = tls
        snmp = snmp_probe(ip)
        if snmp:
            result["snmp"] = snmp
        return result

    results: list[dict] = [{} for _ in devices]
    try:
        with ThreadPoolExecutor(max_workers=min(16, max(4, len(devices)))) as pool:
            results = list(pool.map(probe, devices))
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail a scan
        log.warning("fingerprint probes failed: %s", exc)

    for device, extra in zip(devices, results, strict=False):
        ip = device["ip"]
        info = device.setdefault("info", {})
        if ip in mdns:
            info["mdns"] = mdns[ip]
        if ip in ssdp:
            info["upnp"] = ssdp[ip]
        info.update({key: value for key, value in extra.items() if value})
        http = info.get("http", {})
        device["hostname"] = _pick_name(device)
        device["title"] = http.get("title", "") or device.get("title", "")
        device["model"] = (info.get("upnp", {}).get("modelName")
                           or info.get("mdns", {}).get("model")
                           or device.get("model", ""))
        device["manufacturer"] = (info.get("upnp", {}).get("manufacturer")
                                  or device.get("manufacturer", "")
                                  or (device.get("vendor") if device.get("vendor") != "Unknown" else ""))
        names = {
            "mdns": (info.get("mdns", {}).get("names") or [""])[0],
            "mdns_host": (info.get("mdns", {}).get("host") or "").split(".")[0],
            "netbios": info.get("netbios", {}).get("name", ""),
            "upnp": info.get("upnp", {}).get("friendlyName", ""),
            "http": device["title"],
            "snmp": info.get("snmp", {}).get("sysName", ""),
        }
        device["names"] = {key: value for key, value in names.items() if value}
        device["device_type"] = classify(device)
        device["sources"] = sorted(set(device.get("sources", [])) | {"fingerprint"})

    return {
        "probed": len(devices),
        "mdns": len(mdns),
        "ssdp": len(ssdp),
        "errors": [],
    }
