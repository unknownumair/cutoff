"""CUTOFF test suite — stdlib unittest, no live network changes required.

Run: .venv/bin/python -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["CUTOFF_DATA_DIR"] = tempfile.mkdtemp(prefix="cutoff-test-")
os.environ["CUTOFF_SIMULATE"] = "on"
os.environ["CUTOFF_TOKEN"] = "test-token-123"

import arpguard  # noqa: E402
import bettercap_ctl  # noqa: E402
import firewall_win  # noqa: E402
import platform_ops  # noqa: E402
import discovery  # noqa: E402
import enforcer as enforcer_mod  # noqa: E402
import fingerprint  # noqa: E402
import firewall  # noqa: E402
import ipv6 as ipv6_mod  # noqa: E402
import ndpguard  # noqa: E402
import monitor as monitor_mod  # noqa: E402
import netinfo  # noqa: E402
import nmapgui  # noqa: E402
import nmapscan  # noqa: E402
import store as store_mod  # noqa: E402
import wifi  # noqa: E402
from oui import vendor_for  # noqa: E402


class FingerprintTests(unittest.TestCase):
    def test_dns_encode_and_parse_ptr(self):
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        owner = fingerprint.encode_name("_airplay._tcp.local")
        target = fingerprint.encode_name("Living-Room-TV.local")
        record = owner + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
        records = fingerprint.parse_dns(header + record)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["type"], 12)
        self.assertEqual(records[0]["value"], "Living-Room-TV.local")

    def test_dns_compression_pointer(self):
        # name at offset 12: "tv.local"; answer name is a pointer to it
        body = fingerprint.encode_name("tv.local") + struct.pack("!HH", 1, 1)
        header = struct.pack("!HHHHHH", 0, 0x8400, 1, 0, 0, 0)
        data = header + body
        name, offset = fingerprint.read_name(data, 12)
        self.assertEqual(name, "tv.local")

    def test_netbios_response(self):
        qname = b"\x20" + b"CK" + b"A" * 30 + b"\x00"
        rdata = (bytes([1]) + b"MYPC".ljust(15, b"\x00") + b"\x00" + b"\x00\x00"
                 + bytes.fromhex("aabbccddeeff"))
        data = (struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0)
                + qname + struct.pack("!HH", 0x21, 1)
                + b"\xc0\x0c" + struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata)
        result = fingerprint.parse_netbios_response(data)
        self.assertEqual(result["name"], "MYPC")
        self.assertEqual(result["mac"], "aa:bb:cc:dd:ee:ff")

    def test_upnp_xml(self):
        xml = """<root><device>
          <friendlyName>Living Room TV</friendlyName>
          <manufacturer>Acme</manufacturer><modelName>X1</modelName>
          <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
        </device></root>"""
        info = fingerprint.parse_upnp_xml(xml)
        self.assertEqual(info["friendlyName"], "Living Room TV")
        self.assertEqual(info["manufacturer"], "Acme")
        self.assertEqual(info["deviceClass"], "MediaRenderer")

    def test_device_classify(self):
        self.assertEqual(fingerprint.classify({"vendor": "Apple", "hostname": "iPhone"}), "phone")
        self.assertEqual(fingerprint.classify({"is_self": True}), "workstation")
        self.assertEqual(fingerprint.classify({"ports": [{"port": 9100}]}), "printer")


class NmapTests(unittest.TestCase):
    XML = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <address addr="aa:bb:cc:dd:ee:01" addrtype="mac"/>
        <hostnames><hostname name="nas.local"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="9.6"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http"/>
            <script id="http-title" output="Title: NAS admin"/>
          </port>
        </ports>
        <os><osmatch name="Linux 5.0" accuracy="95"/></os>
        <hostscript><script id="nbstat" output="NetBIOS name: NAS"/></hostscript>
      </host>
      <host><status state="down"/><address addr="192.168.1.11" addrtype="ipv4"/></host>
    </nmaprun>"""

    def test_parse_xml(self):
        hosts = nmapscan.parse_xml(self.XML)
        self.assertIn("192.168.1.10", hosts)
        self.assertNotIn("192.168.1.11", hosts)
        host = hosts["192.168.1.10"]
        self.assertEqual(host["hostnames"], ["nas.local"])
        self.assertEqual(host["ports"][0]["service"], "ssh")
        self.assertEqual(host["ports"][0]["version"], "9.6")
        self.assertEqual(host["os"][0]["name"], "Linux 5.0")
        self.assertIn("NetBIOS name", host["scripts"]["nbstat"])
        self.assertEqual(host["scripts"]["http-title"], "Title: NAS admin")

    def test_capabilities_shape(self):
        caps = nmapscan.capabilities()
        for key in ("available", "path", "version", "privileged", "note"):
            self.assertIn(key, caps)


class SelfDeviceTests(unittest.TestCase):
    def test_self_device_included(self):
        iface = netinfo.current_interface()
        if iface is None:
            self.skipTest("no IPv4 default route")
        device = discovery.self_device(iface.name, iface.ip)
        self.assertIsNotNone(device)
        self.assertTrue(device["is_self"])
        self.assertEqual(device["ip"], iface.ip)
        self.assertTrue(device["mac"])
        self.assertIn("self", device["info"])

    def test_apply_nmap_merges_ports_and_names(self):
        devices = [{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "sources": ["arp"]}]
        hosts = {
            "192.168.1.10": {
                "hostnames": ["nas.local"],
                "mac": "aa:bb:cc:dd:ee:01",
                "ports": [{"port": 22, "proto": "tcp", "service": "ssh",
                           "product": "OpenSSH", "version": "9.6"}],
                "services": ["ssh"],
                "os": [{"name": "Linux", "accuracy": 95}],
                "scripts": {"nbstat": "NetBIOS name: NAS"},
            }
        }
        discovery.apply_nmap(devices, hosts)
        self.assertEqual(devices[0]["hostname"], "nas.local")
        self.assertEqual(devices[0]["services"], ["ssh"])
        self.assertEqual(devices[0]["os"], "Linux")
        self.assertIn("nmap", devices[0]["sources"])



def _udp_frame(src: str, dst: str, sport: int = 40000, dport: int = 443,
               payload: bytes = b"") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x00" * 12 + b"\x08\x00" + ip + udp


def _client_hello(sni: str) -> bytes:
    name = sni.encode()
    extension = (struct.pack("!H", 0x0000) + struct.pack("!H", len(name) + 5)
                 + struct.pack("!H", len(name) + 3) + b"\x00"
                 + struct.pack("!H", len(name)) + name)
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02\x00\x2f" + b"\x01\x00"
            + struct.pack("!H", len(extension)) + extension)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class MonitorParserTests(unittest.TestCase):
    def test_dns_question(self):
        query = (struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0)
                 + fingerprint.encode_name("www.tiktok.com")
                 + struct.pack("!HH", 1, 1))
        name, qtype = monitor_mod.parse_dns_question(query)
        self.assertEqual(name, "www.tiktok.com")
        self.assertEqual(qtype, 1)

    def test_tls_sni(self):
        self.assertEqual(monitor_mod.parse_tls_sni(_client_hello("api.tiktok.com")), "api.tiktok.com")
        self.assertEqual(monitor_mod.parse_tls_sni(b"not tls"), "")

    def test_http_host(self):
        payload = b"GET /feed HTTP/1.1\r\nHost: www.tiktok.com\r\n\r\n"
        self.assertEqual(monitor_mod.parse_http_host(payload), "www.tiktok.com")

    def test_capture_only_counts_inventoried_ips(self):
        capture = monitor_mod.PacketCapture("lo", {"domains": [], "keywords": []},
                                            {"10.0.0.5"})
        capture._handle(_udp_frame("10.0.0.5", "8.8.8.8"))
        capture._handle(_udp_frame("8.8.8.8", "10.0.0.5"))
        capture._handle(_udp_frame("1.1.1.1", "9.9.9.9"))
        self.assertEqual(set(capture.counters.keys()), {"10.0.0.5"})
        self.assertGreater(capture.counters["10.0.0.5"]["tx"], 0)
        self.assertGreater(capture.counters["10.0.0.5"]["rx"], 0)
        self.assertEqual(capture.snapshot()["scope"], 1)

    def test_policy_match_creates_alert(self):
        capture = monitor_mod.PacketCapture("lo", {"domains": ["tiktok.com"], "keywords": ["torrent"]})
        capture._match_policy("10.0.0.2", "www.tiktok.com", "dns")
        capture._match_policy("10.0.0.2", "tracker.torrent-site.net", "sni")
        capture._match_policy("10.0.0.3", "example.org", "dns")
        self.assertEqual(len(capture.alerts), 2)
        self.assertEqual(capture.alerts[0]["match"], "tiktok.com")


    def test_capture_start_with_fake_socket(self):
        class FakeSocket:
            def __init__(self):
                self.options = []
            def bind(self, *args):
                pass
            def setsockopt(self, *args):
                self.options.append(args)
            def settimeout(self, *args):
                pass
            def recv(self, *args):
                raise socket.timeout
            def close(self):
                pass

        fake = FakeSocket()
        with mock.patch.object(monitor_mod.socket, "socket", return_value=fake), \
             mock.patch.object(monitor_mod.socket, "if_nametoindex", return_value=1):
            capture = monitor_mod.PacketCapture("lo", {"domains": [], "keywords": []})
            ok, message = capture.start()
            self.assertTrue(ok, message)
            capture.stop()
        self.assertTrue(any(opt[0] == monitor_mod.SOL_PACKET for opt in fake.options))
        self.assertIsInstance(monitor_mod.SOL_PACKET, int)



class MonitorScopeTests(unittest.TestCase):
    def test_scope_keeps_only_online_local_ips(self):
        tmp = Path(tempfile.mkdtemp(prefix="cutoff-scope-"))
        store = store_mod.Store(tmp / "devices.json", tmp / "events.jsonl")
        store.upsert_scan([
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2"},
            {"mac": "aa:bb:cc:dd:ee:02", "ip": "10.0.0.3"},
            {"mac": "aa:bb:cc:dd:ee:03", "ip": "10.9.0.2"},
        ])
        store.upsert_scan([{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2"}])
        interface = type("Iface", (), {"ip": "10.0.0.5", "prefix": 24})()
        monitor = monitor_mod.NetworkMonitor(store)
        self.assertEqual(monitor._scope_ips(interface), {"10.0.0.2"})


class ToolPresetTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp(prefix="cutoff-tools-"))
        self.store = store_mod.Store(tmp / "devices.json", tmp / "events.jsonl")
        self.store.upsert_scan([{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2"}])
        self.iface = type("Iface", (), {
            "ip": "10.0.0.5", "prefix": 24, "network": "10.0.0.0/24",
            "gateway": "10.0.0.1",
        })()
        self.runner = nmapgui.NmapRunner(self.store)

    def test_nmap_presets_and_targets(self):
        presets = self.runner.presets()
        self.assertTrue(any(p["id"] == "fast" for p in presets))
        self.assertTrue(any(p["id"] == "os" and p["needs_root"] for p in presets))
        targets = self.runner.targets(self.iface)
        self.assertTrue(any(t["id"] == "subnet" for t in targets))
        self.assertTrue(any(t["id"] == "device:10.0.0.2" for t in targets))

    def test_nmap_target_validation(self):
        self.assertEqual(self.runner._resolve("subnet", "", self.iface), "10.0.0.0/24")
        self.assertEqual(self.runner._resolve("custom", "10.0.0.9", self.iface), "10.0.0.9")
        self.assertEqual(self.runner._resolve("device:10.0.0.2", "", self.iface), "10.0.0.2")
        with self.assertRaises(ValueError):
            self.runner._resolve("custom", "8.8.8.8", self.iface)
        with self.assertRaises(ValueError):
            self.runner._resolve("device:10.9.9.9", "", self.iface)

    def test_bettercap_presets(self):
        caps = bettercap_ctl.capabilities()
        for key in ("available", "path", "version", "privileged", "presets", "note"):
            self.assertIn(key, caps)
        ids = {p["id"] for p in caps["presets"]}
        self.assertIn("recon", ids)
        self.assertIn("monitor", ids)

    def test_nmap_extraports_closed_counts_as_responsive(self):
        xml = """<nmaprun><host><status state="up" reason="user-set"/>
          <address addr="10.0.0.2" addrtype="ipv4"/>
          <ports><extraports state="closed" count="100"/></ports></host></nmaprun>"""
        host = nmapscan.parse_xml(xml)["10.0.0.2"]
        self.assertTrue(host["responsive"])

    def test_nmap_extraports_filtered_is_not_responsive(self):
        xml = """<nmaprun><host><status state="up" reason="user-set"/>
          <address addr="10.0.0.3" addrtype="ipv4"/>
          <ports><extraports state="filtered" count="100"/></ports></host></nmaprun>"""
        host = nmapscan.parse_xml(xml)["10.0.0.3"]
        self.assertFalse(host["responsive"])

    def test_touch_hosts_marks_device_online(self):
        tmp = Path(tempfile.mkdtemp(prefix="cutoff-touch-"))
        st = store_mod.Store(tmp / "devices.json", tmp / "events.jsonl")
        st.upsert_scan([{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2"}])
        st.upsert_scan([])
        self.assertFalse(st.get("aa:bb:cc:dd:ee:01")["active"])
        touched = st.touch_hosts([{"ip": "10.0.0.2", "hostnames": ["phone"]}])
        self.assertEqual(touched, 1)
        self.assertTrue(st.get("aa:bb:cc:dd:ee:01")["active"])

class WindowsAdapterTests(unittest.TestCase):
    def test_firewall_rules_use_ip_and_strip_colons(self):
        fw = firewall_win.WindowsFirewall(simulate=True)
        fw.privileged = True
        result = fw.block("aa:bb:cc:dd:ee:01", "10.0.0.2", "both")
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["applied"]), 2)
        self.assertIn("winfw:ip-in", result["applied"])
        self.assertIn("winfw:ip-out", result["applied"])
        self.assertIn("CUTOFF-aabbccddee01-10.0.0.2-in",
                      " ".join(fw.last_commands) or "CUTOFF-aabbccddee01-10.0.0.2-in")

    def test_firewall_commands_are_ip_rules(self):
        fw = firewall_win.WindowsFirewall(simulate=False)
        fw.privileged = True
        calls = []
        fw._run = lambda args, timeout=20: (calls.append(args) or (0, "", ""))
        fw._rule_exists = lambda name: False
        result = fw.block("aa:bb:cc:dd:ee:01", "10.0.0.2", "both")
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 2)
        self.assertIn("remoteip=10.0.0.2", calls[0])
        self.assertIn("dir=in", calls[0])
        self.assertIn("dir=out", calls[1])

    def test_firewall_rejects_mac_only(self):
        fw = firewall_win.WindowsFirewall(simulate=True)
        result = fw.block("aa:bb:cc:dd:ee:01", "10.0.0.2", "mac")
        self.assertFalse(result["ok"])
        self.assertIn("by IP", result["error"])

    def test_windows_neighbour_parser(self):
        original = platform_ops.IS_WINDOWS
        original_ps = platform_ops.powershell
        platform_ops.IS_WINDOWS = True
        platform_ops.powershell = lambda script, timeout=15: (
            0, '[{"IPAddress":"10.0.0.1","LinkLayerAddress":"AA-BB-CC-DD-EE-01"}]', "")
        try:
            table = netinfo.neighbour_table("Ethernet")
        finally:
            platform_ops.IS_WINDOWS = original
            platform_ops.powershell = original_ps
        self.assertEqual(table["10.0.0.1"], "aa:bb:cc:dd:ee:01")


class GatewayModeTests(unittest.TestCase):
    def test_lan_gateway_pairs(self):
        gateway = arpguard.LanGateway(
            "eno1", "10.0.0.5", "aa:aa:aa:aa:aa:aa",
            "10.0.0.1", "bb:bb:bb:bb:bb:bb",
            [("10.0.0.9", "cc:cc:cc:cc:cc:cc"), ("10.0.0.10", "dd:dd:dd:dd:dd:dd")],
        )
        self.assertEqual(len(gateway.clients), 2)
        self.assertEqual(len(gateway.pairs), 4)
        destinations = {(p["dst_mac"], p["spoof_ip"]) for p in gateway.pairs}
        self.assertIn(("cc:cc:cc:cc:cc:cc", "10.0.0.1"), destinations)
        self.assertIn(("bb:bb:bb:bb:bb:bb", "10.0.0.9"), destinations)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cutoff-store-"))
        self.store = store_mod.Store(self.dir / "devices.json", self.dir / "events.jsonl")

    def test_norm_mac(self):
        self.assertEqual(store_mod.norm_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(store_mod.norm_mac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff")
        with self.assertRaises(ValueError):
            store_mod.norm_mac("not-a-mac")

    def test_scan_merge_and_offline(self):
        new = self.store.upsert_scan([
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2", "vendor": "Test"},
        ])
        self.assertEqual(new, 1)
        self.assertEqual(self.store.devices()[0]["active"], True)
        self.store.upsert_scan([{"mac": "aa:bb:cc:dd:ee:02", "ip": "10.0.0.3"}])
        by_mac = {d["mac"]: d for d in self.store.devices()}
        self.assertFalse(by_mac["aa:bb:cc:dd:ee:01"]["active"])
        self.assertTrue(by_mac["aa:bb:cc:dd:ee:02"]["active"])

    def test_names_blocks_events(self):
        self.store.upsert_scan([{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2"}])
        self.store.set_name("aa:bb:cc:dd:ee:01", "Desk lamp")
        self.assertEqual(self.store.get("aa:bb:cc:dd:ee:01")["name"], "Desk lamp")
        self.store.add_block("aa:bb:cc:dd:ee:01", "both", True, "host", "full")
        block = self.store.block_for("aa:bb:cc:dd:ee:01")
        self.assertIsNotNone(block)
        self.assertEqual(block["isolation"], "full")
        self.store.log("block", "test", mac="aa:bb:cc:dd:ee:01", simulated=True)
        events = self.store.events()
        self.assertEqual(events[0]["kind"], "block")
        self.store.remove_block("aa:bb:cc:dd:ee:01")
        self.assertIsNone(self.store.block_for("aa:bb:cc:dd:ee:01"))

    def test_persistence_reload(self):
        self.store.upsert_scan([{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2"}])
        self.store.set_name("aa:bb:cc:dd:ee:01", "keep me")
        reloaded = store_mod.Store(self.dir / "devices.json", self.dir / "events.jsonl")
        self.assertEqual(reloaded.get("aa:bb:cc:dd:ee:01")["name"], "keep me")

    def test_block_removal_persists(self):
        self.store.add_block("aa:bb:cc:dd:ee:01", "both", True, "host")
        self.store.remove_block("aa:bb:cc:dd:ee:01")
        reloaded = store_mod.Store(self.dir / "devices.json", self.dir / "events.jsonl")
        self.assertIsNone(reloaded.block_for("aa:bb:cc:dd:ee:01"))

    def test_rich_metadata_persists(self):
        self.store.upsert_scan([{
            "mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2",
            "ports": [{"port": 22, "proto": "tcp", "service": "ssh"}],
            "names": {"mdns": "Living Room TV", "netbios": "TV-PC"},
            "info": {"mdns": {"names": ["Living Room TV"]}},
            "model": "X1", "device_type": "tv", "sources": ["arp", "nmap"],
        }])
        reloaded = store_mod.Store(self.dir / "devices.json", self.dir / "events.jsonl")
        device = reloaded.get("aa:bb:cc:dd:ee:01")
        self.assertEqual(device["ports"][0]["service"], "ssh")
        self.assertEqual(device["names"]["mdns"], "Living Room TV")
        self.assertEqual(device["device_type"], "tv")
        self.assertIn("nmap", device["sources"])


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.fw = firewall.Firewall(simulate=False)
        self.fw.privileged = True
        self.commands: list[list[str]] = []

        def fake_run(binary, args, timeout=15.0):
            self.commands.append([binary] + args)
            if args[:1] == ["-S"]:
                return 0, "\n".join([
                    "-N CUTOFF_BLOCK",
                    "-A CUTOFF_BLOCK -m mac --mac-source aa:bb:cc:dd:ee:01 "
                    "-m comment --comment CUTOFF:aa:bb:cc:dd:ee:01:l2 -j DROP",
                    "-A CUTOFF_BLOCK -s 10.0.0.2 "
                    "-m comment --comment CUTOFF:aa:bb:cc:dd:ee:01:l3 -j DROP",
                ]), ""
            if args[:1] == ["-N"]:
                return 0, "", ""
            if args[:1] == ["-C"]:
                if args[1] in ("INPUT", "FORWARD"):
                    return 1, "", "jump missing"
                return (0, "", "") if " ".join(args[1:]) in self.rules else (1, "", "")
            if args[:1] == ["-A"]:
                self.rules.add(" ".join(args[1:]))
                return 0, "", ""
            return 0, "", ""

        self.rules: set[str] = set()
        self.fw._run = fake_run  # type: ignore[method-assign]

    def test_block_builds_mac_and_ip_rules(self):
        result = self.fw.block("aa:bb:cc:dd:ee:01", "10.0.0.2", "both")
        self.assertTrue(result["ok"])
        joined = " ".join(" ".join(c) for c in self.commands)
        self.assertIn("--mac-source aa:bb:cc:dd:ee:01", joined)
        self.assertIn("-s 10.0.0.2", joined)
        self.assertIn("-d 10.0.0.2", joined)
        self.assertIn("ipv4:l2", result["applied"])
        self.assertIn("ipv4:l3", result["applied"])
        self.assertIn("ipv6:l2", result["applied"])

    def test_chain_is_created_and_hooked(self):
        self.fw.ensure()
        creates = [c for c in self.commands if "-N" in c]
        families = len([b for b in (self.fw.ipt, self.fw.ip6t) if b])
        self.assertEqual(len(creates), 2 * families)  # CUTOFF_BLOCK + CUTOFF_OUT
        self.assertTrue(any("INPUT" in c and "-I" in c for c in self.commands))
        self.assertTrue(any("FORWARD" in c and "-I" in c for c in self.commands))
        # The MAC-bearing chain must never be reachable from OUTPUT.
        self.assertFalse(any("OUTPUT" in c and "-I" in c and firewall.CHAIN in c
                             for c in self.commands))
        self.assertTrue(any("OUTPUT" in c and "-I" in c and firewall.CHAIN_OUT in c
                            for c in self.commands))

    def test_unblock_deletes_tagged_rules_only(self):
        result = self.fw.unblock("aa:bb:cc:dd:ee:01")
        self.assertTrue(result["ok"])
        deletes = [c for c in self.commands if "-D" in c]
        families = len([b for b in (self.fw.ipt, self.fw.ip6t) if b])
        # 2 tagged rules × (CUTOFF_BLOCK, CUTOFF_OUT, NPENT_BLOCK, NPENT_OUT)
        self.assertEqual(len(deletes), 8 * families)
        self.assertTrue(all("CUTOFF:aa:bb:cc:dd:ee:01" in " ".join(c) for c in deletes))

    def test_simulation_never_touches_kernel(self):
        fw = firewall.Firewall(simulate=True)
        result = fw.block("aa:bb:cc:dd:ee:01", "10.0.0.2", "both")
        self.assertTrue(result["ok"])
        self.assertTrue(result["simulated"])
        self.assertEqual(fw.last_commands, [])

    def test_simulation_models_rules_for_display(self):
        fw = firewall.Firewall(simulate=True)
        fw.block("aa:bb:cc:dd:ee:01", "10.0.0.2", "both", ip6=["2001:db8::7"])
        rules = fw.list_rules()
        self.assertTrue(rules)
        self.assertTrue(all(r["simulated"] for r in rules))
        self.assertIn("ipv6", {r["family"] for r in rules})
        self.assertEqual(fw.status()["ipv6"]["rules"],
                         len([r for r in rules if r["family"] == "ipv6"]))
        fw.block_prefix("2001:db8:1::/64")
        self.assertEqual(fw.status()["ipv6"]["prefix_rules"], 2)  # BLOCK + OUT
        freed = fw.unblock_prefix("2001:db8:1::/64")
        self.assertEqual(len(freed["removed"]), 4)
        self.assertEqual(fw.status()["ipv6"]["prefix_rules"], 0)
        fw.panic()
        self.assertEqual(fw.list_rules(), [])


class ArpTests(unittest.TestCase):
    def test_reply_frame_layout(self):
        frame = arpguard.arp_reply(
            dst_mac="aa:bb:cc:dd:ee:02",
            src_mac="11:22:33:44:55:66",
            sender_ip="10.0.0.1",
            sender_mac="11:22:33:44:55:66",
            target_ip="10.0.0.9",
            target_mac="aa:bb:cc:dd:ee:02",
        )
        self.assertEqual(len(frame), 42)
        self.assertEqual(frame[12:14], b"\x08\x06")
        self.assertEqual(int.from_bytes(frame[20:22], "big"), 2)   # reply
        self.assertEqual(frame[22:28], bytes.fromhex("112233445566"))
        self.assertEqual(frame[28:32], bytes.fromhex("0a000001"))
        self.assertEqual(frame[38:42], bytes.fromhex("0a000009"))

    def test_refuses_own_mac(self):
        interceptor = arpguard.ArpInterceptor(
            "eno1", "10.0.0.5", "aa:aa:aa:aa:aa:aa",
            "10.0.0.1", "bb:bb:bb:bb:bb:bb", "10.0.0.9", "aa:aa:aa:aa:aa:aa",
        )
        ok, message = interceptor.start()
        self.assertFalse(ok)
        self.assertIn("own MAC", message)

    def test_refuses_forwarding_host(self):
        interceptor = arpguard.ArpInterceptor(
            "eno1", "10.0.0.5", "aa:aa:aa:aa:aa:aa",
            "10.0.0.1", "bb:bb:bb:bb:bb:bb", "10.0.0.9", "cc:cc:cc:cc:cc:cc",
        )
        original = arpguard.ip_forward_enabled
        arpguard.ip_forward_enabled = lambda: True
        try:
            ok, message = interceptor.start()
            self.assertFalse(ok)
            self.assertIn("ip_forward", message)
        finally:
            arpguard.ip_forward_enabled = original

    def test_blackhole_pairs_cover_both_directions_and_peers(self):
        blackhole = arpguard.ArpBlackhole(
            "eno1", "10.0.0.5", "aa:aa:aa:aa:aa:aa",
            "10.0.0.1", "bb:bb:bb:bb:bb:bb",
            "10.0.0.9", "cc:cc:cc:cc:cc:cc",
            peers=[("10.0.0.3", "dd:dd:dd:dd:dd:dd")], total=True,
        )
        self.assertEqual(len(blackhole.pairs), 4)
        pairs = {(p["dst_mac"], p["spoof_ip"]) for p in blackhole.pairs}
        self.assertIn(("cc:cc:cc:cc:cc:cc", "10.0.0.1"), pairs)   # victim -> gateway
        self.assertIn(("bb:bb:bb:bb:bb:bb", "10.0.0.9"), pairs)   # gateway -> victim
        self.assertIn(("dd:dd:dd:dd:dd:dd", "10.0.0.9"), pairs)   # peer -> victim
        self.assertIn(("cc:cc:cc:cc:cc:cc", "10.0.0.3"), pairs)   # victim -> peer

    def test_blackhole_internet_only_has_two_pairs(self):
        blackhole = arpguard.ArpBlackhole(
            "eno1", "10.0.0.5", "aa:aa:aa:aa:aa:aa",
            "10.0.0.1", "bb:bb:bb:bb:bb:bb",
            "10.0.0.9", "cc:cc:cc:cc:cc:cc",
            peers=[("10.0.0.3", "dd:dd:dd:dd:dd:dd")], total=False,
        )
        self.assertEqual(len(blackhole.pairs), 2)


class EnforcerTests(unittest.TestCase):
    def test_restore_blocks_skips_in_simulation(self):
        tmp = Path(tempfile.mkdtemp(prefix="cutoff-enf-"))
        st = store_mod.Store(tmp / "devices.json", tmp / "events.jsonl")
        st.upsert_scan([{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2"}])
        st.add_block("aa:bb:cc:dd:ee:01", "both", True, "host")
        enf = enforcer_mod.Enforcer(st, firewall.Firewall(simulate=True), None, True)
        result = enf.restore_blocks()
        self.assertTrue(result["simulated"])
        self.assertEqual(result["restored"], 0)


class WifiTests(unittest.TestCase):
    def test_deauth_frame(self):
        frame = wifi._deauth_frame("aa:bb:cc:dd:ee:02", "11:22:33:44:55:66")
        self.assertEqual(len(frame), 34)
        self.assertEqual(frame[8:10], b"\xc0\x00")
        self.assertEqual(frame[12:18], bytes.fromhex("aabbccddee02"))
        self.assertEqual(frame[18:24], bytes.fromhex("112233445566"))
        self.assertEqual(int.from_bytes(frame[32:34], "little"), 7)

    def test_capabilities_shape(self):
        caps = wifi.capabilities()
        for key in ("wireless_interfaces", "monitor_interfaces", "can_deauth", "note"):
            self.assertIn(key, caps)


class DiscoveryTests(unittest.TestCase):
    def test_arp_request_encodes_target(self):
        frame = discovery._arp_request(
            bytes.fromhex("112233445566"), "10.0.0.5", "10.0.0.9"
        )
        self.assertEqual(len(frame), 42)
        self.assertEqual(frame[0:6], b"\xff" * 6)
        self.assertEqual(int.from_bytes(frame[20:22], "big"), 1)  # request
        self.assertEqual(frame[28:32], bytes.fromhex("0a000005"))
        self.assertEqual(frame[38:42], bytes.fromhex("0a000009"))

    def test_vendor_lookup(self):
        self.assertEqual(vendor_for("b8:27:eb:12:34:56"), "Raspberry Pi")
        self.assertEqual(vendor_for("3c:22:fb:00:00:01"), "Apple")
        self.assertIn("Private", vendor_for("ee:cc:d3:a5:5e:3f"))
        self.assertEqual(vendor_for("02:00:00:00:00:01"), "Private / randomised MAC")


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as app_mod
        cls.app_mod = app_mod
        app_mod.store.upsert_scan([
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2", "vendor": "Test Vendor"},
        ])
        cls.client = app_mod.app.test_client()

    def req(self, method, path, token="test-token-123", body=None):
        headers = {"X-API-Token": token} if token else {}
        return self.client.open(path, method=method, headers=headers, json=body)

    def test_health_open(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_index_injects_token_for_loopback(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"window.__CUTOFF_TOKEN__", response.data)
        self.assertIn(b"test-token-123", response.data)
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))


    def test_tool_pages_and_apis(self):
        self.assertEqual(self.client.get("/nmap").status_code, 200)
        self.assertEqual(self.client.get("/bettercap").status_code, 200)
        nmap_data = self.req("GET", "/api/nmap")
        self.assertEqual(nmap_data.status_code, 200)
        self.assertIn("presets", nmap_data.get_json())
        self.assertEqual(self.req("POST", "/api/nmap/run",
                                  body={"preset": "nope"}).status_code, 400)
        bc_data = self.req("GET", "/api/bettercap")
        self.assertEqual(bc_data.status_code, 200)
        self.assertIn("capabilities", bc_data.get_json())
        self.assertEqual(self.req("POST", "/api/bettercap/start",
                                  body={"preset": "nope"}).status_code, 400)

    def test_map_page_injects_token(self):
        response = self.client.get("/map")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"window.__CUTOFF_TOKEN__", response.data)
        self.assertIn(b"Network Map", response.data)

    def test_device_detail_route(self):
        device = self.req("GET", "/api/devices/aa:bb:cc:dd:ee:01")
        self.assertEqual(device.status_code, 200)
        self.assertEqual(device.get_json()["device"]["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(self.req("GET", "/api/devices/aa:bb:cc:dd:ee:99").status_code, 404)

    def test_status_requires_token(self):
        self.assertEqual(self.req("GET", "/api/status", token=None).status_code, 401)
        self.assertEqual(self.req("GET", "/api/status", token="wrong").status_code, 401)
        self.assertEqual(self.req("GET", "/api/status").status_code, 200)

    def test_block_unknown_and_invalid(self):
        r = self.req("POST", "/api/block", body={"mac": "nope", "mode": "both"})
        self.assertEqual(r.status_code, 400)
        r = self.req("POST", "/api/block",
                     body={"mac": "aa:aa:aa:aa:aa:aa", "mode": "both"})
        self.assertEqual(r.status_code, 400)

    def test_block_and_unblock_flow(self):
        r = self.req("POST", "/api/block",
                     body={"mac": "aa:bb:cc:dd:ee:01", "mode": "both"})
        self.assertEqual(r.status_code, 200)
        payload = r.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["simulated"])
        devices = self.req("GET", "/api/devices").get_json()["devices"]
        target = next(d for d in devices if d["mac"] == "aa:bb:cc:dd:ee:01")
        self.assertEqual(target["status"], "blocked")

        r = self.req("POST", "/api/unblock", body={"mac": "aa:bb:cc:dd:ee:01"})
        self.assertEqual(r.status_code, 200)
        devices = self.req("GET", "/api/devices").get_json()["devices"]
        target = next(d for d in devices if d["mac"] == "aa:bb:cc:dd:ee:01")
        self.assertEqual(target["status"], "active")

    def test_rename_validation(self):
        r = self.req("POST", "/api/devices/aa:bb:cc:dd:ee:01/name",
                     body={"name": "x" * 80})
        self.assertEqual(r.status_code, 400)
        r = self.req("POST", "/api/devices/aa:bb:cc:dd:ee:01/name",
                     body={"name": "Lab lamp"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["device"]["name"], "Lab lamp")

    def test_events_and_panic(self):
        self.assertEqual(self.req("GET", "/api/events").status_code, 200)
        r = self.req("POST", "/api/panic")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["devices_cleared"], 0)


class IPv6ParseTests(unittest.TestCase):
    ADDR_OUTPUT = """2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 fe80::65ba:3cad:b555:7759/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
    inet6 2001:db8:1:2::5/64 scope global dynamic mngtmpaddr noprefixroute
       valid_lft 2591963sec preferred_lft 604763sec
    inet6 2001:db8:1:2::5:9f3a/64 scope global temporary dynamic
       valid_lft 604799sec preferred_lft 86399sec
    inet6 fd12:3456:789a::9/64 scope global deprecated
       valid_lft 100sec preferred_lft 0sec
"""

    NEIGH_OUTPUT = """
fe80::1 lladdr aa:bb:cc:dd:ee:02 router REACHABLE
fe80::1 dev eno1 lladdr aa:bb:cc:dd:ee:01 router REACHABLE
fe80::99 dev eno1 FAILED
2001:db8:1:2::7 dev eno1 lladdr 11:22:33:44:55:66 STALE
ff02::1 dev eno1 lladdr 33:33:00:00:00:01 NOARP
"""

    def test_parse_addresses_classifies_and_flags(self):
        records = ipv6_mod.parse_addresses(self.ADDR_OUTPUT)
        self.assertEqual(len(records), 4)
        by_addr = {r["address"]: r for r in records}
        link = by_addr["fe80::65ba:3cad:b555:7759"]
        self.assertEqual(link["class"], "link-local")
        global_rec = by_addr["2001:db8:1:2::5"]
        self.assertEqual(global_rec["class"], "global")
        self.assertTrue(global_rec["dynamic"])
        self.assertEqual(global_rec["network"], "2001:db8:1:2::/64")
        temp = by_addr["2001:db8:1:2::5:9f3a"]
        self.assertTrue(temp["temporary"])
        self.assertEqual(by_addr["fd12:3456:789a::9"]["class"], "ula")
        self.assertTrue(by_addr["fd12:3456:789a::9"]["deprecated"])

    def test_parse_neighbours_keeps_macs_drops_failed_and_multicast(self):
        records = ipv6_mod.parse_neighbours(self.NEIGH_OUTPUT)
        macs = {r["ip"]: r["mac"] for r in records}
        # both forms appear: with "dev eno1" and without (dev-filtered output)
        self.assertEqual(macs["fe80::1"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(len([r for r in records if r["ip"] == "fe80::1"]), 2)
        self.assertEqual(macs["2001:db8:1:2::7"], "11:22:33:44:55:66")
        self.assertNotIn("fe80::99", macs)          # FAILED, no lladdr
        self.assertNotIn("ff02::1", macs)           # multicast is not a host
        router = next(r for r in records if r["ip"] == "fe80::1")
        self.assertTrue(router["router"])
        self.assertEqual(router["state"], "REACHABLE")

    def test_prefix_validation(self):
        self.assertEqual(str(ipv6_mod.valid_prefix("2001:db8:1:2::/64")),
                         "2001:db8:1:2::/64")
        # host bits are normalised away rather than rejected
        self.assertEqual(str(ipv6_mod.valid_prefix("2001:db8:1:2::5/64")),
                         "2001:db8:1:2::/64")
        for bad in ("10.0.0.0/8", "::/0", "2001:db8::/4", "2001:db8::1/128", "junk"):
            with self.assertRaises(ValueError):
                ipv6_mod.valid_prefix(bad)

    def test_is_host_rules(self):
        self.assertTrue(ipv6_mod.is_host("fe80::1"))
        self.assertTrue(ipv6_mod.is_host("2001:db8::1"))
        for bad in ("ff02::1", "::1", "::", "10.0.0.1", "nope"):
            self.assertFalse(ipv6_mod.is_host(bad), bad)

    def test_classify(self):
        self.assertEqual(ipv6_mod.classify("2001:db8::1"), "global")
        self.assertEqual(ipv6_mod.classify("fd00::1"), "ula")
        self.assertEqual(ipv6_mod.classify("fe80::1"), "link-local")
        self.assertEqual(ipv6_mod.classify("::1"), "loopback")
        self.assertEqual(ipv6_mod.classify("ff02::1"), "multicast")

    def test_attach_joins_by_mac_and_clears_stale(self):
        devices = [
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2", "ip6": ["2001:db8::dead"]},
            {"mac": "aa:bb:cc:dd:ee:02", "ip": "10.0.0.3"},
        ]
        with mock.patch.object(ipv6_mod, "neighbours", return_value=[
            {"ip": "2001:db8:1:2::7", "mac": "aa:bb:cc:dd:ee:01", "class": "global",
             "iface": "eno1", "state": "REACHABLE", "router": False},
            {"ip": "fe80::7", "mac": "aa:bb:cc:dd:ee:01", "class": "link-local",
             "iface": "eno1", "state": "STALE", "router": False},
        ]), mock.patch.object(ipv6_mod, "local_addresses", return_value=[]):
            stats = ipv6_mod.attach(devices, "eno1")
        self.assertEqual(stats["devices_with_ipv6"], 1)
        self.assertEqual(devices[0]["ip6"], ["2001:db8:1:2::7", "fe80::7"])
        self.assertEqual(devices[1]["ip6"], [])   # stale address cleared


class IPv6FirewallTests(unittest.TestCase):
    def setUp(self):
        self.fw = firewall.Firewall(simulate=False)
        self.fw.privileged = True
        self.commands: list[list[str]] = []
        self.rules: set[str] = set()          # "<binary>|-A ..." keys
        self.lines: dict[str, set[str]] = {}  # per-binary rule text for -S

        def fake_run(binary, args, timeout=15.0):
            self.commands.append([binary] + args)
            lines = self.lines.setdefault(binary or "", set())
            if args[:1] == ["-S"]:
                chain = args[1] if len(args) > 1 else ""
                return 0, "\n".join(sorted(l for l in lines if l.startswith(f"-A {chain} "))), ""
            if args[:1] in (["-N"], ["-I"], ["-F"], ["-X"]):
                return 0, "", ""
            # Key on the rule body so -C/-A/-D for the same rule collide.
            key = f"{binary}|{' '.join(args[1:])}"
            if args[:1] == ["-C"]:
                return (0, "", "") if key in self.rules else (1, "", "missing")
            if args[:1] == ["-A"]:
                self.rules.add(key)
                lines.add(" ".join(args))
                return 0, "", ""
            if args[:1] == ["-D"]:
                self.rules.discard(key)
                lines.discard(" ".join(args))
                return 0, "", ""
            return 1, "", ""

        self.fw._run = fake_run  # type: ignore[method-assign]

    def _cmds(self, binary_suffix: str) -> list[str]:
        return [c for c in self.commands
                if c[0] and c[0].endswith(binary_suffix)]

    def test_parse_tag_new_and_legacy(self):
        tag = firewall.parse_tag("CUTOFF:mac:aa:bb:cc:dd:ee:01:v6l3")
        self.assertEqual(tag, {"kind": "mac", "key": "aa:bb:cc:dd:ee:01", "scope": "v6l3"})
        pfx = firewall.parse_tag("CUTOFF:pfx:2001:db8:1::/64:pfxl3")
        self.assertEqual(pfx["kind"], "prefix")
        self.assertEqual(pfx["key"], "2001:db8:1::/64")
        # pre-rename rules must still parse so an upgrade can remove them
        pre = firewall.parse_tag("NPENT:mac:aa:bb:cc:dd:ee:01:v6l3")
        self.assertEqual(pre, {"kind": "mac", "key": "aa:bb:cc:dd:ee:01", "scope": "v6l3"})
        self.assertEqual(set(firewall.ALL_TAGS), {"CUTOFF:", "NPENT:"})
        legacy = firewall.parse_tag("CUTOFF:aa:bb:cc:dd:ee:01:l2")
        self.assertEqual(legacy, {"kind": "mac", "key": "aa:bb:cc:dd:ee:01", "scope": "l2"})
        self.assertIsNone(firewall.parse_tag("something else"))

    def test_block_writes_v6_mac_and_address_rules(self):
        result = self.fw.block("aa:bb:cc:dd:ee:01", "10.0.0.2", "both",
                               ip6=["2001:db8:1:2::7", "fe80::7"])
        self.assertTrue(result["ok"])
        self.assertIn("ipv6:l2", result["applied"])
        self.assertIn("ipv6:l3x2", result["applied"])
        self.assertEqual(result["ipv6"]["addresses_blocked"], 2)
        v6 = " ".join(" ".join(c) for c in self._cmds("ip6tables"))
        self.assertIn("--mac-source aa:bb:cc:dd:ee:01", v6)
        self.assertIn("-s 2001:db8:1:2::7", v6)
        self.assertIn("-d fe80::7", v6)
        self.assertIn("CUTOFF:mac:aa:bb:cc:dd:ee:01:v6l2", v6)
        # IPv6 addresses must never land in the IPv4 tool
        v4 = " ".join(" ".join(c) for c in self._cmds("iptables"))
        self.assertNotIn("2001:db8", v4)
        self.assertNotIn("fe80::", v4)

    def test_block_without_ip6tables_reports_unavailable(self):
        self.fw.ip6t = None
        result = self.fw.block("aa:bb:cc:dd:ee:01", "10.0.0.2", "both", ip6=["fe80::7"])
        self.assertTrue(result["ok"])
        self.assertIn("ipv6:unavailable", result["applied"])

    def test_prefix_block_and_unblock_are_precise(self):
        blocked = self.fw.block_prefix("2001:db8:1:2::/64")
        self.assertTrue(blocked["ok"])
        self.assertEqual(sorted(blocked["applied"]), ["pfxl3", "pfxout"])
        v6 = " ".join(" ".join(c) for c in self._cmds("ip6tables"))
        self.assertIn("-s 2001:db8:1:2::/64", v6)
        self.assertIn("-d 2001:db8:1:2::/64", v6)

        # a device block in the same chain must survive the prefix removal
        self.fw.block("aa:bb:cc:dd:ee:01", None, "mac")
        removed = self.fw.unblock_prefix("2001:db8:1:2::/64")
        self.assertTrue(removed["ok"])
        self.assertEqual(len(removed["removed"]), 4)
        self.assertTrue(any("CUTOFF:mac:" in r for r in self.rules))

    def test_rule_listing_tags_family_and_chain(self):
        self.lines.setdefault(self.fw.ip6t, set()).update({
            "-A CUTOFF_BLOCK -m mac --mac-source aa:bb:cc:dd:ee:01 "
            "-m comment --comment CUTOFF:mac:aa:bb:cc:dd:ee:01:v6l2 -j DROP",
            "-A CUTOFF_OUT -s 2001:db8::/64 "
            "-m comment --comment CUTOFF:pfx:2001:db8::/64:pfxout -j DROP",
        })
        rules = self.fw.list_rules()
        self.assertTrue(all(r["family"] == "ipv6" for r in rules))
        chains = {r["chain"] for r in rules}
        self.assertEqual(chains, {firewall.CHAIN, firewall.CHAIN_OUT})
        status = self.fw.status()
        self.assertEqual(status["ipv6"]["rules"], 2)
        self.assertEqual(status["ipv6"]["prefix_rules"], 1)
        self.assertTrue(status["ipv6"]["available"])


class IPv6EnforcerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cutoff-v6-"))
        self.store = store_mod.Store(self.tmp / "devices.json", self.tmp / "events.jsonl")
        self.store.upsert_scan([{
            "mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2",
            "ip6": ["2001:db8:1:2::7", "fe80::7"],
        }])
        self.iface = netinfo.Interface(
            name="eno1", ip="10.0.0.5", prefix=24, mac="aa:bb:cc:dd:ee:99",
            gateway="10.0.0.1", gateway_mac="11:22:33:44:55:66", wireless=False)
        self.enforcer = enforcer_mod.Enforcer(
            self.store, firewall.Firewall(simulate=True), self.iface, True)

    def test_block_carries_ipv6_addresses_into_rules_and_store(self):
        result = self.enforcer.block("aa:bb:cc:dd:ee:01", mode="both")
        self.assertTrue(result["ok"])
        self.assertEqual(result["ip6"], ["2001:db8:1:2::7", "fe80::7"])
        self.assertTrue(any(l.startswith("firewall:ipv6") for l in result["layers"]))
        stored = self.store.block_for("aa:bb:cc:dd:ee:01")
        self.assertEqual(stored["ip6"], ["2001:db8:1:2::7", "fe80::7"])

    def test_block_can_skip_ipv6(self):
        result = self.enforcer.block("aa:bb:cc:dd:ee:01", mode="both", ip6=False)
        self.assertTrue(result["ok"])
        self.assertEqual(result["ip6"], [])

    def test_block_pulls_ipv6_from_ndp_when_inventory_is_stale(self):
        # Inventory knows the device but no v6 address; the NDP cache does.
        self.store.upsert_scan([{"mac": "aa:bb:cc:dd:ee:03", "ip": "10.0.0.3", "ip6": []}])
        ndp = [{"ip": "2001:db8:1:2::9", "mac": "aa:bb:cc:dd:ee:03", "iface": "eno1",
                "state": "REACHABLE", "router": False, "class": "global"}]
        with mock.patch.object(ipv6_mod, "neighbours", return_value=ndp):
            result = self.enforcer.block("aa:bb:cc:dd:ee:03", mode="both")
        self.assertTrue(result["ok"])
        self.assertEqual(result["ip6"], ["2001:db8:1:2::9"])
        self.assertTrue(any(l == "firewall:ipv6:l2" for l in result["layers"]))

    def test_merged_block_installs_ipv4_and_ipv6_together(self):
        with mock.patch.object(ipv6_mod, "local_addresses", return_value=[]), \
             mock.patch.object(ipv6_mod, "neighbours", return_value=[]):
            result = self.enforcer.block("aa:bb:cc:dd:ee:01", mode="both")
        self.assertTrue(result["ok"])
        layers = result["layers"]
        self.assertTrue(any(l.startswith("firewall:ipv4") for l in layers))
        self.assertTrue(any(l.startswith("firewall:ipv6") for l in layers))
        self.assertTrue(any(l.startswith("arp-blackhole:") for l in layers))
        rules = self.enforcer.fw.list_rules()
        self.assertEqual({"ipv4", "ipv6"}, {r["family"] for r in rules})

    def test_prefix_option_covers_slaac_rotation(self):
        addr = "2001:db8:1:2::7"
        with mock.patch.object(ipv6_mod, "local_addresses", return_value=[]), \
             mock.patch.object(ipv6_mod, "neighbours", return_value=[]):
            result = self.enforcer.block("aa:bb:cc:dd:ee:01", mode="both", ip6_prefix=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["ip6_prefixes"], ["2001:db8:1:2::/64"])
        self.assertTrue(any(l.startswith("firewall:ipv6:prefix:") for l in result["layers"]))
        stored = self.store.block_for("aa:bb:cc:dd:ee:01")
        self.assertEqual(stored["ip6_prefix"], ["2001:db8:1:2::/64"])
        prec = self.enforcer.fw.status()["ipv6"]["prefix_rules"]
        self.assertEqual(prec, 2)  # CUTOFF_BLOCK + CUTOFF_OUT
        self.assertIn(addr, stored["ip6"])

        # unblock must remove the prefix rules it installed, not just the MAC
        freed = self.enforcer.unblock("aa:bb:cc:dd:ee:01")
        self.assertTrue(freed["ok"])
        self.assertEqual(self.enforcer.fw.status()["ipv6"]["prefix_rules"], 0)
        self.assertIsNone(self.store.block_for("aa:bb:cc:dd:ee:01"))

    def test_prefix_option_skips_link_local(self):
        self.store.upsert_scan([{"mac": "aa:bb:cc:dd:ee:04", "ip": "10.0.0.4",
                                 "ip6": ["fe80::4"]}])
        with mock.patch.object(ipv6_mod, "local_addresses", return_value=[]), \
             mock.patch.object(ipv6_mod, "neighbours", return_value=[]):
            result = self.enforcer.block("aa:bb:cc:dd:ee:04", mode="both", ip6_prefix=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["ip6_prefixes"], [])  # fe80::/64 is shared with us

    def test_prefix_option_refuses_prefix_containing_this_host(self):
        with mock.patch.object(ipv6_mod, "local_addresses",
                               return_value=[{"address": "2001:db8:1:2::5"}]), \
             mock.patch.object(ipv6_mod, "neighbours", return_value=[]):
            result = self.enforcer.block("aa:bb:cc:dd:ee:01", mode="both", ip6_prefix=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["ip6_prefixes"], [])
        self.assertTrue(any("contains this host" in w for w in result["warnings"]))

    def test_prefix_guard_refuses_own_address(self):
        with mock.patch.object(ipv6_mod, "local_addresses",
                               return_value=[{"address": "2001:db8:1:2::5"}]):
            refused = self.enforcer.block_ipv6_prefix("2001:db8:1:2::/64")
            self.assertFalse(refused["ok"])
            self.assertIn("own address", refused["error"])
            forced = self.enforcer.block_ipv6_prefix("2001:db8:1:2::/64", force=True)
            self.assertTrue(forced["ok"])
            self.assertTrue(forced["warnings"])

    def test_prefix_guard_rejects_wide_and_malformed(self):
        for bad in ("::/0", "10.0.0.0/8", "2001:db8::1/128"):
            self.assertFalse(self.enforcer.block_ipv6_prefix(bad)["ok"])

    def test_snapshot_shape(self):
        with mock.patch.object(ipv6_mod, "neighbours", return_value=[
            {"ip": "2001:db8:1:2::7", "mac": "aa:bb:cc:dd:ee:01", "iface": "eno1",
             "state": "REACHABLE", "router": False, "class": "global"},
        ]), mock.patch.object(ipv6_mod, "local_addresses", return_value=[
            {"address": "fe80::5", "prefix": 64, "scope": "link", "class": "link-local",
             "network": "fe80::/64", "dynamic": False, "temporary": False,
             "deprecated": False, "valid_lft": "", "preferred_lft": ""},
        ]):
            snap = self.enforcer.ipv6_snapshot()
        self.assertEqual(len(snap["neighbours"]), 1)
        self.assertTrue(snap["neighbours"][0]["known"])
        self.assertIn("capabilities", snap)
        self.assertEqual(snap["rules"], [])


class IPv6ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as app_mod
        cls.app_mod = app_mod
        app_mod.store.upsert_scan([{
            "mac": "aa:bb:cc:dd:ee:11", "ip": "10.0.0.11",
            "ip6": ["2001:db8:1:2::11"],
        }])
        cls.client = app_mod.app.test_client()

    def req(self, method, path, token="test-token-123", body=None):
        headers = {"X-API-Token": token} if token else {}
        return self.client.open(path, method=method, headers=headers, json=body)

    def test_page_and_token(self):
        page = self.client.get("/ipv6")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"window.__CUTOFF_TOKEN__", page.data)
        self.assertIn(b"ipv6.js", page.data)
        self.assertEqual(self.req("GET", "/api/ipv6", token=None).status_code, 401)

    def test_snapshot_endpoint(self):
        response = self.req("GET", "/api/ipv6")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        for key in ("supported", "addresses", "neighbours", "prefixes",
                    "capabilities", "rules"):
            self.assertIn(key, data)
        self.assertTrue(data["capabilities"]["simulated"])

    def test_block_and_unblock_with_ipv6(self):
        blocked = self.req("POST", "/api/ipv6/block",
                           body={"mac": "aa:bb:cc:dd:ee:11", "mode": "both"})
        self.assertEqual(blocked.status_code, 200)
        payload = blocked.get_json()
        self.assertTrue(payload["ip6"])
        self.assertIn("2001:db8:1:2::11", payload["ip6"])
        freed = self.req("POST", "/api/ipv6/unblock", body={"mac": "aa:bb:cc:dd:ee:11"})
        self.assertEqual(freed.status_code, 200)

    def test_prefix_endpoint_rejects_bad_input(self):
        for bad in ("", "10.0.0.0/8", "::/0", "2001:db8::1/128"):
            self.assertEqual(self.req("POST", "/api/ipv6/prefix",
                                      body={"prefix": bad}).status_code, 400)

    def test_prefix_endpoint_block_and_unblock(self):
        with mock.patch.object(ipv6_mod, "local_addresses", return_value=[]):
            blocked = self.req("POST", "/api/ipv6/prefix",
                               body={"prefix": "2001:db8:beef::/64"})
            self.assertEqual(blocked.status_code, 200)
            self.assertEqual(blocked.get_json()["prefix"], "2001:db8:beef::/64")
            freed = self.req("POST", "/api/ipv6/prefix/unblock",
                             body={"prefix": "2001:db8:beef::/64"})
            self.assertEqual(freed.status_code, 200)

    def test_block_accepts_prefix_option(self):
        with mock.patch.object(ipv6_mod, "local_addresses", return_value=[]), \
             mock.patch.object(ipv6_mod, "neighbours", return_value=[]):
            response = self.req("POST", "/api/block", body={
                "mac": "aa:bb:cc:dd:ee:11", "mode": "both",
                "ip6_prefix": True, "force": True,
            })
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ip6"])
        self.assertEqual(payload["ip6_prefixes"], ["2001:db8:1:2::/64"])
        self.req("POST", "/api/unblock", body={"mac": "aa:bb:cc:dd:ee:11"})

    def test_status_reports_ipv6_summary(self):
        response = self.req("GET", "/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("ipv6", response.get_json())


class StoreIPv6Tests(unittest.TestCase):
    def test_ipv6_addresses_persist_and_clear(self):
        tmp = Path(tempfile.mkdtemp(prefix="cutoff-store6-"))
        st = store_mod.Store(tmp / "devices.json", tmp / "events.jsonl")
        st.upsert_scan([{"mac": "aa:bb:cc:dd:ee:21", "ip": "10.0.0.21",
                         "ip6": ["2001:db8::21"]}])
        self.assertEqual(st.get("aa:bb:cc:dd:ee:21")["ip6"], ["2001:db8::21"])
        st.upsert_scan([{"mac": "aa:bb:cc:dd:ee:21", "ip": "10.0.0.21", "ip6": []}])
        self.assertEqual(st.get("aa:bb:cc:dd:ee:21")["ip6"], [])
        reloaded = store_mod.Store(tmp / "devices.json", tmp / "events.jsonl")
        self.assertIn("ip6", reloaded.get("aa:bb:cc:dd:ee:21"))


class NdpGuardTests(unittest.TestCase):
    """IPv6 layer 2: frame construction, pairing, and the forwarding guard."""

    OUR_MAC = "aa:aa:aa:aa:aa:aa"
    VICTIM_MAC = "cc:cc:cc:cc:cc:cc"
    ROUTER_MAC = "11:22:33:44:55:66"
    OUR_LL = "fe80::99"

    @staticmethod
    def _checksum_valid(frame: bytes) -> bool:
        ip = frame[14:54]
        icmp = frame[54:]
        pseudo = ip[8:24] + ip[24:40] + struct.pack("!I", len(icmp)) + b"\x00\x00\x00\x3a"
        data = pseudo + icmp
        if len(data) % 2:
            data += b"\x00"
        total = sum(struct.unpack(f"!{len(data) // 2}H", data))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return total == 0xFFFF

    def test_na_frame_fields_and_checksum(self):
        frame = ndpguard.na_frame(
            dst_mac=self.VICTIM_MAC, src_mac=self.OUR_MAC,
            src_ip=self.OUR_LL, dst_ip="fe80::7",
            target_ip="fe80::1", tll_mac=self.OUR_MAC)
        self.assertEqual(frame[12:14], b"\x86\xdd")
        self.assertEqual(frame[20], 58)          # ICMPv6
        self.assertEqual(frame[21], 255)         # NDP hop limit
        self.assertEqual(frame[54], 136)         # Neighbor Advertisement
        self.assertEqual(struct.unpack("!I", frame[58:62])[0], 0x20000000)  # O=1
        self.assertEqual(frame[62:78], socket.inet_pton(socket.AF_INET6, "fe80::1"))
        self.assertEqual(frame[78], 2)           # target link-layer option
        self.assertEqual(frame[80:86], bytes.fromhex(self.OUR_MAC.replace(":", "")))
        self.assertTrue(self._checksum_valid(frame))

    def test_ns_frame_fields_and_checksum(self):
        frame = ndpguard.ns_frame(
            dst_mac=self.VICTIM_MAC, src_mac=self.OUR_MAC,
            src_ip="2001:db8::9", dst_ip="fe80::7",
            target_ip="fe80::7", sll_mac=self.OUR_MAC)
        self.assertEqual(frame[54], 135)         # Neighbor Solicitation
        self.assertEqual(frame[58:62], b"\x00" * 4)
        self.assertEqual(frame[78], 1)           # source link-layer option
        self.assertTrue(self._checksum_valid(frame))

    def _blackhole(self, **kwargs):
        params = dict(
            iface="eno1", our_mac=self.OUR_MAC, our_ip6=self.OUR_LL,
            victim_mac=self.VICTIM_MAC,
            victim_addrs=["fe80::7", "2001:db8:1:2::7"],
            router_ip="fe80::1", router_mac=self.ROUTER_MAC,
        )
        params.update(kwargs)
        return ndpguard.NdpBlackhole(**params)

    def test_pairs_cover_router_in_both_directions(self):
        blackhole = self._blackhole()
        keys = {(p["dst_mac"], p["spoof_ip"]) for p in blackhole.pairs}
        self.assertEqual(len(blackhole.pairs), 3)
        self.assertIn((self.VICTIM_MAC, "fe80::1"), keys)
        self.assertIn((self.ROUTER_MAC, "fe80::7"), keys)
        self.assertIn((self.ROUTER_MAC, "2001:db8:1:2::7"), keys)

    def test_total_mode_poisons_known_peers(self):
        peers = [{"mac": "dd:dd:dd:dd:dd:dd", "dst": "fe80::d",
                  "addrs": ["fe80::d", "2001:db8:1:2::d"]}]
        blackhole = self._blackhole(peers=peers, total=True)
        # 1 victim->router + 2 router->victim + 2 victim->peer + 2 peer->victim
        self.assertEqual(len(blackhole.pairs), 7)
        self.assertEqual(blackhole.status()["peers"], 1)

    def test_peer_provider_adds_pairs_after_start(self):
        peers = [{"mac": "dd:dd:dd:dd:dd:dd", "dst": "fe80::d",
                  "addrs": ["fe80::d"]}]
        blackhole = self._blackhole(total=True, peer_provider=lambda: peers)
        before = len(blackhole.pairs)
        blackhole._refresh_peers()
        self.assertEqual(len(blackhole.pairs), before + 3)

    def test_start_refuses_forwarding_without_forward_drop(self):
        blackhole = self._blackhole()
        with mock.patch.object(ndpguard, "forwarding", return_value=True):
            ok, msg = blackhole.start()
        self.assertFalse(ok)
        self.assertIn("MITM", msg)

    def test_default_route_without_dev_group_is_parsed(self):
        # `ip -6 route show default dev X` omits "dev X" from its output.
        text = "default via fe80::1 proto ra metric 20100 pref medium\n"
        self.assertEqual(ipv6_mod.parse_default_route(text, "eno1"), "fe80::1")

    def test_default_route_skips_other_interfaces(self):
        text = "default via fe80::1 dev wlan0 proto ra\n"
        self.assertIsNone(ipv6_mod.parse_default_route(text, "eno1"))


class PeerRefreshTests(unittest.TestCase):
    """IPv4 peers that appear after the block must be added mid-flight."""

    def test_set_peers_rebuilds_pairs_and_primes_nothing_yet(self):
        blackhole = arpguard.ArpBlackhole(
            "eno1", "10.0.0.5", "aa:aa:aa:aa:aa:aa",
            "10.0.0.1", "bb:bb:bb:bb:bb:bb",
            "10.0.0.9", "cc:cc:cc:cc:cc:cc", total=True)
        self.assertEqual(len(blackhole.pairs), 2)
        fresh = blackhole.set_peers([("10.0.0.3", "dd:dd:dd:dd:dd:dd")])
        self.assertEqual(len(blackhole.pairs), 4)
        self.assertEqual(len(fresh), 4)  # every pair is unprimed on first sight
        self.assertEqual(len(blackhole.peers), 1)

    def test_identical_peer_list_is_a_noop(self):
        peers = [("10.0.0.3", "dd:dd:dd:dd:dd:dd")]
        blackhole = arpguard.ArpBlackhole(
            "eno1", "10.0.0.5", "aa:aa:aa:aa:aa:aa",
            "10.0.0.1", "bb:bb:bb:bb:bb:bb",
            "10.0.0.9", "cc:cc:cc:cc:cc:cc", peers=peers, total=True)
        self.assertEqual(blackhole.set_peers(peers), [])

    def test_arp_request_is_a_request_not_a_reply(self):
        frame = arpguard.arp_request(
            dst_mac="dd:dd:dd:dd:dd:dd", src_mac="aa:aa:aa:aa:aa:aa",
            sender_ip="10.0.0.9", sender_mac="aa:aa:aa:aa:aa:aa",
            target_ip="10.0.0.3", target_mac="dd:dd:dd:dd:dd:dd")
        self.assertEqual(frame[12:14], b"\x08\x06")
        self.assertEqual(struct.unpack("!H", frame[20:22])[0], 1)  # opcode request


class NdpEnforcerTests(unittest.TestCase):
    """The enforcer must start the v6 layer 2 cut and report it honestly."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cutoff-ndp-enf-"))
        self.store = store_mod.Store(self.tmp / "devices.json", self.tmp / "events.jsonl")
        self.store.upsert_scan([{
            "mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2",
            "ip6": ["2001:db8:1:2::7", "fe80::7"],
        }])
        self.iface = netinfo.Interface(
            name="eno1", ip="10.0.0.5", prefix=24, mac="aa:bb:cc:dd:ee:99",
            gateway="10.0.0.1", gateway_mac="11:22:33:44:55:66", wireless=False)
        self.enforcer = enforcer_mod.Enforcer(
            self.store, firewall.Firewall(simulate=True), self.iface, True)
        self.patches = [
            mock.patch.object(ipv6_mod, "local_addresses",
                              return_value=[{"address": "fe80::99",
                                             "class": "link-local"}]),
            mock.patch.object(ipv6_mod, "default_router", return_value="fe80::1"),
            mock.patch.object(ipv6_mod, "router_mac", return_value="11:22:33:44:55:66"),
            mock.patch.object(ipv6_mod, "neighbours", return_value=[
                {"ip": "fe80::7", "mac": "aa:bb:cc:dd:ee:01", "iface": "eno1",
                 "state": "REACHABLE", "router": False, "class": "link-local"}]),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in self.patches:
            patcher.stop()

    def test_block_starts_ndp_layer(self):
        result = self.enforcer.block("aa:bb:cc:dd:ee:01", mode="both")
        self.assertTrue(result["ok"])
        self.assertIn("ndp-blackhole:full", result["layers"])
        self.assertGreaterEqual(result["ndp"]["pairs"], 3)
        self.assertEqual(result["ndp"]["router"], "fe80::1")
        self.assertTrue(any("NDP black-hole" in w for w in result["warnings"]))
        self.assertFalse(any("need gateway/AP enforcement" in w
                             for w in result["warnings"]))

    def test_block_can_skip_ndp(self):
        result = self.enforcer.block("aa:bb:cc:dd:ee:01", mode="both", ip6_ndp=False)
        self.assertTrue(result["ok"])
        self.assertFalse(any(l.startswith("ndp-blackhole") for l in result["layers"]))

    def test_unblock_stops_ndp(self):
        self.enforcer.block("aa:bb:cc:dd:ee:01", mode="both")
        self.assertIn("aa:bb:cc:dd:ee:01", self.enforcer._ndp)
        self.enforcer.unblock("aa:bb:cc:dd:ee:01")
        self.assertNotIn("aa:bb:cc:dd:ee:01", self.enforcer._ndp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
