"""Enforcement orchestration: decide which layers can actually cut a device.

Layer map
---------
gateway/AP host : iptables INPUT+FORWARD drops (network-wide) + optional deauth
ordinary host   : iptables drops traffic to this host; ARP interception cuts the
                  device's internet; deauth only with an AP/monitor adapter

Every action returns the truth about what was applied, what was simulated and
what could not be done, so the dashboard never claims a block it did not make.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Any

import config
import ipv6
import netinfo
import platform_ops
import wifi

if platform_ops.IS_WINDOWS:
    import arpguard_win as arpguard
    ndpguard = None
else:
    import arpguard
    import ndpguard
from firewall import Firewall
from netinfo import Interface, local_macs, run
from store import Store, norm_mac

log = logging.getLogger("cutoff.enforcer")

MULTICAST_MACS = {"ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"}
# Upper bound on peers added to a black hole, to keep the frame rate sane.
_MAX_PEERS = 64


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


class Enforcer:
    def __init__(self, store: Store, firewall: Firewall, iface: Interface | None,
                 simulate: bool):
        self.store = store
        self.fw = firewall
        self.iface = iface
        self.simulate = simulate
        self._interceptors: dict[str, arpguard.ArpBlackhole] = {}
        self._ndp: dict[str, Any] = {}
        self._lock = threading.RLock()
        self.gateway_override = False

    # topology --------------------------------------------------------------
    def is_gateway(self) -> bool:
        """True when this host actually routes/APs for the LAN.

        ``ip_forward=1`` alone is not evidence — Docker and VPN clients set it
        on ordinary workstations — so require either an AP daemon or the LAN's
        default gateway being one of our own addresses/MACs. Monitor gateway
        mode sets ``gateway_override`` because it deliberately forwards.
        """
        if self.gateway_override:
            return True
        if self.iface:
            try:
                if self.iface.gateway and self.iface.gateway in netinfo.local_ipv4s():
                    return True
            except OSError:
                pass
            if (self.iface.gateway_mac and self.iface.mac
                    and self.iface.gateway_mac.lower() == self.iface.mac.lower()):
                return True
        if platform_ops.IS_WINDOWS:
            return False
        rc, out, _ = run(["sh", "-c", "pgrep -x hostapd >/dev/null && echo yes"])
        return rc == 0 and "yes" in out

    def topology(self) -> str:
        return "gateway" if self.is_gateway() else "host"

    def capabilities(self) -> dict:
        caps = wifi.capabilities()
        return {
            "platform": platform_ops.capabilities(),
            "topology": self.topology(),
            "simulated": self.simulate,
            "firewall": self.fw.status(),
            "wifi": caps,
            "interceptions": [i.status() for i in self._interceptors.values()],
            "ndp": [i.status() for i in self._ndp.values()],
        }

    # guardrails ------------------------------------------------------------
    def _guard(self, mac: str, force: bool) -> tuple[dict | None, str]:
        device = self.store.get(mac)
        if device is None:
            return None, "device not in inventory — scan the network first"
        own = local_macs()
        if mac in own:
            return None, "refusing to block this host's own interface"
        if mac in MULTICAST_MACS or mac.startswith("01:"):
            return None, "refusing to block a multicast/broadcast address"
        gw_mac = self.iface.gateway_mac.lower() if self.iface and self.iface.gateway_mac else None
        if gw_mac and mac == gw_mac and not force:
            return None, ("that MAC belongs to the default gateway; blocking it cuts the "
                          "whole network including this host (pass force=true to override)")
        return device, ""

    # block / unblock -------------------------------------------------------
    def block(self, mac: str, mode: str = "both", force: bool = False,
              isolation: str = "full", ip6: bool = True,
              ip6_prefix: bool = False, ip6_ndp: bool = True) -> dict:
        try:
            mac = norm_mac(mac)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if mode not in ("mac", "ip", "both"):
            return {"ok": False, "error": "mode must be mac, ip or both"}
        if isolation not in ("internet", "full"):
            return {"ok": False, "error": "isolation must be internet or full"}
        device, err = self._guard(mac, force)
        if device is None:
            return {"ok": False, "error": err}

        ip = device.get("ip") if _valid_ip(device.get("ip", "")) else None
        if mode in ("ip", "both") and not ip:
            return {"ok": False, "error": "no IP known for this device; scan again or use mode=mac"}

        # IPv6 addresses come from the NDP cache; MAC mode still needs the
        # per-address rules to catch the destination direction.
        warnings_pre: list[str] = []
        ip6_addrs: list[str] = []
        if ip6:
            for candidate in (device.get("ip6") or []):
                if ipv6.is_host(candidate) and candidate not in ip6_addrs:
                    ip6_addrs.append(candidate)
            if not ip6_addrs and self.iface:
                # The inventory may predate the device's first IPv6 packet; ask
                # the kernel's NDP cache directly so one click really covers
                # both families.
                for record in ipv6.neighbours(self.iface.name):
                    addr = record.get("ip") or ""
                    if (record.get("mac") or "").lower() == mac and ipv6.is_host(addr):
                        if addr not in ip6_addrs:
                            ip6_addrs.append(addr)
            ip6_addrs = ip6_addrs[:ipv6.MAX_ADDRS_PER_DEVICE]

        # Optionally cover the /64 so SLAAC privacy addresses that rotate after
        # the block stay dead. Link-local is skipped: fe80::/64 is shared with
        # this host, so "blocking the device's link-local prefix" blocks us.
        prefixes6: list[str] = []
        if ip6_prefix and ip6_addrs and not platform_ops.IS_WINDOWS:
            own = [a["address"] for a in ipv6.local_addresses(self.iface.name)] if self.iface else []
            for addr in ip6_addrs:
                if ipv6.classify(addr) not in ("global", "ula"):
                    continue
                candidate = ipv6.prefix_for(addr)
                if not candidate or candidate in prefixes6:
                    continue
                try:
                    net = ipv6.valid_prefix(candidate)
                except ValueError:
                    continue
                if any(ipaddr in net for ipaddr in (ipaddress.ip_address(a)
                                                   for a in own if ipv6.is_host(a))):
                    warnings_pre.append(f"ipv6: skipped {net} — contains this host")
                    continue
                prefixes6.append(str(net))

        layers: list[str] = []
        warnings: list[str] = []

        fw = self.fw.block(mac, ip, mode, ip6=ip6_addrs)
        warnings.extend(warnings_pre)
        if fw.get("ok"):
            layers.extend(f"firewall:{item}" for item in fw.get("applied", []))
        else:
            warnings.append(f"firewall: {fw.get('error', 'failed')}")
        if prefixes6 and fw.get("ok"):
            for prefix in prefixes6:
                pfx = self.fw.block_prefix(prefix)
                if pfx.get("ok"):
                    layers.append(f"firewall:ipv6:prefix:{prefix}")
                else:
                    warnings.append(f"ipv6 prefix {prefix}: {pfx.get('error', 'failed')}")
        if ip6_addrs and mode in ("ip", "both"):
            warnings.append(
                f"IPv6: blocked {len(ip6_addrs)} known address(es) by MAC and by "
                "address"
                + (f", plus the /64(s) {', '.join(prefixes6)}" if prefixes6 else "")
                + "; addresses the device picks up later are covered by the "
                "MAC rule only where this host sees the traffic")

        topology = self.topology()
        l2_blocked = any(str(layer).endswith(":l2") for layer in fw.get("applied", []))
        if topology != "gateway" and ip and mode in ("ip", "both"):
            if not fw.get("ok"):
                warnings.append("arp-blackhole: skipped — no firewall rule was installed")
            else:
                ok, msg = self._start_intercept(mac, ip, device["mac"],
                                                l2_blocked, isolation)
                if ok:
                    layers.append(f"arp-blackhole:{isolation}")
                    if isolation == "full":
                        warnings.append(
                            "IPv4 full isolation: gateway + every known LAN peer, "
                            f"peer list re-read every {int(config.PEER_REFRESH_SEC)}s")
                else:
                    warnings.append(f"arp-blackhole: {msg}")
        elif topology != "gateway" and mode == "mac":
            warnings.append(
                "MAC-only mode on a non-gateway host only filters traffic to this "
                "machine; choose 'both' + isolation=full for a complete block"
            )

        # IPv6 layer 2: NDP is the only thing on an ordinary host that can cut
        # traffic the router forwards for the victim. Best effort by nature —
        # report what really started, never pretend coverage.
        ndp_info: dict = {}
        if (ip6_ndp and ndpguard is not None and topology != "gateway"
                and mode in ("ip", "both") and ip6_addrs):
            ok, msg, ndp_info = self._start_ndp(mac, device, ip6_addrs,
                                                isolation, l2_blocked)
            if ok:
                layers.append(f"ndp-blackhole:{isolation}")
                warnings.append(
                    f"IPv6 layer 2: NDP black-hole over {len(ip6_addrs)} known "
                    "address(es) + the default router"
                    + ("; LAN peers are re-read from the neighbour cache and "
                       f"inventory every {int(config.PEER_REFRESH_SEC)}s"
                       if isolation == "full" else "")
                    + ". Off-link IPv6 stays dead even if the source address "
                      "rotates; peer-to-peer v6 is best-effort."
                )
            else:
                warnings.append(f"IPv6 layer 2 not active: {msg}")

        if (platform_ops.IS_WINDOWS and topology != "gateway" and ip
                and mode in ("ip", "both")
                and not any(str(layer).startswith("arp-blackhole:")
                            for layer in layers)
                and not self.simulate):
            # Windows Firewall only filters this PC; without the ARP cut the
            # device would keep browsing and the UI must not claim a block.
            self.fw.unblock(mac)
            return {
                "ok": False,
                "error": ("Windows could not start the ARP block; Windows Firewall "
                          "alone only filters this PC. Fix: run as Administrator, "
                          "install Npcap/scapy, disable IP forwarding, then retry. "
                          + "; ".join(warnings)),
                "warnings": warnings,
            }

        if not layers and not self.simulate:
            return {"ok": False, "error": "; ".join(warnings) or "no enforcement layer available",
                    "warnings": warnings}

        block = self.store.add_block(mac, mode, self.simulate, topology, isolation,
                                     ip6=ip6_addrs, ip6_prefix=prefixes6)
        self.store.log(
            "block",
            f"blocked {mac} ({isolation})"
            + (f" incl. {len(ip6_addrs)} IPv6 address(es)" if ip6_addrs else "")
            + (" (simulated)" if self.simulate else ""),
            mac=mac, ok=True, simulated=self.simulate,
        )
        return {
            "ok": True,
            "mac": mac,
            "ip": ip,
            "ip6": ip6_addrs,
            "ip6_prefixes": prefixes6,
            "ndp": ndp_info,
            "mode": mode,
            "isolation": isolation,
            "topology": topology,
            "layers": layers,
            "warnings": warnings,
            "simulated": self.simulate,
            "block": block,
        }

    def _peer_list(self, victim_mac: str) -> list[tuple[str, str]]:
        """Active LAN peers (ip, mac) for full L2 isolation, minus self/gateway."""
        own = local_macs()
        gw_mac = (self.iface.gateway_mac.lower()
                  if self.iface and self.iface.gateway_mac else None)
        peers: dict[str, str] = {}
        for device in self.store.devices():
            mac = (device.get("mac") or "").lower()
            ip = device.get("ip") or ""
            if not mac or not _valid_ip(ip):
                continue
            if mac == victim_mac or mac in own or mac == gw_mac:
                continue
            recent = (time.time() - float(device.get("last_seen_epoch") or 0)
                      ) <= config.RECENT_WINDOW_SEC
            if not (device.get("active") or recent):
                continue
            peers[ip] = mac
        return list(peers.items())

    # peer refresh + IPv6 layer 2 -------------------------------------------
    def _peer_provider(self, victim_mac: str):
        """Live IPv4 peer list: inventory plus the kernel neighbour table.

        Called from the poison thread every ``PEER_REFRESH_SEC``. The
        neighbour table catches a device that started talking to this host
        since the last scan; the inventory catches everything a scan found.
        """
        def provider() -> list[tuple[str, str]]:
            peers: dict[str, str] = {}
            for ip, mac in self._peer_list(victim_mac):
                peers[ip] = mac
            if self.iface:
                try:
                    live = netinfo.neighbour_table(self.iface.name)
                except OSError:
                    live = {}
                own = local_macs()
                gateway_mac = (self.iface.gateway_mac or "").lower()
                for ip, mac in live.items():
                    mac = (mac or "").lower()
                    if not _valid_ip(ip) or not mac:
                        continue
                    if mac in own or mac == gateway_mac or mac == victim_mac:
                        continue
                    peers.setdefault(ip, mac)
            return list(peers.items())[:_MAX_PEERS]
        return provider

    def _ndp_peers(self, victim_mac: str) -> list[dict]:
        """Known LAN peers that have an IPv6 address, grouped by MAC."""
        if not self.iface:
            return []
        own = local_macs()
        gateway_mac = (self.iface.gateway_mac or "").lower()
        grouped: dict[str, dict] = {}
        for record in ipv6.neighbours(self.iface.name):
            mac = (record.get("mac") or "").lower()
            addr = record.get("ip") or ""
            if not mac or not addr:
                continue
            if record.get("router"):
                continue
            if mac in own or mac == gateway_mac or mac == victim_mac:
                continue
            entry = grouped.setdefault(mac, {"mac": mac, "dst": "", "addrs": []})
            if addr not in entry["addrs"]:
                entry["addrs"].append(addr)
            if not entry["dst"] and addr.startswith("fe80:"):
                entry["dst"] = addr
        peers = []
        for entry in grouped.values():
            if not entry["dst"]:
                entry["dst"] = entry["addrs"][0]
            peers.append(entry)
        return peers[:_MAX_PEERS]

    def _start_ndp(self, mac: str, device: dict, ip6_addrs: list[str],
                   isolation: str, forward_blocked: bool
                   ) -> tuple[bool, str, dict]:
        if ndpguard is None:
            return False, "NDP enforcement is Linux-only", {}
        if not self.iface:
            return False, "no interface", {}
        name = self.iface.name
        own6 = [a["address"] for a in ipv6.local_addresses(name)
                if a.get("class") == "link-local"]
        if not own6:
            return False, "this host has no IPv6 link-local address", {}
        router = ipv6.default_router(name)
        if not router:
            return False, "no IPv6 default router on this link", {}
        router_mac = ipv6.router_mac(name, router, self.iface.gateway_mac)
        if not router_mac:
            return False, f"MAC for IPv6 router {router} is unknown", {}
        victim_addrs = list(dict.fromkeys(ip6_addrs))
        link_local = ipv6.link_local_for(name, device["mac"])
        if link_local and link_local not in victim_addrs:
            victim_addrs.append(link_local)
        if not victim_addrs:
            return False, "no IPv6 address known for the victim", {}
        if router in victim_addrs or (router_mac or "").lower() == device["mac"].lower():
            return False, ("the victim is the IPv6 default router; an NDP black hole "
                           "would only poison the router for itself"), {}
        try:
            interceptor = ndpguard.NdpBlackhole(
                iface=name,
                our_mac=self.iface.mac,
                our_ip6=own6[0],
                victim_mac=device["mac"],
                victim_addrs=victim_addrs[:ipv6.MAX_ADDRS_PER_DEVICE],
                router_ip=router,
                router_mac=router_mac,
                peers=self._ndp_peers(device["mac"]),
                total=isolation == "full",
                refresh=config.POISON_REFRESH_SEC,
                max_minutes=config.POISON_MAX_MIN,
                forward_blocked=forward_blocked,
                peer_provider=lambda: self._ndp_peers(device["mac"]),
                peer_refresh=config.PEER_REFRESH_SEC,
            )
        except (ValueError, IndexError) as exc:
            return False, f"invalid NDP parameters: {exc}", {}
        with self._lock:
            previous = self._ndp.pop(mac, None)
        if previous:
            previous.stop()
        if self.simulate:
            with self._lock:
                self._ndp[mac] = interceptor
            return (True, f"simulated NDP black-hole ({len(interceptor.pairs)} pairs)",
                    interceptor.status())
        ok, msg = interceptor.start()
        if ok:
            with self._lock:
                self._ndp[mac] = interceptor
            return True, msg, interceptor.status()
        return False, msg, {}

    def _start_intercept(self, mac: str, ip: str, device_mac: str,
                         forward_blocked: bool = False,
                         isolation: str = "full") -> tuple[bool, str]:
        if not self.iface or not self.iface.gateway or not self.iface.gateway_mac:
            return False, "gateway MAC unknown (neighbour table empty)"
        with self._lock:
            if mac in self._interceptors:
                return True, "already intercepting"
            total = isolation == "full"
            peers = self._peer_list(device_mac) if total else []
            interceptor = arpguard.ArpBlackhole(
                iface=self.iface.name,
                our_ip=self.iface.ip,
                our_mac=self.iface.mac,
                gateway_ip=self.iface.gateway,
                gateway_mac=self.iface.gateway_mac,
                victim_ip=ip,
                victim_mac=device_mac,
                peers=peers,
                total=total,
                refresh=config.POISON_REFRESH_SEC,
                max_minutes=config.POISON_MAX_MIN,
                forward_blocked=forward_blocked,
                peer_provider=self._peer_provider(device_mac) if total else None,
                peer_refresh=config.PEER_REFRESH_SEC,
            )
            if self.simulate:
                # No raw socket in simulation mode; record intent only.
                return True, (f"simulated black-hole ({len(interceptor.pairs)} pairs, "
                              f"total={total})")
            ok, msg = interceptor.start()
            if ok:
                self._interceptors[mac] = interceptor
            return ok, msg

    def block_ipv6_prefix(self, prefix: str, force: bool = False) -> dict:
        """Block a whole IPv6 prefix (typically a /64) on this host.

        Guards: the prefix must parse, must not be wider than /16, and must not
        contain an address of this host — blocking your own /64 locks the
        operator out of the link they are administering.
        """
        try:
            net = ipv6.valid_prefix(prefix)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        own = [a["address"] for a in ipv6.local_addresses(self.iface.name)] if self.iface else []
        inside = [addr for addr in own if ipv6.is_host(addr)
                  and ipaddress.ip_address(addr) in net]
        if inside and not force:
            return {
                "ok": False,
                "error": (f"{net} contains this host's own address(es) "
                          f"{', '.join(inside[:3])} — blocking it cuts this console "
                          "off the link (pass force=true to override)"),
            }
        result = self.fw.block_prefix(str(net))
        self.store.log(
            "ipv6",
            f"prefix {'blocked' if result.get('ok') else 'block failed'}: {net}"
            + (" (simulated)" if self.simulate else ""),
            ok=bool(result.get("ok")), simulated=self.simulate,
        )
        result["prefix"] = str(net)
        result["force"] = bool(force)
        result["warnings"] = (
            ["this prefix contains this host's own address — the console may go dark"]
            if inside else [])
        return result

    def unblock_ipv6_prefix(self, prefix: str) -> dict:
        try:
            net = ipv6.valid_prefix(prefix)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        result = self.fw.unblock_prefix(str(net))
        self.store.log("ipv6", f"prefix unblocked: {net}", ok=bool(result.get("ok")),
                       simulated=self.simulate)
        return result

    def ipv6_snapshot(self) -> dict:
        """Everything the /ipv6 page needs, in one payload."""
        name = self.iface.name if self.iface else ""
        snap = ipv6.status(name)
        rules = [r for r in self.fw.list_rules() if r.get("family") == "ipv6"]
        blocked_macs = set(self.store.blocks())
        inventory = {d.get("mac"): d for d in self.store.devices()}
        gw_mac = (self.iface.gateway_mac.lower()
                  if self.iface and self.iface.gateway_mac else None)
        for record in snap["neighbours"]:
            mac = record.get("mac") or ""
            device = inventory.get(mac)
            display = ((device or {}).get("name") or (device or {}).get("hostname") or "")
            if not display and mac and mac == gw_mac:
                display = "Gateway"
            if not display and (device or {}).get("is_self"):
                display = "This host"
            record["name"] = display
            record["known"] = device is not None
            record["blocked"] = mac in blocked_macs
            record["gateway"] = bool(gw_mac and mac == gw_mac)
            record["is_self"] = bool((device or {}).get("is_self"))
            record["ipv4"] = (device or {}).get("ip", "")
        snap["rules"] = rules
        seen_prefix: set[str] = set()
        snap["prefix_rules"] = []
        for rule in rules:
            if rule.get("kind") != "prefix" or rule["key"] in seen_prefix:
                continue
            seen_prefix.add(rule["key"])
            snap["prefix_rules"].append(rule)
        snap["blocked_devices"] = [
            {"mac": mac, "name": (inventory.get(mac) or {}).get("name", ""),
             "ip6": (block.get("ip6") or [])}
            for mac, block in self.store.blocks().items() if block.get("ip6")
        ]
        snap["capabilities"] = {
            "ip6tables": self.fw.status().get("ipv6", {}),
            "privileged": self.fw.privileged,
            "privilege_mode": self.fw.privilege_mode,
            "simulated": self.simulate,
            "can_block": self.fw.privileged or self.simulate,
        }
        return snap

    def unblock(self, mac: str) -> dict:
        try:
            mac = norm_mac(mac)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        with self._lock:
            interceptor = self._interceptors.pop(mac, None)
            ndp = self._ndp.pop(mac, None)
        if interceptor:
            interceptor.stop()
        if ndp:
            ndp.stop()
        record = self.store.block_for(mac) or {}
        fw = self.fw.unblock(mac)
        # Prefix rules are shared, not MAC-tagged: drop the ones this block
        # installed or they would outlive the unblock and isolate a whole /64.
        for prefix in record.get("ip6_prefix", []) or []:
            pfx = self.fw.unblock_prefix(prefix)
            fw.setdefault("removed", []).extend(pfx.get("removed", []))
        removed = self.store.remove_block(mac)
        self.store.log("unblock", f"unblocked {mac}", mac=mac,
                       ok=fw.get("ok", False), simulated=self.simulate)
        return {
            "ok": fw.get("ok", False) or removed is not None,
            "mac": mac,
            "removed_rules": fw.get("removed", []),
            "was_blocked": removed is not None,
            "error": fw.get("error", ""),
            "simulated": self.simulate,
        }

    def cut_wifi(self, mac: str, bssid: str | None, seconds: int) -> dict:
        try:
            mac = norm_mac(mac)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        device, err = self._guard(mac, force=False)
        if device is None:
            return {"ok": False, "error": err}
        if platform_ops.IS_WINDOWS:
            return {"ok": False, "error": ("Wi-Fi deauthentication is not supported on "
                                           "Windows; use Block (ARP + firewall) instead")}
        if self.simulate:
            self.store.log("wifi", f"simulated deauth for {mac}", mac=mac, simulated=True)
            return {
                "ok": True, "simulated": True, "method": "simulated",
                "detail": "deauth frames are not sent in simulation mode; "
                          "Block still models the traffic cut",
            }
        result = wifi.deauth(mac, bssid=bssid, seconds=seconds)
        self.store.log(
            "wifi",
            f"deauth {mac}: {'sent' if result.get('ok') else result.get('error', 'failed')}",
            mac=mac, ok=bool(result.get("ok")), simulated=False,
        )
        return result

    def restore_blocks(self) -> dict:
        """Re-apply persisted blocks after a restart (live mode only)."""
        if self.simulate:
            return {"restored": 0, "failed": [], "simulated": True}
        restored = 0
        failed: list[dict] = []
        for mac, block in self.store.blocks().items():
            result = self.block(mac, mode=block.get("mode", "both"), force=False,
                                isolation=block.get("isolation", "internet"))
            if result.get("ok"):
                restored += 1
            else:
                failed.append({"mac": mac, "error": result.get("error", "failed")})
        self.store.log("startup", f"reapplied {restored} persisted blocks",
                       ok=not failed, simulated=False)
        return {"restored": restored, "failed": failed, "simulated": False}

    def panic(self) -> dict:
        with self._lock:
            interceptors = list(self._interceptors.values())
            self._interceptors.clear()
            ndp_interceptors = list(self._ndp.values())
            self._ndp.clear()
        for interceptor in interceptors:
            try:
                interceptor.stop()
            except Exception:  # noqa: BLE001 - best effort restore
                log.exception("failed to restore interception")
        for interceptor in ndp_interceptors:
            try:
                interceptor.stop()
            except Exception:  # noqa: BLE001 - best effort restore
                log.exception("failed to restore NDP interception")
        fw = self.fw.panic()
        cleared = 0
        for mac in list(self.store.blocks()):
            if self.store.remove_block(mac):
                cleared += 1
        self.store.log("panic", f"restored network: {cleared} devices unblocked",
                       simulated=self.simulate)
        return {"ok": fw.get("ok", True), "interceptors_stopped": len(interceptors),
                "firewall": fw, "devices_cleared": cleared}
