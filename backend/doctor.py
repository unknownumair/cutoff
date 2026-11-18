#!/usr/bin/env python3
"""CUTOFF doctor — verify live enforcement capability without touching devices.

Usage:
    sudo .venv/bin/python backend/doctor.py            # read-only checks
    sudo .venv/bin/python backend/doctor.py --apply    # add+remove a dummy rule

The --apply test uses 02:00:00:00:00:01 / 203.0.113.7 (TEST-NET-3), so no real
device is ever affected. Everything it creates is removed before exit.
"""
from __future__ import annotations

import argparse
import os
import sys
import textwrap

import arpguard
import ipv6
import netinfo
import platform_ops
import wifi
from firewall import create as create_firewall, privileges

DUMMY_MAC = "02:00:00:00:00:01"
DUMMY_IP = "203.0.113.7"      # RFC 5737 TEST-NET-3
DUMMY_IP6 = "2001:db8::7"     # RFC 3849 documentation prefix


def _tagged(rules: list[dict], mac: str) -> list[dict]:
    return [r for r in rules if r.get("kind") == "mac" and r.get("key") == mac]


def line(label: str, value: str) -> None:
    print(f"  {label:<22} {value}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="create and remove a dummy firewall rule")
    args = parser.parse_args()

    failures = 0
    print("\nCUTOFF doctor\n" + "=" * 52)

    can_enforce, how = privileges()
    line("user", f"{'administrator' if platform_ops.is_admin() else 'user'} "
                 f"({os.environ.get('USERNAME') or os.environ.get('USER', '?')})")
    line("privileges", f"{'yes' if can_enforce else 'no'} ({how})")
    if not can_enforce:
        failures += 1
        print(textwrap.indent(
            "! run with sudo for live scanning, firewall rules and deauth\n", "  "))

    interface = netinfo.current_interface()
    if interface:
        line("interface", f"{interface.name} · {interface.ip}/{interface.prefix}")
        line("network", interface.network)
        line("gateway", f"{interface.gateway or '—'} ({interface.gateway_mac or 'mac unknown'})")
        line("wireless", "yes" if interface.wireless else "no")
    else:
        failures += 1
        line("interface", "NO IPv4 DEFAULT ROUTE")

    caps = wifi.capabilities()
    line("wifi adapters", ", ".join(caps["wireless_interfaces"]) or "none")
    line("monitor adapters", ", ".join(caps["monitor_interfaces"]) or "none")
    line("hostapd_cli", "present" if caps["hostapd_cli"] else "absent")
    print(textwrap.indent(f"  deauth: {caps['note']}\n", ""))

    fw = create_firewall(simulate=False)
    if platform_ops.IS_WINDOWS:
        status = fw.status()
        line("firewall", f"Windows Firewall ({status['rules']} NPENT rules)")
        if not status["available"] or not status["privileged"]:
            failures += 1
    else:
        line("iptables", fw.ipt or "MISSING")
        line("ip6tables", fw.ip6t or "absent")
        if not fw.ipt:
            failures += 1
    if not platform_ops.IS_WINDOWS:
        iface_now = netinfo.current_interface()
        v6 = ipv6.status(iface_now.name if iface_now else "")
        addrs = v6["addresses"]
        global6 = [a for a in addrs if a["class"] == "global"]
        line("ipv6 stack", "on" if v6["supported"] and v6["enabled"] else "off/disabled")
        line("ipv6 addresses", f"{len(addrs)} ({len(global6)} global)")
        line("ipv6 prefixes", ", ".join(v6["prefixes"]) or "none")
        line("ndp neighbours", str(len(v6["neighbours"])))
        line("ipv6 forwarding", "enabled" if v6["forwarding"] else "disabled")
    line("ip_forward", "enabled (gateway path)" if arpguard.ip_forward_enabled()
         else "disabled (host path, arp interception)")

    if args.apply:
        print("\nApplying a dummy rule (IPv4 + IPv6)…")
        result = fw.block(DUMMY_MAC, DUMMY_IP, "both", ip6=[DUMMY_IP6])
        if result.get("ok"):
            rules = _tagged(fw.list_rules(), DUMMY_MAC)
            families = sorted({r["family"] for r in rules})
            line("rule applied", f"yes ({len(rules)} tagged rules: {', '.join(families) or 'none'})")
            if not rules:
                failures += 1
                line("verification", "FAILED — rule not found in chain")
            elif fw.ip6t and "ipv6" not in families:
                failures += 1
                line("ipv6 rule", "FAILED — no ip6tables rule was created")
        else:
            failures += 1
            line("rule applied", f"FAILED — {result.get('error')}")
        cleanup = fw.unblock(DUMMY_MAC)
        line("cleanup", "ok" if cleanup.get("ok") else f"FAILED — {cleanup.get('error')}")
        remaining = _tagged(fw.list_rules(), DUMMY_MAC)
        if remaining:
            failures += 1
            line("leftover rules", f"{len(remaining)} — run with --apply again or flush manually")

    print("=" * 52)
    print("RESULT:", "PASS" if failures == 0 else f"{failures} issue(s) found")
    print("Note: live ARP interception and deauth need a real target; this checks plumbing only.\n")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
