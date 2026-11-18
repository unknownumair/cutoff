"""Windows Firewall enforcement (IP-level) via ``netsh advfirewall``.

Windows has no MAC-match firewall rule in the built-in product, so the MAC is
carried in the rule name (``CUTOFF-<mac>-<ip>-in``) and the actual filter is by
remote IPv4 address. The ARP layer (scapy/Npcap) supplies the LAN-wide cut.
"""
from __future__ import annotations

import logging
import re
import shutil
import threading

import platform_ops

log = logging.getLogger("cutoff.firewall.win")
TAG = "CUTOFF-"
LEGACY_TAG = "NPENT-"


class WindowsFirewall:
    def __init__(self, simulate: bool = False):
        self.netsh = shutil.which("netsh") or r"C:\Windows\System32\netsh.exe"
        self.privileged = platform_ops.is_admin()
        self.privilege_mode = "administrator" if self.privileged else "unprivileged"
        self.simulate = simulate
        self._lock = threading.RLock()
        self.last_commands: list[str] = []

    # plumbing --------------------------------------------------------------
    def _run(self, args: list[str], timeout: float = 20.0) -> tuple[int, str, str]:
        cmd = [self.netsh, "advfirewall", "firewall"] + args
        if self.simulate:
            log.info("simulate: %s", " ".join(cmd))
            return 0, "", ""
        self.last_commands.append(" ".join(cmd))
        self.last_commands = self.last_commands[-50:]
        return platform_ops.run(cmd, timeout=timeout)

    def ensure(self) -> tuple[bool, str]:
        if self.simulate:
            return True, "simulation (no firewall changes)"
        if not self.netsh:
            return False, "netsh not found"
        if not self.privileged:
            return False, "run CUTOFF as Administrator to change Windows Firewall rules"
        return True, "Windows Firewall ready"

    def _rule_name(self, mac: str, ip: str, direction: str) -> str:
        key = mac.lower().replace(":", "")
        # Rule names cannot carry IPv6 colons cleanly; map them to dashes.
        safe = (ip or "").replace(":", "-").replace("/", "_")
        return f"{TAG}{key}-{safe}-{direction}"

    # public ----------------------------------------------------------------
    def block(self, mac: str, ip: str | None, mode: str,
              ip6: list[str] | None = None) -> dict:
        mac = mac.lower()
        targets: list[str] = []
        if ip:
            targets.append(ip)
        for addr in (ip6 or []):
            if addr and addr not in targets:
                targets.append(addr)
        if mode == "mac" or not targets:
            return {
                "ok": False,
                "error": ("Windows Firewall blocks by IP; scan again for an IP or use "
                          "mode=both so the ARP layer can cut the device"),
                "applied": [], "simulated": self.simulate,
            }
        ok, msg = self.ensure()
        if not ok:
            return {"ok": False, "error": msg, "applied": [], "simulated": self.simulate}
        applied: list[str] = []
        errors: list[str] = []
        # IPv6 addresses get IP-level rules too: Windows Firewall matches
        # remoteaddress for both families, so the IPv6 gap is closed here (the
        # ARP black hole still only covers IPv4).
        for target in targets:
            family = "ipv6" if ":" in target else "ipv4"
            for direction in ("in", "out"):
                name = self._rule_name(mac, target, direction)
                if not self.simulate and self._rule_exists(name):
                    applied.append(f"winfw:{'ipv6' if family == 'ipv6' else 'ip'}-{direction}")
                    continue
                args = ["add", "rule", f"name={name}", f"dir={direction}",
                        "action=block", f"remoteip={target}", "profile=any",
                        "enable=yes"]
                rc, _, err = self._run(args)
                if rc != 0:
                    errors.append(f"{family} {direction}: {err}")
                    continue
                verified = self.simulate or self._rule_exists(name)
                # Keep the legacy "winfw:ip-in/out" labels for IPv4 so callers
                # and tests that key on them keep working.
                label = "ipv6" if family == "ipv6" else "ip"
                applied.append(f"winfw:{label}-{direction}"
                               f"{'' if verified else ' (unverified)'}")
        return {
            "ok": bool(applied),
            "error": "; ".join(errors),
            "applied": applied,
            "simulated": self.simulate,
            "ipv6": {"addresses_blocked": sum(1 for t in targets if ":" in t)},
            "note": "IP-level rules; MAC filtering is handled by the ARP layer",
        }

    def _rule_exists(self, name: str) -> bool:
        rc, out, _ = self._run(["show", "rule", f"name={name}"])
        return rc == 0 and name in out

    def _rule_names(self) -> list[str]:
        # Get-NetFirewallRule is language-independent; netsh output is localized.
        pattern = f"{TAG}*"
        rc, out, _ = platform_ops.powershell(
            f"Get-NetFirewallRule -Name '{pattern}' -ErrorAction SilentlyContinue | "
            f"Get-NetFirewallRule -Name '{LEGACY_TAG}*' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Name")
        if rc == 0:
            return sorted({line.strip() for line in out.splitlines()
                           if line.strip().startswith((TAG, LEGACY_TAG))})
        rc, out, _ = self._run(["show", "rule", "name=all", "verbose"])
        if rc != 0:
            return []
        return sorted(set(re.findall(rf"Rule Name:\s*((?:{TAG}|{LEGACY_TAG})\S+)", out)))

    def unblock(self, mac: str) -> dict:
        mac = mac.lower()
        removed: list[str] = []
        errors: list[str] = []
        key = mac.lower().replace(":", "")
        names = [n for n in self._rule_names()
                 if n.lower().startswith((f"{TAG}{key}-", f"{LEGACY_TAG}{key}-"))]
        if not names and not self.simulate:
            # No rules is still a successful unblock.
            return {"ok": True, "removed": [], "error": ""}
        for name in names:
            rc, _, err = self._run(["delete", "rule", f"name={name}"])
            if rc == 0:
                removed.append(name)
            else:
                errors.append(err)
        return {"ok": not errors, "removed": removed, "error": "; ".join(errors)}

    def list_rules(self) -> list[dict]:
        rules: list[dict] = []
        for name in self._rule_names():
            m = re.match(rf"{TAG}([0-9a-f]{{12}})-(.+)-(in|out)$", name, re.I)
            if m:
                raw = m.group(1).lower()
                pretty = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
                rules.append({"mac": pretty, "ip": m.group(2).replace("-", ":"),
                              "direction": m.group(3), "rule": name})
        return rules

    def status(self) -> dict:
        return {
            "available": bool(self.netsh),
            "backend": "windows-firewall",
            "privileged": self.privileged,
            "privilege_mode": self.privilege_mode,
            "simulated": self.simulate,
            "chain": "NPENT rules",
            "rules": 0 if self.simulate else len(self.list_rules()),
        }

    def panic(self) -> dict:
        removed = 0
        errors: list[str] = []
        for name in self._rule_names():
            rc, _, err = self._run(["delete", "rule", f"name={name}"])
            if rc == 0:
                removed += 1
            else:
                errors.append(err)
        return {"ok": not errors, "removed": removed, "error": "; ".join(errors),
                "simulated": self.simulate}
