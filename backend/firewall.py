"""iptables / ip6tables rule management for MAC and IP enforcement.

Two dedicated chains per address family, so a rule never sits in a hook the
kernel rejects:

``CUTOFF_BLOCK``  hooked into ``INPUT`` and ``FORWARD`` — MAC and L3 rules.
``CUTOFF_OUT``    hooked into ``OUTPUT`` — L3 rules only, because the xt_mac
                 match is only valid for packets *entering* the host and
                 ip6tables refuses a MAC rule in a chain reachable from OUTPUT.

Every rule carries a ``CUTOFF:<kind>:<id>:<scope>`` comment, which is how rules
are found again for removal. The legacy ``CUTOFF:<mac>:<scope>`` form written by
older builds still parses, so an upgrade can clean up after itself.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time

import platform_ops

log = logging.getLogger("cutoff.firewall")
CHAIN = "CUTOFF_BLOCK"
CHAIN_OUT = "CUTOFF_OUT"
TAG = "CUTOFF:"
# Pre-rename artefacts: still parsed and cleaned up so an upgrade does not
# leave orphaned rules or a stale chain hooked into INPUT/FORWARD/OUTPUT.
LEGACY_TAG = "NPENT:"
LEGACY_CHAINS = ("NPENT_BLOCK", "NPENT_OUT")
ALL_TAGS = (TAG, LEGACY_TAG)

# scope -> (chain, needs MAC match)
SCOPES = {
    "l2": (CHAIN, True),
    "l3": (CHAIN, False),
    "l3out": (CHAIN_OUT, False),
    "v6l2": (CHAIN, True),
    "v6l3": (CHAIN, False),
    "v6l3out": (CHAIN_OUT, False),
    "pfxl3": (CHAIN, False),
    "pfxout": (CHAIN_OUT, False),
}

_COMMENT_RE = re.compile(r'--comment\s+(?:"([^"]*)"|(\S+))')


def find_binary(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for candidate in (f"/usr/sbin/{name}", f"/sbin/{name}", f"/usr/bin/{name}"):
        if os.path.exists(candidate):
            return candidate
    return None


def privileges() -> tuple[bool, str]:
    """(can_enforce, how) — root/sudo on Linux, Administrator on Windows."""
    if platform_ops.IS_WINDOWS:
        return (True, "administrator") if platform_ops.is_admin() else (False, "unprivileged")
    if os.geteuid() == 0:
        return True, "root"
    try:
        cp = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        if cp.returncode == 0:
            return True, "sudo"
    except (OSError, subprocess.SubprocessError):
        pass
    return False, "unprivileged"


def make_tag(kind: str, ident: str, scope: str) -> str:
    return f"{TAG}{kind}:{ident}:{scope}"


def parse_tag(comment: str) -> dict | None:
    """Parse a rule comment into ``{kind, key, scope}``.

    Handles ``CUTOFF:mac:aa:bb:cc:dd:ee:ff:v6l3``,
    ``CUTOFF:pfx:2001:db8::/64:pfxl3`` and the legacy
    ``CUTOFF:aa:bb:cc:dd:ee:ff:l2`` written by older builds.
    """
    prefix = next((tag for tag in ALL_TAGS if comment and comment.startswith(tag)), None)
    if prefix is None:
        return None
    body = comment[len(prefix):]
    if body.startswith("mac:"):
        parts = body.split(":")
        if len(parts) < 8:
            return None
        return {"kind": "mac", "key": ":".join(parts[1:7]).lower(), "scope": parts[-1]}
    if body.startswith("pfx:"):
        parts = body.split(":")
        if len(parts) < 3:
            return None
        return {"kind": "prefix", "key": ":".join(parts[1:-1]), "scope": parts[-1]}
    parts = body.split(":")
    if len(parts) >= 7 and all(re.fullmatch(r"[0-9a-fA-F]{1,4}", p) for p in parts[:6]):
        return {"kind": "mac", "key": ":".join(parts[:6]).lower(), "scope": parts[-1]}
    return None


def _comment_of(line: str) -> str:
    match = _COMMENT_RE.search(line or "")
    if not match:
        return ""
    return match.group(1) if match.group(1) is not None else match.group(2)


def _dedupe_rules(rules: list[dict]) -> list[dict]:
    """One row per rule identity.

    A block installs ``-s`` and ``-d`` twins with the same comment, so the raw
    list doubles every rule; the table only needs the identity.
    """
    seen: set[tuple] = set()
    unique: list[dict] = []
    for rule in rules:
        ident = (rule["family"], rule["chain"], rule["kind"],
                 rule["key"], rule["scope"])
        if ident in seen:
            continue
        seen.add(ident)
        unique.append(rule)
    return unique


class Firewall:
    def __init__(self, simulate: bool = False):
        self.ipt = find_binary("iptables")
        self.ip6t = find_binary("ip6tables")
        can, how = privileges()
        self.privileged = can
        self.privilege_mode = how
        self.simulate = simulate
        self._sudo = how == "sudo"
        self._lock = threading.RLock()
        self.last_commands: list[str] = []
        # Simulated rules, so the UI can show what *would* be applied instead
        # of an empty table next to a successful "block" result.
        self._sim: dict[str, list[tuple[str, str]]] = {}
        # /api/status polls every few seconds; without this every poll shelled
        # out to ip(6)tables -S (x2 families x2+ chains).
        self._rules_cache: list[dict] = []
        self._rules_at = 0.0

    # plumbing --------------------------------------------------------------
    def _cmd(self, binary: str, args: list[str]) -> list[str]:
        base = [binary, "-w", "5"] if binary.endswith("iptables") else [binary]
        if self._sudo:
            return ["sudo", "-n"] + base + args
        return base + args

    def _run(self, binary: str | None, args: list[str],
             timeout: float = 15.0) -> tuple[int, str, str]:
        if binary is None:
            return 127, "", "binary not found"
        cmd = self._cmd(binary, args)
        if self.simulate:
            log.info("simulate: %s", " ".join(cmd))
            return 0, "", ""
        self.last_commands.append(" ".join(cmd))
        self.last_commands = self.last_commands[-50:]
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            return 127, "", str(exc)

    def _ensure_family(self, binary: str | None, family: str) -> tuple[bool, str]:
        if not binary:
            return False, f"{family} tool not installed"
        for chain in (CHAIN, CHAIN_OUT):
            rc, _, err = self._run(binary, ["-N", chain])
            if rc != 0 and "exist" not in err.lower():
                return False, f"cannot create {chain} ({family}): {err}"
            hooks = ("OUTPUT",) if chain == CHAIN_OUT else ("INPUT", "FORWARD")
            for hook in hooks:
                rc, _, _ = self._run(binary, ["-C", hook, "-j", chain])
                if rc != 0:
                    rc, _, err = self._run(binary, ["-I", hook, "1", "-j", chain])
                    if rc != 0:
                        return False, f"cannot hook {hook} -> {chain} ({family}): {err}"
        # Migration: builds before the chain split also dropped the MAC-bearing
        # chain into OUTPUT, which modern ip(6)tables rejects.
        rc, _, _ = self._run(binary, ["-C", "OUTPUT", "-j", CHAIN])
        if rc == 0:
            self._run(binary, ["-D", "OUTPUT", "-j", CHAIN])
        # Migration: retire the pre-rename NPENT_* chains.
        for legacy in LEGACY_CHAINS:
            for hook in ("INPUT", "FORWARD", "OUTPUT"):
                rc, _, _ = self._run(binary, ["-C", hook, "-j", legacy])
                if rc == 0:
                    self._run(binary, ["-D", hook, "-j", legacy])
            self._run(binary, ["-F", legacy])
            self._run(binary, ["-X", legacy])
        return True, f"{family} chains ready"

    def ensure(self) -> tuple[bool, str]:
        with self._lock:
            if self.simulate:
                return True, "simulation (no kernel changes)"
            if not self.ipt:
                return False, "iptables not installed"
            if not self.privileged:
                return False, ("root or passwordless sudo is required to change "
                               "firewall rules")
            ok, msg = self._ensure_family(self.ipt, "ipv4")
            if not ok:
                return ok, msg
            if self.ip6t:
                ok6, msg6 = self._ensure_family(self.ip6t, "ipv6")
                if not ok6:
                    log.warning("ipv6 chains unavailable: %s", msg6)
            return True, "chains ready"

    # rule primitives -------------------------------------------------------
    def _invalidate(self) -> None:
        self._rules_cache = []
        self._rules_at = 0.0

    def _add(self, binary: str | None, chain: str, args: list[str],
             tag: str) -> tuple[bool, str]:
        """Idempotent add + verify. Returns ``(ok, error)``."""
        spec = list(args) + ["-m", "comment", "--comment", tag, "-j", "DROP"]
        if self.simulate:
            entries = self._sim.setdefault(binary or "", [])
            line = " ".join(spec)
            if not any(c == chain and l == line for c, l in entries):
                entries.append((chain, line))
            self._invalidate()
            return True, ""
        rc, _, err = self._run(binary, ["-C", chain] + spec)
        if rc == 0:
            return True, ""
        rc, _, err = self._run(binary, ["-A", chain] + spec)
        if rc != 0:
            return False, err or "add failed"
        if not self.simulate:
            rc, _, err = self._run(binary, ["-C", chain] + spec)
            if rc != 0:
                return False, err or "rule not found after add"
        self._invalidate()
        return True, ""

    def _delete_matching(self, binary: str | None,
                         predicate) -> tuple[list[str], list[str]]:
        removed: list[str] = []
        errors: list[str] = []
        if not binary:
            return removed, errors
        if self.simulate:
            family = "ipv6" if binary == self.ip6t else "ipv4"
            keep: list[tuple[str, str]] = []
            for chain, line in self._sim.get(binary, []):
                info = parse_tag(_comment_of(line))
                if info and predicate(info):
                    removed.append(f"{family}:{info['scope']}")
                else:
                    keep.append((chain, line))
            self._sim[binary] = keep
            self._invalidate()
            return removed, errors
        for chain in (CHAIN, CHAIN_OUT) + LEGACY_CHAINS:
            rc, out, _ = self._run(binary, ["-S", chain])
            if rc != 0:
                continue
            for line in out.splitlines():
                if not line.startswith("-A "):
                    continue
                info = parse_tag(_comment_of(line))
                if not info or not predicate(info):
                    continue
                spec = line.split()
                spec[0] = "-D"
                rc, _, err = self._run(binary, spec)
                family = "ipv6" if binary == self.ip6t else "ipv4"
                if rc == 0:
                    removed.append(f"{family}:{info['scope']}")
                else:
                    errors.append(err)
        self._invalidate()
        return removed, errors

    # public ----------------------------------------------------------------
    def block(self, mac: str, ip: str | None, mode: str,
              ip6: list[str] | None = None) -> dict:
        mac = mac.lower()
        ok, msg = self.ensure()
        if not ok:
            return {"ok": False, "error": msg, "applied": [], "simulated": self.simulate}
        applied: list[str] = []
        errors: list[str] = []

        if mode in ("mac", "both"):
            good, err = self._add(self.ipt, CHAIN,
                                  ["-m", "mac", "--mac-source", mac],
                                  make_tag("mac", mac, "l2"))
            if good:
                applied.append("ipv4:l2")
            else:
                errors.append(f"ipv4 l2: {err}")

        if mode in ("ip", "both") and ip:
            for chain, scope, args in (
                (CHAIN, "l3", ["-s", ip]),
                (CHAIN, "l3", ["-d", ip]),
                (CHAIN_OUT, "l3out", ["-s", ip]),
                (CHAIN_OUT, "l3out", ["-d", ip]),
            ):
                good, err = self._add(self.ipt, chain, args, make_tag("mac", mac, scope))
                if good:
                    label = f"ipv4:{scope}"
                    if label not in applied:
                        applied.append(label)
                else:
                    errors.append(f"ipv4 {scope}: {err}")

        # ---- IPv6 ---------------------------------------------------------
        # The MAC rule is the only hook that survives SLAAC privacy addresses;
        # the per-address L3 rules add the destination side and our own OUTPUT.
        if self.ip6t:
            if mode in ("mac", "both"):
                good, err = self._add(self.ip6t, CHAIN,
                                      ["-m", "mac", "--mac-source", mac],
                                      make_tag("mac", mac, "v6l2"))
                if good:
                    applied.append("ipv6:l2")
                else:
                    errors.append(f"ipv6 l2: {err}")
            if mode in ("ip", "both"):
                for addr in (ip6 or []):
                    for chain, scope, args in (
                        (CHAIN, "v6l3", ["-s", addr]),
                        (CHAIN, "v6l3", ["-d", addr]),
                        (CHAIN_OUT, "v6l3out", ["-s", addr]),
                        (CHAIN_OUT, "v6l3out", ["-d", addr]),
                    ):
                        good, err = self._add(self.ip6t, chain, args,
                                              make_tag("mac", mac, scope))
                        if not good:
                            errors.append(f"ipv6 {addr} {scope}: {err}")
                if ip6:
                    applied.append(f"ipv6:l3x{len(ip6)}")
        else:
            applied.append("ipv6:unavailable")

        if errors and not applied:
            return {"ok": False, "error": "; ".join(errors), "applied": [],
                    "simulated": self.simulate}
        return {
            "ok": True,
            "error": "; ".join(errors) if errors else "",
            "applied": applied,
            "simulated": self.simulate,
            "ipv6": {
                "tool": self.ip6t or "",
                "addresses_blocked": len(ip6 or []),
                "mac_rule": "ipv6:l2" in applied,
            },
        }

    def unblock(self, mac: str) -> dict:
        mac = mac.lower()
        removed: list[str] = []
        errors: list[str] = []
        if not self.ipt:
            return {"ok": False, "error": "iptables not installed", "removed": []}
        with self._lock:
            for binary in (self.ipt, self.ip6t):
                gone, errs = self._delete_matching(
                    binary,
                    lambda info, m=mac: info["kind"] == "mac" and info["key"].lower() == m)
                removed.extend(gone)
                errors.extend(errs)
        return {"ok": not errors, "removed": removed, "error": "; ".join(errors)}

    # prefix rules ----------------------------------------------------------
    def block_prefix(self, prefix: str) -> dict:
        """Block a whole IPv6 prefix, in both directions and both chains."""
        ok, msg = self.ensure()
        if not ok:
            return {"ok": False, "error": msg, "applied": [], "simulated": self.simulate}
        if not self.ip6t:
            return {"ok": False, "error": "ip6tables not installed", "applied": [],
                    "simulated": self.simulate}
        applied: list[str] = []
        errors: list[str] = []
        for chain, scope, args in (
            (CHAIN, "pfxl3", ["-s", prefix]),
            (CHAIN, "pfxl3", ["-d", prefix]),
            (CHAIN_OUT, "pfxout", ["-s", prefix]),
            (CHAIN_OUT, "pfxout", ["-d", prefix]),
        ):
            good, err = self._add(self.ip6t, chain, args, make_tag("pfx", prefix, scope))
            if good:
                if scope not in applied:
                    applied.append(scope)
            else:
                errors.append(f"{scope}: {err}")
        if errors and not applied:
            return {"ok": False, "error": "; ".join(errors), "applied": [],
                    "simulated": self.simulate}
        return {"ok": True, "error": "; ".join(errors), "applied": applied,
                "prefix": prefix, "simulated": self.simulate}

    def unblock_prefix(self, prefix: str) -> dict:
        removed: list[str] = []
        errors: list[str] = []
        with self._lock:
            gone, errs = self._delete_matching(
                self.ip6t,
                lambda info, p=prefix: info["kind"] == "prefix" and info["key"] == p)
            removed.extend(gone)
            errors.extend(errs)
        return {"ok": not errors, "removed": removed, "prefix": prefix,
                "error": "; ".join(errors)}

    # introspection ---------------------------------------------------------
    def list_rules(self, force: bool = False) -> list[dict]:
        """Every tagged rule, both families, both chains (cached ~2.5 s)."""
        if not force and self._rules_cache and time.monotonic() - self._rules_at < 2.5:
            return [dict(r) for r in self._rules_cache]
        rules: list[dict] = []
        if self.simulate:
            for binary, entries in self._sim.items():
                family = "ipv6" if binary == self.ip6t else "ipv4"
                for chain, line in entries:
                    info = parse_tag(_comment_of(line))
                    if not info:
                        continue
                    rules.append({"family": family, "chain": chain,
                                  "kind": info["kind"], "key": info["key"],
                                  "scope": info["scope"], "rule": f"-A {chain} {line}",
                                  "simulated": True})
            self._rules_cache = _dedupe_rules(rules)
            self._rules_at = time.monotonic()
            return [dict(r) for r in self._rules_cache]
        if not self.ipt:
            return rules
        for family, binary in (("ipv4", self.ipt), ("ipv6", self.ip6t)):
            if not binary:
                continue
            for chain in (CHAIN, CHAIN_OUT) + LEGACY_CHAINS:
                rc, out, _ = self._run(binary, ["-S", chain])
                if rc != 0:
                    continue
                for line in out.splitlines():
                    if not line.startswith("-A "):
                        continue
                    info = parse_tag(_comment_of(line))
                    if not info:
                        continue
                    rules.append({
                        "family": family,
                        "chain": chain,
                        "kind": info["kind"],
                        "key": info["key"],
                        "scope": info["scope"],
                        "rule": line,
                    })
        return _dedupe_rules(rules)

    def status(self) -> dict:
        rules = self.list_rules()
        ipv6_rules = [r for r in rules if r["family"] == "ipv6"]
        return {
            "available": bool(self.ipt),
            "privileged": self.privileged,
            "privilege_mode": self.privilege_mode,
            "simulated": self.simulate,
            "chain": CHAIN,
            "out_chain": CHAIN_OUT,
            "rules": len(rules),
            "ipv4_rules": len(rules) - len(ipv6_rules),
            "ipv6": {
                "available": bool(self.ip6t),
                "binary": self.ip6t or "",
                "rules": len(ipv6_rules),
                "mac_rules": sum(1 for r in ipv6_rules if "l2" in r["scope"]),
                "prefix_rules": sum(1 for r in ipv6_rules if r["kind"] == "prefix"),
                "chains": [CHAIN, CHAIN_OUT],
            },
        }

    def panic(self) -> dict:
        """Remove every CUTOFF rule and unhook both chains, both families."""
        with self._lock:
            removed = 0
            errors: list[str] = []
            if self.simulate:
                removed = sum(len(v) for v in self._sim.values())
                self._sim = {}
                self._invalidate()
                return {"ok": True, "removed": removed, "simulated": True}
            if not self.ipt:
                return {"ok": True, "removed": 0, "simulated": self.simulate}
            for binary in (self.ipt, self.ip6t):
                if not binary:
                    continue
                for chain in (CHAIN, CHAIN_OUT) + LEGACY_CHAINS:
                    rc, out, _ = self._run(binary, ["-S", chain])
                    if rc != 0:
                        continue
                    for line in out.splitlines():
                        if not line.startswith("-A "):
                            continue
                        spec = line.split()
                        spec[0] = "-D"
                        rcx, _, errx = self._run(binary, spec)
                        if rcx == 0:
                            removed += 1
                        else:
                            errors.append(errx)
                for parent in ("INPUT", "FORWARD", "OUTPUT"):
                    for chain in (CHAIN, CHAIN_OUT) + LEGACY_CHAINS:
                        self._run(binary, ["-D", parent, "-j", chain])
                for chain in (CHAIN, CHAIN_OUT) + LEGACY_CHAINS:
                    self._run(binary, ["-F", chain])
                    self._run(binary, ["-X", chain])
            self._invalidate()
            return {"ok": not errors, "removed": removed, "error": "; ".join(errors),
                    "simulated": self.simulate}


def create(simulate: bool = False):
    """Return the platform firewall backend."""
    if platform_ops.IS_WINDOWS:
        from firewall_win import WindowsFirewall

        return WindowsFirewall(simulate)
    return Firewall(simulate)
