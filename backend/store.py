"""Thread-safe JSON inventory of devices, blocks and audit events."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MAX_EVENTS = 2000
MAX_DEVICES = 1000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def norm_mac(mac: str) -> str:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if len(cleaned) != 12:
        raise ValueError(f"invalid MAC address: {mac!r}")
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def atomic_write(path: Path, payload: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(path)


class Store:
    def __init__(self, devices_file: Path, events_file: Path):
        self.devices_file = devices_file
        self.events_file = events_file
        self._lock = threading.RLock()
        self._data: dict = {"devices": {}, "blocks": {}, "version": 1}
        self._load()

    # persistence -----------------------------------------------------------
    def _load(self) -> None:
        if not self.devices_file.exists():
            return
        try:
            raw = json.loads(self.devices_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("devices"), dict):
                self._data["devices"] = raw["devices"]
                self._data["blocks"] = raw.get("blocks", {})
        except (OSError, json.JSONDecodeError):
            # A corrupt file must not stop the service; keep a copy for recovery.
            try:
                self.devices_file.replace(self.devices_file.with_suffix(".corrupt"))
            except OSError:
                pass

    def _save(self) -> None:
        atomic_write(self.devices_file, json.dumps(self._data, indent=2, sort_keys=True))

    # devices ---------------------------------------------------------------
    def upsert_scan(self, found: list[dict]) -> int:
        """Merge a scan result. Returns the number of new devices."""
        with self._lock:
            seen = {d["mac"] for d in found}
            new = 0
            ts = now_iso()
            for dev in found:
                mac = norm_mac(dev["mac"])
                entry = self._data["devices"].get(mac)
                if entry is None:
                    entry = {
                        "mac": mac,
                        "name": "",
                        "hostname": "",
                        "first_seen": ts,
                        "created_at": ts,
                        "info": {},
                        "names": {},
                        "sources": [],
                    }
                    self._data["devices"][mac] = entry
                    new += 1
                entry.update(
                    {
                        "ip": dev.get("ip") or entry.get("ip", ""),
                        "last_seen": ts,
                        "last_seen_epoch": time.time(),
                        "active": True,
                    }
                )
                vendor = (dev.get("vendor") or "").strip()
                if vendor and (entry.get("vendor") in (None, "", "Unknown") or vendor != "Unknown"):
                    entry["vendor"] = vendor
                for key in ("hostname", "model", "manufacturer", "device_type", "title", "os"):
                    value = dev.get(key)
                    if value:
                        entry[key] = value
                if dev.get("ports"):
                    entry["ports"] = dev["ports"]
                if dev.get("services"):
                    entry["services"] = dev["services"]
                if dev.get("names"):
                    entry["names"] = {
                        **(entry.get("names") or {}),
                        **{k: v for k, v in dev["names"].items() if v},
                    }
                if dev.get("sources"):
                    entry["sources"] = sorted(set(entry.get("sources") or []) | set(dev["sources"]))
                if dev.get("info"):
                    entry["info"] = {**(entry.get("info") or {}), **dev["info"]}
                if "ip6" in dev:
                    # Preserve the NDP-derived IPv6 set verbatim: an address
                    # that rotated away must not stay blockable forever.
                    entry["ip6"] = [a for a in (dev.get("ip6") or []) if a][:8]
                    if dev.get("ip6_scopes"):
                        entry["ip6_scopes"] = dev["ip6_scopes"]
                if dev.get("is_self"):
                    entry["is_self"] = True
            for mac, entry in self._data["devices"].items():
                if mac not in seen:
                    entry["active"] = False
            if len(self._data["devices"]) > MAX_DEVICES:
                ordered = sorted(
                    self._data["devices"].items(),
                    key=lambda kv: kv[1].get("last_seen_epoch", 0),
                    reverse=True,
                )
                self._data["devices"] = dict(ordered[:MAX_DEVICES])
            self._save()
            return new

    def touch_hosts(self, hosts: list[dict]) -> int:
        """Mark nmap-confirmed hosts online without marking anything offline."""
        with self._lock:
            by_ip = {v.get("ip"): v for v in self._data["devices"].values() if v.get("ip")}
            ts = now_iso()
            epoch = time.time()
            touched = 0
            for host in hosts:
                ip = host.get("ip") or ""
                mac = (host.get("mac") or "").lower()
                entry = by_ip.get(ip) or (self._data["devices"].get(mac) if mac else None)
                if entry is None:
                    continue
                if ip and not entry.get("ip"):
                    entry["ip"] = ip
                entry["active"] = True
                entry["last_seen"] = ts
                entry["last_seen_epoch"] = epoch
                names = host.get("hostnames") or []
                if names and not entry.get("hostname"):
                    entry["hostname"] = names[0]
                if host.get("ports"):
                    entry["ports"] = host["ports"]
                    entry["services"] = host.get("services", [])
                entry["sources"] = sorted(set(entry.get("sources") or []) | {"nmap"})
                touched += 1
            if touched:
                self._save()
            return touched

    def set_name(self, mac: str, name: str) -> dict | None:
        with self._lock:
            entry = self._data["devices"].get(norm_mac(mac))
            if entry is None:
                return None
            entry["name"] = name.strip()[:64]
            self._save()
            return dict(entry)

    def get(self, mac: str) -> dict | None:
        with self._lock:
            entry = self._data["devices"].get(norm_mac(mac))
            return dict(entry) if entry else None

    def devices(self) -> list[dict]:
        with self._lock:
            return [dict(v) for v in self._data["devices"].values()]

    # blocks ----------------------------------------------------------------
    def add_block(self, mac: str, mode: str, simulated: bool, strategy: str,
                  isolation: str = "internet",
                  ip6: list[str] | None = None,
                  ip6_prefix: list[str] | None = None) -> dict:
        with self._lock:
            mac = norm_mac(mac)
            block = {
                "mac": mac,
                "mode": mode,
                "strategy": strategy,
                "isolation": isolation,
                "simulated": simulated,
                "blocked_at": now_iso(),
            }
            if ip6:
                block["ip6"] = list(ip6)[:8]
            if ip6_prefix:
                block["ip6_prefix"] = list(ip6_prefix)[:4]
            self._data["blocks"][mac] = block
            self._save()
            return dict(block)

    def remove_block(self, mac: str) -> dict | None:
        with self._lock:
            block = self._data["blocks"].pop(norm_mac(mac), None)
            if block is not None:
                self._save()
            return block

    def block_for(self, mac: str) -> dict | None:
        with self._lock:
            b = self._data["blocks"].get(norm_mac(mac))
            return dict(b) if b else None

    def blocks(self) -> dict[str, dict]:
        with self._lock:
            return {k: dict(v) for k, v in self._data["blocks"].items()}

    # events ----------------------------------------------------------------
    def log(self, kind: str, message: str, mac: str = "", ok: bool = True,
            simulated: bool = False) -> None:
        event = {
            "ts": now_iso(),
            "epoch": time.time(),
            "kind": kind,
            "mac": mac,
            "message": message,
            "ok": ok,
            "simulated": simulated,
        }
        with self._lock:
            try:
                self.events_file.parent.mkdir(parents=True, exist_ok=True)
                with self.events_file.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event) + "\n")
            except OSError:
                pass

    def events(self, limit: int = 100) -> list[dict]:
        if not self.events_file.exists():
            return []
        try:
            lines = self.events_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        out: list[dict] = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(reversed(out))

    def clear_events(self) -> None:
        with self._lock:
            try:
                if self.events_file.exists():
                    self.events_file.write_text("", encoding="utf-8")
            except OSError:
                pass
