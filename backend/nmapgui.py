"""Nmap preset runner for the GUI — fixed, validated commands only."""
from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import threading
import time
from pathlib import Path

import config
import nmapscan
import platform_ops

log = logging.getLogger("cutoff.nmapgui")
WORK_DIR = config.DATA_DIR / "nmap"

PRESETS: dict[str, dict] = {
    "discover": {
        "label": "Discover hosts",
        "desc": "Ping/ARP sweep of the subnet. Fast inventory check.",
        "args": ["-sn"],
        "timeout": 120,
        "needs_root": False,
    },
    "fast": {
        "label": "Fast scan + versions",
        "desc": "Top 100 TCP ports, service/version detection.",
        "args": ["-sT", "-Pn", "--top-ports", "100", "-sV", "--version-light"],
        "timeout": 240,
        "needs_root": False,
    },
    "services": {
        "label": "Service scan",
        "desc": "TCP 1-1024 with version detection.",
        "args": ["-sT", "-Pn", "-p", "1-1024", "-sV", "--version-light"],
        "timeout": 300,
        "needs_root": False,
    },
    "os": {
        "label": "OS detection",
        "desc": "SYN scan plus OS fingerprinting (root only).",
        "args": ["-sS", "-Pn", "-O", "--osscan-guess", "--top-ports", "100"],
        "timeout": 240,
        "needs_root": True,
    },
    "scripts": {
        "label": "Default scripts",
        "desc": "Top 50 ports with the safe default NSE set.",
        "args": ["-sT", "-Pn", "--top-ports", "50", "-sV", "--script", "default"],
        "timeout": 300,
        "needs_root": False,
    },
    "vuln": {
        "label": "Vulnerability scripts",
        "desc": "NSE vuln category against top 100 ports. Loud and slow.",
        "args": ["-sT", "-Pn", "--top-ports", "100", "--script", "vuln"],
        "timeout": 600,
        "needs_root": False,
        "warn": True,
    },
    "full": {
        "label": "Full TCP + versions",
        "desc": "All 65535 TCP ports with version detection. Very slow.",
        "args": ["-sT", "-Pn", "-p-", "-sV", "--version-light"],
        "timeout": 900,
        "needs_root": False,
        "warn": True,
    },
}


class NmapRunner:
    def __init__(self, store):
        self.store = store
        self._lock = threading.RLock()
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        # set by stop(): the child dies with SIGTERM, which used to surface as
        # "nmap exited -15" and a spurious XML parse warning.
        self._stop_requested = False
        self.state: dict = {
            "running": False, "preset": "", "label": "", "target": "",
            "started_at": 0.0, "finished_at": 0.0, "error": "",
            "output": "", "hosts": [], "command": "", "duration_s": 0,
        }

    # targets -------------------------------------------------------------
    def targets(self, iface) -> list[dict]:
        out = [{"id": "subnet", "label": "Whole subnet", "value": iface.network if iface else ""}]
        if iface and iface.gateway:
            out.append({"id": "gateway", "label": "Gateway", "value": iface.gateway})
        now = time.time()
        for device in self.store.devices():
            recent = (now - float(device.get("last_seen_epoch") or 0)) <= config.RECENT_WINDOW_SEC
            if not (device.get("active") or recent) or not device.get("ip"):
                continue
            out.append({
                "id": f"device:{device['ip']}",
                "label": device.get("display_name") or device.get("hostname") or device["ip"],
                "value": device["ip"],
            })
        return out

    def _resolve(self, target: str, custom: str, iface) -> str:
        if not iface:
            raise ValueError("no network interface")
        network = ipaddress.ip_interface(f"{iface.ip}/{iface.prefix}").network
        if target == "subnet":
            return str(network)
        if target == "gateway":
            if not iface.gateway:
                raise ValueError("gateway unknown")
            return iface.gateway
        if target.startswith("device:"):
            ip = target.split(":", 1)[1]
            if not any(d.get("ip") == ip for d in self.store.devices()):
                raise ValueError("device is not in the inventory")
            return ip
        if target == "custom":
            text = (custom or "").strip()
            try:
                parsed = ipaddress.ip_network(text, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid IP/CIDR: {text}") from exc
            if not (parsed.subnet_of(network) if parsed.num_addresses > 1
                    else parsed.network_address in network):
                raise ValueError("target must be inside your local subnet")
            return str(parsed) if parsed.num_addresses > 1 else str(parsed.network_address)
        raise ValueError("unknown target")

    # lifecycle -----------------------------------------------------------
    def start(self, preset: str, target: str, custom: str, iface) -> tuple[bool, str]:
        if preset not in PRESETS:
            return False, "unknown preset"
        with self._lock:
            if self.state["running"]:
                return False, "a scan is already running"
        binary = nmapscan.locate()
        if not binary:
            return False, "nmap is not bundled (vendor/nmap missing)"
        spec = PRESETS[preset]
        if spec.get("needs_root") and not platform_ops.is_admin():
            return False, "this preset needs root (restart with sudo)"
        try:
            resolved = self._resolve(target, custom, iface)
        except ValueError as exc:
            return False, str(exc)
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        xml_path = WORK_DIR / f"{stamp}.xml"
        txt_path = WORK_DIR / f"{stamp}.txt"
        args = [binary, "-oX", str(xml_path), "-oN", str(txt_path), "-T4"]
        args += list(spec["args"])
        datadir = nmapscan.data_dir()
        if datadir:
            args += ["--datadir", datadir]
        args.append(resolved)
        with self._lock:
            self._stop_requested = False
            self.state = {
                "running": True, "preset": preset, "label": spec["label"],
                "target": resolved, "started_at": time.time(), "finished_at": 0.0,
                "error": "", "output": "", "hosts": [], "command": " ".join(args),
                "duration_s": 0,
            }
        self._thread = threading.Thread(
            target=self._run,
            args=(args, xml_path, txt_path, spec["timeout"]),
            daemon=True, name="cutoff-nmap",
        )
        self._thread.start()
        return True, f"{spec['label']} started against {resolved}"

    def _run(self, args: list[str], xml_path: Path, txt_path: Path, timeout: int) -> None:
        env = os.environ.copy()
        datadir = nmapscan.data_dir()
        if datadir:
            env["NMAPDATADIR"] = datadir
        error = ""
        hosts: list[dict] = []
        exit_code = None
        try:
            with self._lock:
                self._proc = subprocess.Popen(
                    args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=env, text=True,
                )
            exit_code = self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            error = f"scan timed out after {timeout}s"
            if self._proc:
                self._proc.kill()
        except OSError as exc:
            error = str(exc)
        finally:
            stopped = self._stop_requested
            if xml_path.exists() and not stopped:
                try:
                    hosts = list(nmapscan.parse_xml(xml_path.read_text(errors="replace")).values())
                except OSError:
                    hosts = []
            responsive = [h for h in hosts if h.get("responsive")]
            touched = 0
            if responsive:
                try:
                    touched = self.store.touch_hosts(responsive)
                except Exception:  # noqa: BLE001 - scan result must survive a sync error
                    touched = 0
            output = ""
            if txt_path.exists():
                try:
                    output = txt_path.read_text(errors="replace")[-30000:]
                except OSError:
                    pass
            for path in (xml_path, txt_path):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            with self._lock:
                self.state.update({
                    "running": False, "finished_at": time.time(),
                    "duration_s": int(time.time() - self.state["started_at"]),
                    "hosts": hosts, "responsive": len(responsive),
                "touched": touched, "output": output,
                    "error": ("scan stopped by user" if stopped else
                              error or ("" if exit_code in (0, None) else f"nmap exited {exit_code}")),
                })
                self._proc = None

    def stop(self) -> dict:
        with self._lock:
            proc = self._proc
            thread = self._thread
            self._stop_requested = True
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            # let the worker publish its final state before the UI polls again
            if thread is not None:
                thread.join(timeout=3)
            return {"ok": True, "stopped": True}
        return {"ok": True, "stopped": False}

    def status(self) -> dict:
        with self._lock:
            data = dict(self.state)
            data["hosts"] = list(self.state.get("hosts", []))
        return data

    def presets(self) -> list[dict]:
        return [
            {"id": key, "label": spec["label"], "desc": spec["desc"],
             "needs_root": bool(spec.get("needs_root")),
             "warn": bool(spec.get("warn")), "timeout": spec["timeout"]}
            for key, spec in PRESETS.items()
        ]
