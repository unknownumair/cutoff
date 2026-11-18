"""Portable bettercap controller — bundled binary, fixed presets, live log."""
from __future__ import annotations

import collections
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

import platform_ops

log = logging.getLogger("cutoff.bettercap")

PROJECT = Path(__file__).resolve().parent.parent
VENDOR = PROJECT / "vendor" / "bettercap" / "bettercap"
WIN_VENDOR = PROJECT / "vendor" / "bettercap" / "win64"
_WIN_BIN: str | None = None

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

PRESETS: dict[str, dict] = {
    "recon": {
        "label": "Network recon",
        "desc": "Passive/active host discovery with net.probe and net.show.",
        "commands": ["net.probe on", "net.show"],
        "needs_root": True,
    },
    "sniff": {
        "label": "Sniff traffic",
        "desc": "Capture packets on the interface without ARP spoofing.",
        "commands": ["net.sniff on"],
        "needs_root": True,
    },
    "monitor": {
        "label": "Full LAN monitor",
        "desc": "ARP-spoof all targets + sniff. Puts this host in-path for the LAN.",
        "commands": [
            "set arp.spoof.fullduplex true",
            "net.probe on",
            "arp.spoof on",
            "net.sniff on",
            "set net.sniff.verbose false",
        ],
        "needs_root": True,
        "warn": True,
    },
    "http": {
        "label": "HTTP proxy",
        "desc": "Transparent HTTP proxy with sniffing (MITM; own network only).",
        "commands": ["http.proxy on", "net.sniff on"],
        "needs_root": True,
        "warn": True,
    },
}


def _win_binary() -> str | None:
    global _WIN_BIN
    if _WIN_BIN is not None:
        return _WIN_BIN
    found = next(WIN_VENDOR.rglob("bettercap.exe"), None) if WIN_VENDOR.is_dir() else None
    _WIN_BIN = str(found) if found else ""
    return _WIN_BIN or None


def _env() -> dict:
    env = os.environ.copy()
    if not platform_ops.IS_WINDOWS:
        lib = PROJECT / "vendor" / "bettercap" / "lib"
        if lib.is_dir():
            env["LD_LIBRARY_PATH"] = f"{lib}:{env.get('LD_LIBRARY_PATH', '')}".rstrip(":")
    return env


def locate() -> str | None:
    candidates = [os.environ.get("CUTOFF_BETTERCAP"),
                  _win_binary() if platform_ops.IS_WINDOWS else None,
                  str(VENDOR), shutil.which("bettercap"), "/usr/bin/bettercap"]
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file():
            continue
        if platform_ops.IS_WINDOWS or os.access(candidate, os.X_OK):
            return candidate
    return None


def version() -> str:
    binary = locate()
    if not binary:
        return ""
    try:
        kwargs = {"capture_output": True, "text": True, "timeout": 8, "env": _env()}
        if platform_ops.IS_WINDOWS:
            kwargs["creationflags"] = platform_ops.CREATE_NO_WINDOW
        cp = subprocess.run([binary, "-version"], **kwargs)
        text = (cp.stdout or "") + (cp.stderr or "")
        for line in text.splitlines():
            if "bettercap" in line.lower() or "version" in line.lower():
                return line.strip()[:120]
        return text.strip().splitlines()[0][:120] if text.strip() else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def capabilities() -> dict:
    binary = locate()
    return {
        "available": bool(binary),
        "path": binary or "",
        "version": version() if binary else "",
        "privileged": platform_ops.is_admin(),
        "npcap": platform_ops.npcap_installed(),
        "presets": [
            {"id": key, "label": spec["label"], "desc": spec["desc"],
             "warn": bool(spec.get("warn")), "needs_root": bool(spec.get("needs_root"))}
            for key, spec in PRESETS.items()
        ],
        "note": ("" if binary else "bettercap binary missing — run run.bat / "
                 "tools/install-bettercap.sh") + (
                 "" if (not platform_ops.IS_WINDOWS or platform_ops.npcap_installed())
                 else " · Npcap missing — run run.bat as Administrator"),
    }


class BettercapSession:
    def __init__(self):
        self._lock = threading.RLock()
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self.log: collections.deque[str] = collections.deque(maxlen=600)
        self.state = {
            "running": False, "preset": "", "iface": "", "started_at": 0.0,
            "targets": "", "error": "", "pid": 0,
        }

    def _spawn(self, iface: str) -> tuple[bool, str]:
        binary = locate()
        if not binary:
            return False, "bettercap binary missing"
        if not platform_ops.is_admin():
            return False, ("bettercap needs Administrator (run run.bat as Administrator)"
                           if platform_ops.IS_WINDOWS else "bettercap needs root (restart with sudo)")
        try:
            kwargs = {
                "stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT, "text": True, "bufsize": 1,
                "env": _env(),
            }
            if platform_ops.IS_WINDOWS:
                kwargs["creationflags"] = platform_ops.CREATE_NO_WINDOW
            self._proc = subprocess.Popen(
                [binary, "-iface", iface, "-no-colors", "-no-history"], **kwargs)
        except OSError as exc:
            return False, str(exc)
        self._reader = threading.Thread(target=self._read, daemon=True,
                                        name="cutoff-bettercap")
        self._reader.start()
        return True, "started"

    def _read(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            cleaned = ANSI.sub("", line).rstrip()
            if cleaned:
                with self._lock:
                    self.log.append(cleaned)
        with self._lock:
            if self.state["running"]:
                self.state["running"] = False
                self.state["error"] = "bettercap exited"

    def _send(self, command: str) -> None:
        if not self._proc or not self._proc.stdin:
            return
        try:
            self._proc.stdin.write(command + "\n")
            self._proc.stdin.flush()
            with self._lock:
                self.log.append(f"» {command}")
        except (BrokenPipeError, OSError):
            pass

    def start(self, preset: str, iface: str, targets: str = "") -> tuple[bool, str]:
        if preset not in PRESETS:
            return False, "unknown preset"
        with self._lock:
            if self.state["running"]:
                return False, "bettercap is already running"
        ok, message = self._spawn(iface)
        if not ok:
            return False, message
        with self._lock:
            self.state = {
                "running": True, "preset": preset, "iface": iface,
                "started_at": time.time(), "targets": targets, "error": "",
                "pid": self._proc.pid if self._proc else 0,
            }
        time.sleep(0.8)
        if targets:
            self._send(f"set arp.spoof.targets {targets}")
        for command in PRESETS[preset]["commands"]:
            self._send(command)
            time.sleep(0.15)
        return True, f"{PRESETS[preset]['label']} started on {iface}"

    def stop(self) -> dict:
        with self._lock:
            proc = self._proc
        was_running = bool(proc and proc.poll() is None)
        if was_running:
            for command in ("arp.spoof off", "net.sniff off", "http.proxy off", "quit"):
                self._send(command)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        with self._lock:
            self.state["running"] = False
            self._proc = None
        return {"ok": True, "stopped": was_running}

    def status(self) -> dict:
        with self._lock:
            data = dict(self.state)
            data["log"] = list(self.log)[-250:]
            data["capabilities"] = capabilities()
        return data

    def clear_log(self) -> None:
        with self._lock:
            self.log.clear()
