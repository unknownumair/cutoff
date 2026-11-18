"""Cross-platform OS helpers: privileges, commands, Npcap and portable tools.

Linux needs no setup: the firewall is iptables and raw sockets come from the
kernel. Windows needs Npcap for ARP injection/sniffing plus portable nmap and
bettercap builds; ``ensure()`` downloads and installs those on first start.
"""
from __future__ import annotations

import ctypes
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

log = logging.getLogger("cutoff.platform")

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
PROJECT = Path(__file__).resolve().parent.parent
VENDOR = PROJECT / "vendor"
NPCAP_VERSION = "1.90"
NPCAP_URL = f"https://npcap.com/dist/npcap-{NPCAP_VERSION}.exe"
NMAP_WIN_URL = "https://nmap.org/dist/nmap-7.92-win32.zip"
BETTERCAP_WIN_URL = ("https://github.com/bettercap/bettercap/releases/download/"
                     "v2.41.7/bettercap_windows_amd64.zip")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def run(cmd: list[str], timeout: float = 15.0, env: dict | None = None,
        cwd: str | None = None) -> tuple[int, str, str]:
    """Run a command without flashing console windows on Windows."""
    kwargs: dict = {
        "capture_output": True, "text": True, "timeout": timeout,
        "env": env, "cwd": cwd,
    }
    if IS_WINDOWS:
        kwargs["creationflags"] = CREATE_NO_WINDOW
    try:
        cp = subprocess.run(cmd, **kwargs)
        return cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def powershell(script: str, timeout: float = 15.0) -> tuple[int, str, str]:
    return run(["powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", script], timeout=timeout)


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001 - missing shell32 in odd environments
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def privilege_label() -> str:
    if IS_WINDOWS:
        return "administrator" if is_admin() else "unprivileged"
    try:
        if os.geteuid() == 0:
            return "root"
    except AttributeError:
        pass
    try:
        cp = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        if cp.returncode == 0:
            return "sudo"
    except (OSError, subprocess.SubprocessError):
        pass
    return "unprivileged"


def npcap_installed() -> bool:
    if not IS_WINDOWS:
        return True
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    return ((system32 / "Npcap" / "wpcap.dll").is_file()
            or (system32 / "wpcap.dll").is_file())


def _download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size > 1024:
        return dest
    log.info("downloading %s", url)
    partial = dest.with_name(dest.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "CUTOFF/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=120) as resp, partial.open("wb") as fh:
            shutil.copyfileobj(resp, fh, length=1024 * 256)
        partial.replace(dest)
    finally:
        partial.unlink(missing_ok=True)
    return dest


def install_npcap() -> tuple[bool, str]:
    """Silent Npcap install. Requires Administrator; never called on Linux."""
    if not IS_WINDOWS:
        return True, "not needed on Linux"
    if npcap_installed():
        return True, "Npcap already installed"
    if not is_admin():
        return False, "administrator rights are required to install Npcap"
    try:
        installer = _download(NPCAP_URL, VENDOR / "npcap" / f"npcap-{NPCAP_VERSION}.exe")
    except OSError as exc:
        return False, f"Npcap download failed: {exc}"
    rc, out, err = run([str(installer), "/S", "/winpcap_mode=yes"], timeout=300)
    for _ in range(30):
        if npcap_installed():
            return True, "Npcap installed (winpcap-compatible mode)"
        time.sleep(1)
    detail = (err or out or f"installer exit {rc}")[:300]
    return False, f"Npcap install did not complete: {detail}"


def _zip_ok(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.testzip() is None
    except (OSError, zipfile.BadZipFile):
        return False


def _find(root: Path, name: str) -> Path | None:
    if not root.is_dir():
        return None
    direct = root / name
    if direct.is_file():
        return direct
    return next(root.rglob(name), None)


def ensure_nmap() -> tuple[bool, str]:
    if not IS_WINDOWS:
        if (VENDOR / "nmap" / "usr" / "bin" / "nmap").is_file():
            return True, "bundled nmap"
        return False, "run tools/install-nmap-rpm.sh"
    existing = _find(VENDOR / "nmap" / "win32", "nmap.exe")
    if existing:
        return True, str(existing)
    archive = VENDOR / "nmap" / "nmap-win32.zip"
    if archive.exists() and not _zip_ok(archive):
        archive.unlink(missing_ok=True)
    for attempt in (1, 2):
        try:
            archive = _download(NMAP_WIN_URL, archive)
            target = VENDOR / "nmap" / "win32"
            target.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(target)
            archive.unlink(missing_ok=True)
            break
        except (OSError, zipfile.BadZipFile) as exc:
            archive.unlink(missing_ok=True)
            if attempt == 2:
                return False, f"nmap download failed: {exc}"
    found = _find(VENDOR / "nmap" / "win32", "nmap.exe")
    return (True, str(found)) if found else (False, "nmap.exe not found in archive")


def ensure_bettercap() -> tuple[bool, str]:
    if not IS_WINDOWS:
        binary = VENDOR / "bettercap" / "bettercap"
        return (True, str(binary)) if binary.is_file() else (False, "run tools/install-bettercap.sh")
    existing = _find(VENDOR / "bettercap" / "win64", "bettercap.exe")
    if existing:
        return True, str(existing)
    archive = VENDOR / "bettercap" / "bettercap-win.zip"
    if archive.exists() and not _zip_ok(archive):
        archive.unlink(missing_ok=True)
    for attempt in (1, 2):
        try:
            archive = _download(BETTERCAP_WIN_URL, archive)
            target = VENDOR / "bettercap" / "win64"
            target.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(target)
            archive.unlink(missing_ok=True)
            break
        except (OSError, zipfile.BadZipFile) as exc:
            archive.unlink(missing_ok=True)
            if attempt == 2:
                return False, f"bettercap download failed: {exc}"
    found = _find(VENDOR / "bettercap" / "win64", "bettercap.exe")
    return (True, str(found)) if found else (False, "bettercap.exe not found in archive")


def ensure_scapy() -> tuple[bool, str]:
    try:
        import scapy  # noqa: F401
        return True, "scapy available"
    except ImportError:
        pass
    if not IS_WINDOWS:
        return False, "scapy not installed (only needed on Windows)"
    rc, _, err = run([sys.executable, "-m", "pip", "install", "scapy"], timeout=300)
    if rc == 0:
        return True, "scapy installed"
    return False, f"scapy install failed: {err[:200]}"


def ensure(log_output=print) -> dict:
    """Provision drivers and portable tools. Safe to call on every start."""
    result: dict = {
        "platform": platform.system(),
        "windows": IS_WINDOWS,
        "admin": is_admin(),
        "npcap": npcap_installed() if IS_WINDOWS else None,
        "scapy": False,
        "nmap": False,
        "bettercap": False,
        "warnings": [],
    }
    if not IS_WINDOWS:
        result["nmap"], result["nmap_detail"] = ensure_nmap()
        result["bettercap"], result["bettercap_detail"] = ensure_bettercap()
        result["mode"] = "linux-native"
        return result

    log_output("[setup] checking Npcap driver...")
    ok, msg = install_npcap()
    result["npcap"] = npcap_installed()
    log_output(f"[setup] Npcap: {msg}")
    if not ok:
        result["warnings"].append(msg)
    if result["npcap"]:
        ok, msg = ensure_scapy()
        result["scapy"] = ok
        log_output(f"[setup] scapy: {msg}")
        if not ok:
            result["warnings"].append(msg)
    for key, fn in (("nmap", ensure_nmap), ("bettercap", ensure_bettercap)):
        log_output(f"[setup] checking portable {key}...")
        ok, msg = fn()
        result[key] = ok
        result[f"{key}_detail"] = msg
        log_output(f"[setup] {key}: {msg}")
        if not ok:
            result["warnings"].append(msg)
    result["mode"] = "windows-native" if result["npcap"] else "windows-limited"
    return result


def capabilities() -> dict:
    return {
        "platform": platform.system(),
        "windows": IS_WINDOWS,
        "admin": is_admin(),
        "privilege_mode": privilege_label(),
        "npcap": npcap_installed() if IS_WINDOWS else None,
        "raw_capture": (not IS_WINDOWS) or npcap_installed(),
        "portable_tools": {
            "nmap": bool(_find(VENDOR / "nmap", "nmap.exe" if IS_WINDOWS else "nmap")),
            "bettercap": bool(_find(VENDOR / "bettercap",
                                    "bettercap.exe" if IS_WINDOWS else "bettercap")),
        },
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print(ensure())
