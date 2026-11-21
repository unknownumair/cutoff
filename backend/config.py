"""CUTOFF configuration and filesystem layout."""
from __future__ import annotations

import os
import pathlib
import secrets

def _env(name: str, default: str) -> str:
    """CUTOFF_* wins; the pre-rename NPENT_* name still resolves, so existing
    shells, systemd units and run scripts keep working after the rename."""
    value = os.environ.get(f"CUTOFF_{name}")
    if value is None:
        value = os.environ.get(f"NPENT_{name}")
    return default if value is None else value


BASE_DIR = pathlib.Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"
DATA_DIR = pathlib.Path(_env("DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

HOST = _env("HOST", "127.0.0.1")
PORT = int(_env("PORT", "8848"))
# auto  -> simulate only when the process lacks the privileges to enforce rules
# on    -> always simulate (safe UI demo)
# off   -> never simulate; enforcement errors are reported to the caller
SIMULATE = _env("SIMULATE", "auto").lower()
LOG_LEVEL = _env("LOG_LEVEL", "INFO").upper()
# Bake the API token into the page for loopback clients so the dashboard opens
# without a paste step. Disable when binding beyond 127.0.0.1.
TOKEN_INJECTION = _env("TOKEN_INJECTION", "1") not in ("0", "false", "no")

# Safety rails ---------------------------------------------------------------
BLOCK_TTL_MIN = int(_env("BLOCK_TTL_MIN", "0"))  # 0 = until unblocked
POISON_REFRESH_SEC = float(_env("POISON_REFRESH", "2"))
POISON_MAX_MIN = int(_env("POISON_MAX_MIN", "120"))
SCAN_CONCURRENCY = int(_env("SCAN_CONCURRENCY", "64"))
SCAN_MAX_HOSTS = int(_env("SCAN_MAX_HOSTS", "1024"))
# Keep a device "online" for this long after its last confirmed sighting, so a
# sleeping phone does not flap offline between scans.
RECENT_WINDOW_SEC = int(_env("RECENT_SEC", "300"))
# How often an active block re-reads the LAN peer list, so a device that joins
# or is scanned after the block is poisoned too.
PEER_REFRESH_SEC = float(_env("PEER_REFRESH", "10"))

DEVICES_FILE = DATA_DIR / "devices.json"
EVENTS_FILE = DATA_DIR / "events.jsonl"
TOKEN_FILE = DATA_DIR / "api_token"
LOG_FILE = DATA_DIR / "cutoff.log"


def version() -> str:
    """Single source of truth: the VERSION file beside the project root."""
    for candidate in (PROJECT_DIR / "VERSION", BASE_DIR.parent / "VERSION"):
        try:
            text = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text.splitlines()[0][:32]
    return "0.0.0"


VERSION = version()


def secure_data_dir() -> None:
    """Tighten permissions on the inventory and the log.

    The inventory lists every MAC/IP on the LAN and the log repeats it; both
    were created world-readable by older builds. Best effort: a chmod failure
    must not stop the service.
    """
    try:
        DATA_DIR.chmod(0o700)
    except OSError:
        pass
    for path in (DEVICES_FILE, EVENTS_FILE, TOKEN_FILE, LOG_FILE):
        if not path.exists():
            continue
        try:
            path.chmod(0o600)
        except OSError:
            pass


def api_token() -> str:
    """Return the API token, creating a 0600 file on first run."""
    env = _env("TOKEN", "") or None
    if env:
        return env.strip()
    if TOKEN_FILE.exists():
        tok = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(tok + "\n", encoding="utf-8")
    try:
        TOKEN_FILE.chmod(0o600)
    except OSError:
        pass
    return tok
