"""CUTOFF — network device inventory and access control backend."""
from __future__ import annotations

import atexit
import hmac
import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import Flask, Response, jsonify, request, send_from_directory

import bettercap_ctl
import config
import discovery
import netinfo
import nmapgui
import nmapscan
import platform_ops
from enforcer import Enforcer
from firewall import create as create_firewall, privileges
from store import Store, norm_mac

config.secure_data_dir()

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        # Bounded log: an unbounded cutoff.log grows without limit on a long run.
        RotatingFileHandler(config.LOG_FILE, maxBytes=5 * 1024 * 1024,
                            backupCount=5, encoding="utf-8"),
    ],
)
log = logging.getLogger("cutoff.app")

TOKEN = config.api_token()
CAN_ENFORCE, PRIV_MODE = privileges()
if config.SIMULATE == "on":
    SIMULATE = True
elif config.SIMULATE == "off":
    SIMULATE = False
else:
    SIMULATE = not CAN_ENFORCE

SETUP: dict = {}

store = Store(config.DEVICES_FILE, config.EVENTS_FILE)
iface = netinfo.current_interface()
firewall = create_firewall(simulate=SIMULATE)
enforcer = Enforcer(store, firewall, iface, SIMULATE)
nmap_runner = nmapgui.NmapRunner(store)
bettercap = bettercap_ctl.BettercapSession()

app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False

_scan_lock = threading.Lock()
_scan_state: dict = {
    "running": False,
    "phase": "idle",
    "detail": "",
    "deep": False,
    "started_at": None,
    "finished_at": None,
    "found": 0,
    "new": 0,
    "method": None,
    "error": None,
    "warnings": [],
    "nmap": {},
    "fingerprint": {},
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _auth_ok() -> bool:
    supplied = request.headers.get("X-API-Token") or request.args.get("token") or ""
    return hmac.compare_digest(supplied, TOKEN)


def require_token(view):
    from functools import wraps

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not _auth_ok():
            return jsonify({"error": "unauthorized", "detail": "missing or invalid API token"}), 401
        return view(*args, **kwargs)

    return wrapper


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def refresh_interface() -> netinfo.Interface | None:
    global iface
    iface = netinfo.current_interface()
    enforcer.iface = iface
    return iface


def merged_devices() -> list[dict]:
    own = netinfo.local_macs()
    gw_mac = iface.gateway_mac.lower() if iface and iface.gateway_mac else None
    blocks = store.blocks()
    out: list[dict] = []
    for dev in store.devices():
        mac = dev["mac"]
        block = blocks.get(mac)
        dev["blocked"] = block is not None
        dev["block"] = block
        dev["is_self"] = bool(dev.get("is_self")) or mac in own
        dev["is_gateway"] = bool(gw_mac and mac == gw_mac)
        display = dev.get("name") or dev.get("hostname") or ""
        if not display and dev["is_self"]:
            display = "This host"
        if dev["is_self"] and display.lower() == "unknown":
            display = "This host"
        if dev["is_gateway"]:
            if dev.get("device_type") in (None, "", "device"):
                dev["device_type"] = "router"
            if not display:
                vendor = (dev.get("vendor") or "").strip()
                display = f"{vendor} gateway" if vendor and vendor != "Unknown" else "Gateway"
        dev["display_name"] = display
        # A phone that missed one ping sweep is not instantly "offline": keep
        # recently confirmed devices online (nmap touches last_seen too).
        recent = (time.time() - float(dev.get("last_seen_epoch") or 0)) <= config.RECENT_WINDOW_SEC
        dev["status"] = "blocked" if block else (
            "active" if (dev.get("active") or recent) else "offline")
        out.append(dev)
    out.sort(key=lambda d: (
        0 if d["status"] == "blocked" else 1 if d["status"] == "active" else 2,
        0 if d.get("is_self") else 1,
        tuple(int(p) for p in d["ip"].split(".")) if d.get("ip") else (999,),
    ))
    return out


def status_payload() -> dict:
    iface_now = iface
    devices = merged_devices()
    return {
        "app": "CUTOFF",
        "version": config.VERSION,
        "time": _now(),
        "simulate": SIMULATE,
        "privileges": {"can_enforce": CAN_ENFORCE, "mode": PRIV_MODE},
        "platform": {**platform_ops.capabilities(), "setup": SETUP},
        "network": iface_now.as_dict() if iface_now else None,
        "topology": enforcer.topology(),
        "counts": {
            "devices": len(devices),
            "active": sum(1 for d in devices if d["status"] == "active"),
            "blocked": sum(1 for d in devices if d["status"] == "blocked"),
            "offline": sum(1 for d in devices if d["status"] == "offline"),
        },
        "capabilities": enforcer.capabilities(),
        "nmap": nmapscan.capabilities(),
        "ipv6": ipv6_summary(),
        "scan": scan_snapshot(),
        "ttl_minutes": config.BLOCK_TTL_MIN,
    }


_ipv6_cache: dict = {"at": 0.0, "data": {}}


def _invalidate_ipv6() -> None:
    """A block/unblock changed the rule set; don't serve a stale roll-up."""
    _ipv6_cache["data"] = {}
    _ipv6_cache["at"] = 0.0


def ipv6_summary(force: bool = False) -> dict:
    """IPv6 roll-up for the dashboard, cached — the probe shells out."""
    now = time.monotonic()
    if force or not _ipv6_cache["data"] or now - float(_ipv6_cache["at"]) > 15:
        try:
            _ipv6_cache["data"] = enforcer.ipv6_snapshot()
            _ipv6_cache["at"] = now
        except Exception as exc:  # noqa: BLE001 - a v6 probe must not kill /api/status
            log.warning("ipv6 snapshot failed: %s", exc)
            return {"available": bool(getattr(firewall, "ip6t", None)), "error": str(exc),
                    "neighbours": 0, "prefixes": 0, "rules": 0}
    snap = _ipv6_cache["data"]
    return {
        "available": bool(snap.get("supported")),
        "enabled": bool(snap.get("enabled")),
        "has_global": bool(snap.get("has_global")),
        "interface": snap.get("interface", ""),
        "addresses": len(snap.get("addresses") or []),
        "prefixes": len(snap.get("prefixes") or []),
        "neighbours": len(snap.get("neighbours") or []),
        "rules": len(snap.get("rules") or []),
        "prefix_rules": len(snap.get("prefix_rules") or []),
        "can_block": bool((snap.get("capabilities") or {}).get("can_block")),
        "note": snap.get("note", ""),
    }


def scan_snapshot() -> dict:
    with _scan_lock:
        return dict(_scan_state)


def _run_scan(deep: bool = False) -> None:
    with _scan_lock:
        _scan_state.update({"running": True, "phase": "discovering", "detail": "",
                            "deep": deep, "started_at": _now(),
                            "finished_at": None, "error": None, "warnings": [],
                            "found": 0, "new": 0, "method": None,
                            "nmap": {}, "fingerprint": {}})

    def progress(phase: str) -> None:
        with _scan_lock:
            _scan_state["phase"] = phase

    try:
        current = refresh_interface()
        if current is None:
            raise RuntimeError("no IPv4 default route — is the network cable/Wi-Fi up?")
        result = discovery.scan(current.name, current.ip, current.prefix,
                                deep=deep, progress=progress)
        new = store.upsert_scan(result["devices"])
        store.log(
            "scan",
            f"{'deep ' if deep else ''}scan via {result['method']}: "
            f"{len(result['devices'])} devices ({new} new) in {result['elapsed_ms']} ms",
        )
        with _scan_lock:
            _scan_state.update({
                "running": False, "phase": "done", "finished_at": _now(),
                "found": len(result["devices"]), "new": new,
                "method": result["method"], "warnings": result.get("warnings", []),
                "nmap": result.get("nmap", {}),
                "fingerprint": result.get("fingerprint", {}),
            })
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI
        log.exception("scan failed")
        store.log("scan", f"scan failed: {exc}", ok=False)
        with _scan_lock:
            _scan_state.update({"running": False, "phase": "error",
                                "finished_at": _now(), "error": str(exc)})


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _token_injection_allowed() -> bool:
    """Only the local browser gets the token baked into the page."""
    if not config.TOKEN_INJECTION:
        return False
    if config.HOST not in LOOPBACK:
        return False
    return (request.remote_addr or "") in LOOPBACK


def _render_page(name: str) -> Response:
    markup = (config.FRONTEND_DIR / name).read_text(encoding="utf-8")
    snippet = ""
    if _token_injection_allowed():
        snippet = f"<script>window.__CUTOFF_TOKEN__ = {json.dumps(TOKEN)};</script>"
    markup = markup.replace("<!--CUTOFF_TOKEN-->", snippet)
    response = Response(markup, mimetype="text/html")
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.get("/")
def index():
    return _render_page("index.html")


@app.get("/map")
def network_map():
    return _render_page("map.html")


@app.get("/nmap")
def nmap_page():
    return _render_page("nmap.html")


@app.get("/bettercap")
def bettercap_page():
    return _render_page("bettercap.html")


@app.get("/ipv6")
def ipv6_page():
    return _render_page("ipv6.html")


@app.get("/assets/<path:filename>")
def assets(filename: str):
    return send_from_directory(config.FRONTEND_DIR / "assets", filename)


@app.get("/favicon.ico")
def favicon():
    return ("", 204)


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "app": "CUTOFF", "time": _now()})


@app.get("/api/status")
@require_token
def api_status():
    return jsonify(status_payload())


@app.get("/api/devices")
@require_token
def api_devices():
    return jsonify({"devices": merged_devices(), "time": _now()})


@app.get("/api/devices/<mac>")
@require_token
def api_device(mac: str):
    try:
        wanted = norm_mac(mac)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    for device in merged_devices():
        if device["mac"] == wanted:
            return jsonify({"device": device, "time": _now()})
    return jsonify({"error": "unknown device"}), 404


@app.post("/api/scan")
@require_token
def api_scan():
    if not refresh_interface():
        return jsonify({"error": "no IPv4 network interface available"}), 503
    payload = request.get_json(silent=True) or {}
    deep = bool(payload.get("deep", False))
    with _scan_lock:
        if _scan_state["running"]:
            return jsonify({"error": "scan already running", "scan": dict(_scan_state)}), 409
    threading.Thread(target=_run_scan, args=(deep,), daemon=True, name="cutoff-scan").start()
    time.sleep(0.15)
    return jsonify({"ok": True, "scan": scan_snapshot()}), 202


@app.get("/api/scan")
@require_token
def api_scan_state():
    return jsonify(scan_snapshot())


@app.post("/api/devices/<mac>/name")
@require_token
def api_rename(mac: str):
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    if len(name) > 64:
        return jsonify({"error": "name too long (max 64 chars)"}), 400
    try:
        device = store.set_name(mac, name)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if device is None:
        return jsonify({"error": "unknown device"}), 404
    store.log("name", f"renamed {norm_mac(mac)} to {name!r}" if name else f"cleared name for {mac}",
              mac=norm_mac(mac))
    return jsonify({"ok": True, "device": device})


@app.post("/api/block")
@require_token
def api_block():
    payload = request.get_json(silent=True) or {}
    mac = str(payload.get("mac", ""))
    mode = str(payload.get("mode", "both"))
    force = bool(payload.get("force", False))
    isolation = str(payload.get("isolation", "full"))
    ip6 = payload.get("ip6", True)
    result = enforcer.block(mac, mode=mode, force=force, isolation=isolation,
                            ip6=bool(ip6),
                            ip6_prefix=bool(payload.get("ip6_prefix", False)),
                            ip6_ndp=bool(payload.get("ip6_ndp", True)))
    _invalidate_ipv6()
    return jsonify(result), (200 if result.get("ok") else 400)


@app.get("/api/ipv6")
@require_token
def api_ipv6():
    refresh_interface()
    snap = enforcer.ipv6_snapshot()
    _ipv6_cache.update({"at": time.monotonic(), "data": snap})
    return jsonify(snap)


@app.post("/api/ipv6/block")
@require_token
def api_ipv6_block():
    payload = request.get_json(silent=True) or {}
    result = enforcer.block(
        str(payload.get("mac", "")),
        mode=str(payload.get("mode", "both")),
        force=bool(payload.get("force", False)),
        isolation=str(payload.get("isolation", "full")),
        ip6=True,
        ip6_prefix=bool(payload.get("ip6_prefix", False)),
    )
    _invalidate_ipv6()
    return jsonify(result), (200 if result.get("ok") else 400)


@app.post("/api/ipv6/unblock")
@require_token
def api_ipv6_unblock():
    payload = request.get_json(silent=True) or {}
    result = enforcer.unblock(str(payload.get("mac", "")))
    _invalidate_ipv6()
    return jsonify(result), (200 if result.get("ok") else 400)


@app.post("/api/ipv6/prefix")
@require_token
def api_ipv6_prefix_block():
    payload = request.get_json(silent=True) or {}
    result = enforcer.block_ipv6_prefix(str(payload.get("prefix", "")),
                                        force=bool(payload.get("force", False)))
    _invalidate_ipv6()
    return jsonify(result), (200 if result.get("ok") else 400)


@app.post("/api/ipv6/prefix/unblock")
@require_token
def api_ipv6_prefix_unblock():
    payload = request.get_json(silent=True) or {}
    result = enforcer.unblock_ipv6_prefix(str(payload.get("prefix", "")))
    _invalidate_ipv6()
    return jsonify(result), (200 if result.get("ok") else 400)


@app.post("/api/unblock")
@require_token
def api_unblock():
    payload = request.get_json(silent=True) or {}
    result = enforcer.unblock(str(payload.get("mac", "")))
    return jsonify(result), (200 if result.get("ok") else 400)


@app.post("/api/wifi/cut")
@require_token
def api_wifi_cut():
    payload = request.get_json(silent=True) or {}
    try:
        seconds = int(payload.get("seconds", 8))
    except (TypeError, ValueError):
        seconds = 8
    result = enforcer.cut_wifi(
        str(payload.get("mac", "")),
        bssid=(str(payload["bssid"]).strip() or None) if payload.get("bssid") else None,
        seconds=max(1, min(seconds, 60)),
    )
    return jsonify(result), (200 if result.get("ok") else 400)


@app.post("/api/panic")
@require_token
def api_panic():
    result = enforcer.panic()
    _invalidate_ipv6()
    return jsonify(result)




@app.get("/api/nmap")
@require_token
def api_nmap():
    current = refresh_interface()
    return jsonify({
        "capabilities": nmapscan.capabilities(),
        "presets": nmap_runner.presets(),
        "targets": nmap_runner.targets(current) if current else [],
        "status": nmap_runner.status(),
        "network": current.network if current else "",
    })


@app.post("/api/nmap/run")
@require_token
def api_nmap_run():
    current = refresh_interface()
    if current is None:
        return jsonify({"error": "no IPv4 network interface available"}), 503
    payload = request.get_json(silent=True) or {}
    preset = str(payload.get("preset", "fast"))
    target = str(payload.get("target", "subnet"))
    custom = str(payload.get("custom", ""))
    ok, message = nmap_runner.start(preset, target, custom, current)
    if not ok:
        return jsonify({"ok": False, "error": message}), 400
    store.log("nmap", message)
    return jsonify({"ok": True, "message": message, "status": nmap_runner.status()}), 202


@app.post("/api/nmap/stop")
@require_token
def api_nmap_stop():
    result = nmap_runner.stop()
    store.log("nmap", "scan stopped")
    return jsonify(result)


@app.get("/api/bettercap")
@require_token
def api_bettercap():
    current = refresh_interface()
    payload = bettercap.status()
    payload["iface"] = current.name if current else ""
    payload["network"] = current.network if current else ""
    payload["devices"] = [
        {"ip": d["ip"], "mac": d["mac"],
         "name": d.get("display_name") or d.get("hostname") or d["ip"]}
        for d in merged_devices() if d.get("active") and d.get("ip")
    ]
    return jsonify(payload)


@app.post("/api/bettercap/start")
@require_token
def api_bettercap_start():
    current = refresh_interface()
    if current is None:
        return jsonify({"error": "no IPv4 network interface available"}), 503
    body = request.get_json(silent=True) or {}
    preset = str(body.get("preset", "recon"))
    targets = str(body.get("targets", "")).strip()
    if targets:
        known = {d.get("ip") for d in store.devices()}
        for ip in [t.strip() for t in targets.split(",") if t.strip()]:
            if ip not in known:
                return jsonify({"error": f"{ip} is not in the inventoried LAN"}), 400
    ok, message = bettercap.start(preset, current.name, targets)
    if not ok:
        return jsonify({"ok": False, "error": message}), 400
    store.log("bettercap", message)
    return jsonify({"ok": True, "message": message, "status": bettercap.status()}), 202


@app.post("/api/bettercap/stop")
@require_token
def api_bettercap_stop():
    result = bettercap.stop()
    store.log("bettercap", "session stopped")
    return jsonify(result)


@app.post("/api/bettercap/clear")
@require_token
def api_bettercap_clear():
    bettercap.clear_log()
    return jsonify({"ok": True})


@app.get("/api/events")
@require_token
def api_events():
    try:
        limit = max(1, min(int(request.args.get("limit", 60)), 500))
    except ValueError:
        limit = 60
    return jsonify({"events": store.events(limit)})


@app.delete("/api/events")
@require_token
def api_events_clear():
    store.clear_events()
    return jsonify({"ok": True})


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not found"}), 404
    return Response("Not found", status=404, mimetype="text/plain")


@app.errorhandler(500)
def server_error(exc):
    log.exception("unhandled error: %s", exc)
    return jsonify({"error": "internal error"}), 500


def _shutdown() -> None:
    """Restore ARP state but leave intentional firewall blocks in place."""
    with enforcer._lock:  # noqa: SLF001 - controlled shutdown
        interceptors = list(enforcer._interceptors.values())
        enforcer._interceptors.clear()
    for interceptor in interceptors:
        try:
            interceptor.stop()
        except Exception:  # noqa: BLE001
            pass


atexit.register(_shutdown)

BANNER = r"""
  ____ _   _ _____ _____ ____  _____
 / ___| | | |_   _|  ___|  _ \|  ___|
| |   | | | | | | | |_  | | | | |_
| |___| |_| | | | |  _| | |_| |  _|
 \____|\___/  |_| |_|   |____/|_|

  network device control  ·  http://{host}:{port}
  mode: {mode}   interface: {iface}
  token: {token_file}
"""


def main() -> None:
    global SETUP
    SETUP = platform_ops.ensure(log_output=log.info)
    refresh_interface()
    mode = "SIMULATION (no rules applied)" if SIMULATE else f"LIVE ({PRIV_MODE})"
    print(BANNER.format(
        host=config.HOST, port=config.PORT, mode=mode,
        iface=iface.name if iface else "none",
        platform_name=SETUP.get("platform", "?"),
        driver=(("Npcap ready" if SETUP.get("npcap") else "Npcap missing")
                if SETUP.get("windows") else "native"),
        token_file=config.TOKEN_FILE,
    ))
    for warning in SETUP.get("warnings", []):
        print(f"  setup warning: {warning}")
    if SIMULATE:
        hint = ("Run run.bat as Administrator" if platform_ops.IS_WINDOWS
                else "Use sudo for live control")
        print(f"  Unprivileged run: blocks are modelled, not enforced. {hint}.\n")
    else:
        restored = enforcer.restore_blocks()
        if restored["restored"] or restored["failed"]:
            print(f"  re-applied {restored['restored']} persisted block(s); "
                  f"{len(restored['failed'])} failed\n")
    if config.HOST not in ("127.0.0.1", "localhost", "::1"):
        log.warning("binding to %s exposes the API beyond localhost", config.HOST)
    try:
        snap = enforcer.ipv6_snapshot()
        own6 = [a["address"] for a in snap.get("addresses", []) if a.get("class") == "global"]
        print(f"  ipv6: {'on' if snap.get('enabled') else 'off'} · "
              f"{len(own6)} global · {len(snap.get('neighbours', []))} neighbours · "
              f"ip6tables {'ready' if (snap.get('capabilities', {}).get('ip6tables') or {}).get('available') else 'missing'}")
    except Exception as exc:  # noqa: BLE001 - a probe must not block startup
        log.warning("ipv6 probe failed: %s", exc)
    _serve()


def _serve() -> None:
    """Waitress in front of Flask: the dev server is single-process and noisy."""
    try:
        from waitress import serve
    except ImportError:
        print("  [warn] waitress not installed - falling back to the Flask development "
              "server (pip install -r backend/requirements.txt)\n")
        app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)
        return
    log.info("serving via waitress on %s:%s", config.HOST, config.PORT)
    serve(app, host=config.HOST, port=config.PORT, threads=8, ident="CUTOFF",
          clear_untrusted_proxy_headers=True)


if __name__ == "__main__":
    main()
