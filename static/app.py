"""
Nagini Protocol — Flask REST API + Web UI

Endpoints:
  GET  /                          — Web UI
  GET  /api/status                — health check
  POST /api/setup                 — create bundle
  POST /api/recover/shard         — decrypt one shard
  POST /api/recover/reconstruct   — reconstruct secret from shards
  GET  /api/bundles               — list stored bundles
  GET  /api/bundle/<id>           — bundle info

  SOS:
  POST /api/sos/config            — create SOS profile
  POST /api/sos/checkin           — Dead Man's Switch check-in
  POST /api/sos/trigger           — manual SOS trigger
  POST /api/sos/pin               — verify PIN (real vs duress)
  GET  /api/sos/status/<id>       — DMS status
"""

import os
import sys
import json
import hashlib
import datetime
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory

sys.path.insert(0, str(Path(__file__).parent))

from nagini_core import nagini_setup, nagini_recover_shard, nagini_reconstruct
from nagini_storage import save_blobs, load_blobs, list_bundles
from nagini_canary import (
    save_canary_config, load_canary_config, has_canary_config,
    generate_fake_shard, fire_canary_alert,
)
from nagini_sos import (
    save_sos_config, load_sos_config, list_sos_profiles,
    hash_pin, is_duress_pin, is_real_pin,
    broadcast_sos, dead_man_switch, SOS_DIR,
)


app = Flask(__name__, static_folder="static", static_url_path="")


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def ok(data: dict = None, **kwargs):
    payload = {"ok": True}
    if data:
        payload.update(data)
    payload.update(kwargs)
    return jsonify(payload)


def err(message: str, code: int = 400):
    return jsonify({"ok": False, "error": message}), code


def require_json(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return err("Request must be JSON")
        return f(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────
# Web UI
# ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    static_dir = Path(__file__).parent / "static"
    return send_from_directory(str(static_dir), "index.html")


@app.route("/mobile")
def mobile():
    static_dir = Path(__file__).parent / "static"
    return send_from_directory(str(static_dir), "mobile.html")


@app.route("/manifest.json")
def manifest():
    static_dir = Path(__file__).parent / "static"
    return send_from_directory(str(static_dir), "manifest.json")


@app.route("/icon.png")
def icon_route():
    static_dir = Path(__file__).parent / "static"
    return send_from_directory(str(static_dir), "icon.png")


# ─────────────────────────────────────────────────────────
# Status
# ─────────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    return ok(
        version="1.0.0",
        protocol="Nagini Protocol",
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        bundles=len(list_bundles()),
        sos_profiles=len(list_sos_profiles()),
    )


# ─────────────────────────────────────────────────────────
# Bundle management
# ─────────────────────────────────────────────────────────

@app.route("/api/bundles")
def get_bundles():
    bundles = []
    for pid in list_bundles():
        blobs = load_blobs(pid)
        if blobs:
            b = blobs[0]
            bundles.append({
                "public_id": pid,
                "total_shards": b.total_shards,
                "threshold": b.threshold,
                "has_canary": has_canary_config(pid),
            })
    return ok(bundles=bundles)


@app.route("/api/bundle/<public_id>")
def get_bundle(public_id):
    blobs = load_blobs(public_id)
    if not blobs:
        return err("Bundle not found", 404)
    b = blobs[0]
    return ok(
        public_id=public_id,
        total_shards=b.total_shards,
        threshold=b.threshold,
        tile_size=b.tile_size,
        has_canary=has_canary_config(public_id),
        shards=[{"index": blob.shard_index} for blob in blobs],
    )


# ─────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────

@app.route("/api/setup", methods=["POST"])
@require_json
def api_setup():
    """
    POST /api/setup
    {
        "secret_hex": "...",           # hex-encoded secret
        "locations": [[lat, lon], ...],
        "threshold": 3,
        "canary": {                    # optional
            "shard_index": 4,
            "passphrase": "...",
            "contacts": [{"telegram_token": "...", "telegram_chat_id": "..."}],
            "webhook_url": "..."
        }
    }
    """
    data = request.json

    # Secret
    secret_hex = data.get("secret_hex", "")
    if not secret_hex:
        # Also accept passphrase
        phrase = data.get("passphrase", "")
        if not phrase:
            return err("Provide secret_hex or passphrase")
        secret = hashlib.sha3_256(phrase.encode()).digest()
    else:
        try:
            secret = bytes.fromhex(secret_hex)
        except ValueError:
            return err("Invalid secret_hex")

    # Locations
    raw_locs = data.get("locations", [])
    if len(raw_locs) < 2:
        return err("Need at least 2 locations")
    try:
        locations = [(float(lat), float(lon)) for lat, lon in raw_locs]
    except (ValueError, TypeError):
        return err("Invalid location format. Use [[lat, lon], ...]")

    # Threshold
    n = len(locations)
    threshold = int(data.get("threshold", n - 1))
    if not (2 <= threshold < n):
        return err(f"Threshold must be 2 ≤ K < N. Got K={threshold}, N={n}")

    # Run setup
    try:
        blobs, public_id = nagini_setup(secret, locations, threshold)
        save_blobs(blobs)
    except Exception as e:
        return err(f"Setup failed: {e}", 500)

    # Canary config
    canary_data = data.get("canary")
    canary_saved = False
    if canary_data:
        try:
            canary_idx  = int(canary_data["shard_index"])
            canary_pass = canary_data["passphrase"]
            alert_cfg   = {
                "telegram_token":   canary_data.get("telegram_token", ""),
                "telegram_chat_id": canary_data.get("telegram_chat_id", ""),
                "webhook_url":      canary_data.get("webhook_url", ""),
            }
            save_canary_config(public_id, canary_idx, alert_cfg, canary_pass)
            canary_saved = True
        except Exception as e:
            pass  # Non-fatal

    return ok(
        public_id=public_id,
        total_shards=n,
        threshold=threshold,
        canary_configured=canary_saved,
    )


# ─────────────────────────────────────────────────────────
# Recovery
# ─────────────────────────────────────────────────────────

@app.route("/api/recover/shard", methods=["POST"])
@require_json
def api_recover_shard():
    """
    POST /api/recover/shard
    {
        "public_id": "...",
        "shard_index": 2,
        "lat": 48.9226,
        "lon": 24.7111,
        "canary_passphrase": "..."    # optional
    }
    Returns: { "ok": true, "shard_hex": "...", "shard_index": 2 }
    """
    data = request.json
    public_id   = data.get("public_id", "")
    shard_index = int(data.get("shard_index", 0))
    lat = float(data.get("lat", 0))
    lon = float(data.get("lon", 0))

    blobs = load_blobs(public_id)
    if not blobs:
        return err("Bundle not found", 404)

    blob = next((b for b in blobs if b.shard_index == shard_index), None)
    if not blob:
        return err(f"Shard #{shard_index} not found in bundle")

    shard_data = nagini_recover_shard(blob, lat, lon)
    if shard_data is None:
        return err("Decryption failed. Coordinates too far from setup location (>200m).", 422)

    # Canary check
    canary_pass = data.get("canary_passphrase", "")
    canary_triggered = False
    if has_canary_config(public_id) and canary_pass:
        cfg = load_canary_config(public_id, canary_pass)
        if cfg and cfg.get("canary_shard_index") == shard_index:
            fire_canary_alert(public_id, shard_index, cfg.get("alert_config", {}))
            shard_data = generate_fake_shard(len(shard_data), public_id, shard_index)
            canary_triggered = True

    return ok(
        shard_index=shard_index,
        shard_hex=shard_data.hex(),
        canary_triggered=canary_triggered,
    )


@app.route("/api/recover/reconstruct", methods=["POST"])
@require_json
def api_recover_reconstruct():
    """
    POST /api/recover/reconstruct
    {
        "shares": [
            {"index": 1, "shard_hex": "..."},
            {"index": 2, "shard_hex": "..."},
            {"index": 3, "shard_hex": "..."}
        ]
    }
    Returns: { "ok": true, "secret_hex": "..." }
    """
    data   = request.json
    shares = data.get("shares", [])

    if len(shares) < 2:
        return err("Need at least 2 shares")

    try:
        parsed = [(int(s["index"]), bytes.fromhex(s["shard_hex"])) for s in shares]
        secret = nagini_reconstruct(parsed)
        return ok(secret_hex=secret.hex(), bits=len(secret) * 8)
    except Exception as e:
        return err(f"Reconstruction failed: {e}", 422)


# ─────────────────────────────────────────────────────────
# SOS API
# ─────────────────────────────────────────────────────────

@app.route("/api/sos/config", methods=["POST"])
@require_json
def api_sos_config():
    """
    POST /api/sos/config
    {
        "profile_id": "myprofile",
        "owner_name": "Stas",
        "passphrase": "...",
        "real_pin": "1234",
        "duress_pin": "9999",
        "deadman_interval_hours": 24,
        "escalation_levels": [1, 6, 24],
        "emergency_message": "I have been kidnapped.",
        "contacts": [
            {
                "name": "Alice",
                "telegram_token": "...",
                "telegram_chat_id": "..."
            }
        ]
    }
    """
    data = request.json

    profile_id = data.get("profile_id", "")
    passphrase = data.get("passphrase", "")
    if not profile_id or not passphrase:
        return err("profile_id and passphrase required")

    real_pin   = str(data.get("real_pin", ""))
    duress_pin = str(data.get("duress_pin", ""))

    if real_pin == duress_pin:
        return err("Real PIN and duress PIN must be different")

    config = {
        "profile_id":              profile_id,
        "owner_name":              data.get("owner_name", "Unknown"),
        "real_pin_hash":           hash_pin(real_pin)   if real_pin   else "",
        "duress_pin_hash":         hash_pin(duress_pin) if duress_pin else "",
        "deadman_interval_hours":  int(data.get("deadman_interval_hours", 24)),
        "escalation_levels":       data.get("escalation_levels", [1, 6, 24]),
        "emergency_message":       data.get("emergency_message", ""),
        "contacts":                data.get("contacts", []),
    }

    try:
        path = save_sos_config(config, passphrase)
        return ok(profile_id=profile_id, config_path=str(path))
    except Exception as e:
        return err(f"Failed to save SOS config: {e}", 500)


@app.route("/api/sos/checkin", methods=["POST"])
@require_json
def api_sos_checkin():
    """
    POST /api/sos/checkin
    { "profile_id": "myprofile" }
    """
    profile_id = request.json.get("profile_id", "")
    if not profile_id:
        return err("profile_id required")

    state = dead_man_switch.checkin(profile_id)
    return ok(
        profile_id=profile_id,
        last_checkin=state["last_checkin"],
        missed_count=state["missed_count"],
    )


@app.route("/api/sos/status/<profile_id>")
def api_sos_status(profile_id):
    state = dead_man_switch.get_state(profile_id)

    last_str = state.get("last_checkin")
    hours_since = None
    if last_str:
        last = datetime.datetime.fromisoformat(last_str.replace("Z", ""))
        hours_since = round((datetime.datetime.utcnow() - last).total_seconds() / 3600, 2)

    return ok(
        profile_id=profile_id,
        last_checkin=last_str,
        hours_since_checkin=hours_since,
        missed_count=state.get("missed_count", 0),
    )


@app.route("/api/sos/trigger", methods=["POST"])
@require_json
def api_sos_trigger():
    """
    POST /api/sos/trigger
    {
        "profile_id": "myprofile",
        "passphrase": "...",
        "trigger": "manual",
        "gps": {"lat": 50.45, "lon": 30.52},   # optional
        "level": 2                               # optional, 1-3
    }
    """
    data       = request.json
    profile_id = data.get("profile_id", "")
    passphrase = data.get("passphrase", "")

    config = load_sos_config(profile_id, passphrase)
    if not config:
        return err("Profile not found or wrong passphrase", 404)

    gps     = data.get("gps")
    trigger = data.get("trigger", "manual_api")
    level   = int(data.get("level", 2))

    broadcast_sos(config, event="SOS_MANUAL", trigger=trigger, gps=gps, level=level)
    return ok(profile_id=profile_id, trigger=trigger, level=level)


@app.route("/api/sos/pin", methods=["POST"])
@require_json
def api_sos_pin():
    """
    POST /api/sos/pin
    {
        "profile_id": "myprofile",
        "passphrase": "...",
        "pin": "1234",
        "gps": {"lat": 50.45, "lon": 30.52}   # optional
    }
    Returns: { "ok": true, "valid": true/false }
    Note: duress PIN always returns { "valid": true } — never reveals it's a trap
    """
    data       = request.json
    profile_id = data.get("profile_id", "")
    passphrase = data.get("passphrase", "")
    pin        = str(data.get("pin", ""))
    gps        = data.get("gps")

    config = load_sos_config(profile_id, passphrase)
    if not config:
        return err("Profile not found or wrong passphrase", 404)

    if is_duress_pin(pin, config):
        # Fire SOS silently, return "valid: true" to not arouse suspicion
        broadcast_sos(
            config, event="DURESS_PIN_ENTERED",
            trigger="duress_pin", gps=gps, level=2,
        )
        return ok(valid=True, message="Access granted")

    if is_real_pin(pin, config):
        return ok(valid=True, message="Access granted")

    return ok(valid=False, message="Invalid PIN")


# ─────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("""
 ╔═══════════════════════════════════════════╗
 ║      NAGINI PROTOCOL — API SERVER         ║
 ╚═══════════════════════════════════════════╝
  http://localhost:5000
""")
    app.run(host="0.0.0.0", port=5000, debug=False)
