"""
Nagini SOS Protocol
Extended duress and emergency system built on top of Canary.

Features:
  - Dead Man's Switch: if owner doesn't check in → auto-alert
  - Duress PIN: fake PIN that fires SOS silently
  - Emergency broadcast: multi-contact, multi-level escalation
  - GPS-aware alerts
"""

import os
import json
import hashlib
import threading
import datetime
import time
import platform
from pathlib import Path
from typing import Optional, List, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SOS_DIR  = Path.home() / ".nagini" / "sos"
SOS_LOG  = Path.home() / ".nagini" / "sos_alert.log"
DMS_FILE = Path.home() / ".nagini" / "sos" / "deadman.json"


# ─────────────────────────────────────────────────────────
# SOS Config storage
# ─────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=260_000,
    )
    return kdf.derive(passphrase.encode())


def save_sos_config(config: dict, passphrase: str) -> Path:
    """
    Save SOS config encrypted.
    config = {
        "profile_id": str,
        "contacts": [{"name": str, "telegram_token": str, "telegram_chat_id": str, "webhook_url": str}],
        "duress_pin_hash": str,       # SHA3-256 of duress PIN
        "real_pin_hash": str,         # SHA3-256 of real PIN (for duress detection)
        "deadman_interval_hours": int,
        "escalation_levels": [1, 2, 3],  # hours before escalating
        "owner_name": str,
        "emergency_message": str,
    }
    """
    SOS_DIR.mkdir(parents=True, exist_ok=True)
    profile_id = config["profile_id"]

    plaintext = json.dumps(config).encode()
    salt  = os.urandom(32)
    key   = _derive_key(passphrase, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, b"nagini-sos-v1")

    path = SOS_DIR / f"{profile_id}.sos"
    path.write_bytes(salt + nonce + ct)
    return path


def load_sos_config(profile_id: str, passphrase: str) -> Optional[dict]:
    path = SOS_DIR / f"{profile_id}.sos"
    if not path.exists():
        return None
    raw = path.read_bytes()
    salt, nonce, ct = raw[:32], raw[32:44], raw[44:]
    key = _derive_key(passphrase, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, b"nagini-sos-v1")
        return json.loads(plaintext)
    except Exception:
        return None


def list_sos_profiles() -> List[str]:
    if not SOS_DIR.exists():
        return []
    return [f.stem for f in SOS_DIR.glob("*.sos")]


# ─────────────────────────────────────────────────────────
# PIN hashing
# ─────────────────────────────────────────────────────────

def hash_pin(pin: str) -> str:
    return hashlib.sha3_256(f"nagini-pin:{pin}".encode()).hexdigest()


def verify_pin(pin: str, stored_hash: str) -> bool:
    return hash_pin(pin) == stored_hash


def is_duress_pin(pin: str, config: dict) -> bool:
    duress_hash = config.get("duress_pin_hash", "")
    return bool(duress_hash) and verify_pin(pin, duress_hash)


def is_real_pin(pin: str, config: dict) -> bool:
    real_hash = config.get("real_pin_hash", "")
    return bool(real_hash) and verify_pin(pin, real_hash)


# ─────────────────────────────────────────────────────────
# Alert broadcasting
# ─────────────────────────────────────────────────────────

def _write_sos_log(event: str, profile_id: str, details: dict):
    try:
        SOS_LOG.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event": event,
            "profile_id": profile_id,
            "platform": platform.system(),
            "hostname": platform.node(),
            **details,
        }
        with SOS_LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _telegram_send(token: str, chat_id: str, text: str):
    try:
        import urllib.request
        payload = json.dumps({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def _webhook_send(url: str, payload: dict):
    try:
        import urllib.request
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def broadcast_sos(
    config: dict,
    event: str = "SOS_TRIGGERED",
    trigger: str = "unknown",
    gps: Optional[Dict] = None,
    level: int = 1,
):
    """
    Broadcast SOS to all configured contacts.
    Runs in background thread — never blocks caller.
    """
    def _fire():
        profile_id = config.get("profile_id", "unknown")
        owner      = config.get("owner_name", "Unknown")
        msg_extra  = config.get("emergency_message", "")
        lac_wallet = config.get("lac_wallet", "")
        timestamp  = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        gps_str = ""
        if gps:
            lat = gps.get("lat")
            lon = gps.get("lon")
            if lat and lon:
                gps_str = f"\n📍 GPS: `{lat}, {lon}`\nhttps://maps.google.com/?q={lat},{lon}"

        lac_str = f"\n💎 LAC wallet: `{lac_wallet}`" if lac_wallet else ""

        level_emoji = {1: "⚠️", 2: "🚨", 3: "🆘"}.get(level, "🚨")

        tg_text = (
            f"{level_emoji} *NAGINI SOS — LEVEL {level}*\n\n"
            f"👤 Owner: `{owner}`\n"
            f"⏰ Time: `{timestamp}`\n"
            f"⚡ Trigger: `{trigger}`\n"
            f"🔔 Event: `{event}`"
            f"{lac_str}"
            f"{gps_str}"
        )
        if msg_extra:
            tg_text += f"\n\n📝 _{msg_extra}_"

        webhook_payload = {
            "event": event,
            "level": level,
            "trigger": trigger,
            "owner": owner,
            "profile_id": profile_id,
            "lac_wallet": lac_wallet,
            "timestamp": timestamp,
            "gps": gps,
            "message": msg_extra,
            "hostname": platform.node(),
        }

        # Write local log always
        _write_sos_log(event, profile_id, {"trigger": trigger, "level": level, "gps": gps})

        # Broadcast to all contacts
        for contact in config.get("contacts", []):
            tg_token   = contact.get("telegram_token", "").strip()
            tg_chat_id = contact.get("telegram_chat_id", "").strip()
            if tg_token and tg_chat_id:
                _telegram_send(tg_token, tg_chat_id, tg_text)

            webhook = contact.get("webhook_url", "").strip()
            if webhook:
                _webhook_send(webhook, webhook_payload)

    threading.Thread(target=_fire, daemon=True).start()


# ─────────────────────────────────────────────────────────
# Dead Man's Switch
# ─────────────────────────────────────────────────────────

class DeadManSwitch:
    """
    Periodic check-in required. If owner misses check-in window → SOS fires.
    State stored in plain JSON (not sensitive — just timestamps).
    """

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def checkin(self, profile_id: str) -> dict:
        """Record a check-in. Returns updated state."""
        state = self._load_state(profile_id)
        state["last_checkin"] = datetime.datetime.utcnow().isoformat() + "Z"
        state["missed_count"] = 0
        self._save_state(profile_id, state)
        return state

    def get_state(self, profile_id: str) -> dict:
        return self._load_state(profile_id)

    def start_monitor(self, profile_id: str, config: dict, passphrase: str):
        """Start background monitoring thread."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(profile_id, config, passphrase),
            daemon=True,
        )
        self._thread.start()

    def stop_monitor(self):
        self._stop_event.set()

    def _monitor_loop(self, profile_id: str, config: dict, passphrase: str):
        interval_hours = config.get("deadman_interval_hours", 24)
        check_every    = min(interval_hours * 3600 / 12, 300)  # check at least every 5min

        while not self._stop_event.is_set():
            state = self._load_state(profile_id)
            last_str = state.get("last_checkin")

            if last_str:
                last = datetime.datetime.fromisoformat(last_str.replace("Z", ""))
                elapsed_hours = (datetime.datetime.utcnow() - last).total_seconds() / 3600

                if elapsed_hours > interval_hours:
                    missed = state.get("missed_count", 0) + 1
                    state["missed_count"] = missed
                    self._save_state(profile_id, state)

                    # Escalating levels
                    escalation = config.get("escalation_levels", [1, 6, 24])
                    level = 1
                    for i, h in enumerate(escalation):
                        if elapsed_hours > h:
                            level = i + 1

                    broadcast_sos(
                        config=config,
                        event="DEADMAN_TRIGGERED",
                        trigger=f"No check-in for {elapsed_hours:.1f}h (threshold: {interval_hours}h)",
                        level=level,
                    )

            self._stop_event.wait(timeout=check_every)

    def _load_state(self, profile_id: str) -> dict:
        path = SOS_DIR / f"{profile_id}.dms"
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                pass
        return {"profile_id": profile_id, "last_checkin": None, "missed_count": 0}

    def _save_state(self, profile_id: str, state: dict):
        SOS_DIR.mkdir(parents=True, exist_ok=True)
        path = SOS_DIR / f"{profile_id}.dms"
        path.write_text(json.dumps(state, indent=2))


# Global DMS instance
dead_man_switch = DeadManSwitch()
