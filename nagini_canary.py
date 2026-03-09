"""
Nagini Protocol — Canary Shard System

When an attacker forces a victim to "recover" their secret,
they may visit a canary location. This module:
  1. Returns a fake (corrupted) shard — recovery silently produces wrong secret
  2. Fires an alert in background via configured channels

Canary config is stored SEPARATELY from blobs, encrypted with a passphrase.
An attacker with access to blobs cannot determine which shard is the canary.

Alert channels:
  - Local file trigger (~/.nagini/canary_alert.log)
  - Telegram bot webhook (optional)
  - Custom HTTP webhook (optional)
"""

import os
import json
import hashlib
import threading
import datetime
import platform
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


CANARY_DIR = Path.home() / ".nagini" / "canary"
ALERT_LOG  = Path.home() / ".nagini" / "canary_alert.log"


# ─────────────────────────────────────────────────────────
# Canary config encryption (PBKDF2 + AES-256-GCM)
# ─────────────────────────────────────────────────────────

def _derive_canary_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=260_000,  # OWASP recommended minimum 2023
    )
    return kdf.derive(passphrase.encode())


def save_canary_config(
    public_id: str,
    canary_shard_index: int,
    alert_config: dict,
    passphrase: str,
) -> Path:
    """
    Save canary configuration encrypted with passphrase.
    Stored separately from blobs — attacker cannot link them.

    alert_config: {
        "telegram_token": "...",   # optional
        "telegram_chat_id": "...", # optional
        "webhook_url": "...",      # optional custom HTTP endpoint
        "contact_hint": "...",     # human-readable note, stored encrypted
    }
    """
    CANARY_DIR.mkdir(parents=True, exist_ok=True)

    plaintext = json.dumps({
        "public_id": public_id,
        "canary_shard_index": canary_shard_index,
        "alert_config": alert_config,
    }).encode()

    salt = os.urandom(32)
    key = _derive_canary_key(passphrase, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, b"nagini-canary-v1")

    config_path = CANARY_DIR / f"{public_id}.canary"
    config_path.write_bytes(
        salt + nonce + ciphertext
    )
    return config_path


def load_canary_config(public_id: str, passphrase: str) -> Optional[dict]:
    """Load and decrypt canary config. Returns None if wrong passphrase or not found."""
    config_path = CANARY_DIR / f"{public_id}.canary"
    if not config_path.exists():
        return None

    raw = config_path.read_bytes()
    salt      = raw[:32]
    nonce     = raw[32:44]
    ciphertext = raw[44:]

    key = _derive_canary_key(passphrase, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, b"nagini-canary-v1")
        return json.loads(plaintext)
    except Exception:
        return None


def has_canary_config(public_id: str) -> bool:
    return (CANARY_DIR / f"{public_id}.canary").exists()


# ─────────────────────────────────────────────────────────
# Fake shard generation
# ─────────────────────────────────────────────────────────

def generate_fake_shard(shard_len: int, public_id: str, shard_index: int) -> bytes:
    """
    Generate a deterministic-looking fake shard.
    Deterministic so the same canary location always "works" (returns same fake data).
    But it's cryptographically unrelated to real shards.
    """
    # Fake but deterministic — same location always gives same fake shard
    # (so it doesn't raise suspicion by changing each time)
    seed = hashlib.sha3_256(
        b"nagini-canary-fake" + public_id.encode() + shard_index.to_bytes(1, 'big')
    ).digest()
    # Expand to needed length
    fake = bytearray()
    counter = 0
    while len(fake) < shard_len:
        fake.extend(hashlib.sha3_256(seed + counter.to_bytes(4, 'big')).digest())
        counter += 1
    return bytes(fake[:shard_len])


# ─────────────────────────────────────────────────────────
# Alert system
# ─────────────────────────────────────────────────────────

def _write_local_alert(public_id: str, shard_index: int):
    """Write alert to local log file."""
    try:
        ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        entry = {
            "timestamp": timestamp,
            "event": "CANARY_TRIGGERED",
            "public_id": public_id,
            "canary_shard_index": shard_index,
            "platform": platform.system(),
            "hostname": platform.node(),
        }
        with ALERT_LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Alert failure must never crash recovery flow


def _send_telegram_alert(token: str, chat_id: str, public_id: str, shard_index: int):
    """Send Telegram alert. Runs in background thread."""
    try:
        import urllib.request
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        text = (
            f"🚨 *NAGINI CANARY TRIGGERED*\n\n"
            f"⏰ Time: `{timestamp}`\n"
            f"🔑 Bundle: `{public_id[:16]}...`\n"
            f"⚡ Shard: `#{shard_index}`\n"
            f"💻 Host: `{platform.node()}`\n\n"
            f"_Someone is attempting forced recovery of your secret._"
        )
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
        pass  # Silent failure


def _send_webhook_alert(url: str, public_id: str, shard_index: int):
    """Send HTTP POST to custom webhook."""
    try:
        import urllib.request
        payload = json.dumps({
            "event": "NAGINI_CANARY_TRIGGERED",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "public_id": public_id,
            "canary_shard_index": shard_index,
            "hostname": platform.node(),
        }).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def fire_canary_alert(public_id: str, shard_index: int, alert_config: dict):
    """
    Fire all configured alert channels in background threads.
    Recovery flow continues immediately — attacker must not see any delay.
    """
    def _fire():
        # Always write local log
        _write_local_alert(public_id, shard_index)

        # Telegram
        tg_token   = alert_config.get("telegram_token", "").strip()
        tg_chat_id = alert_config.get("telegram_chat_id", "").strip()
        if tg_token and tg_chat_id:
            _send_telegram_alert(tg_token, tg_chat_id, public_id, shard_index)

        # Custom webhook
        webhook_url = alert_config.get("webhook_url", "").strip()
        if webhook_url:
            _send_webhook_alert(webhook_url, public_id, shard_index)

    threading.Thread(target=_fire, daemon=True).start()
