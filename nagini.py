#!/usr/bin/env python3
"""
Nagini Protocol CLI
Usage:
  nagini.py setup   — Split a secret and create encrypted geo-blobs
  nagini.py recover — Reconstruct secret by visiting geographic locations
  nagini.py list    — List stored bundles
  nagini.py info    — Show info about a bundle (no decryption)
"""

import sys
import os
import json
import getpass
import hashlib
from pathlib import Path
from typing import List, Tuple, Optional

# Allow running from same dir
sys.path.insert(0, str(Path(__file__).parent))

from nagini_core import (
    nagini_setup,
    nagini_recover_shard,
    nagini_reconstruct,
    TILE_SIZE,
)
from nagini_storage import save_blobs, load_blobs, list_bundles, DEFAULT_STORE_DIR
from nagini_canary import (
    save_canary_config,
    load_canary_config,
    has_canary_config,
    generate_fake_shard,
    fire_canary_alert,
)


# ─────────────────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────────────────

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def ok(msg):   print(f"{GREEN}✓ {msg}{RESET}")
def warn(msg): print(f"{YELLOW}⚠ {msg}{RESET}")
def err(msg):  print(f"{RED}✗ {msg}{RESET}")
def info(msg): print(f"{CYAN}→ {msg}{RESET}")
def dim(msg):  print(f"{DIM}{msg}{RESET}")


BANNER = f"""{CYAN}{BOLD}
 ╔═══════════════════════════════════════════╗
 ║         NAGINI PROTOCOL  v1.0             ║
 ║   Geographic Secret Distribution          ║
 ║   for Cryptographic Key Recovery          ║
 ╚═══════════════════════════════════════════╝{RESET}
{YELLOW}  ⚠  PROTOTYPE — NOT AUDITED — DO NOT USE FOR REAL ASSETS{RESET}
"""


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def parse_coord(s: str) -> float:
    try:
        return float(s.strip())
    except ValueError:
        raise ValueError(f"Cannot parse coordinate: '{s}'. Use decimal degrees, e.g. 43.2567")


def input_locations(n: int) -> List[Tuple[float, float]]:
    """Interactively collect N geographic locations from user."""
    print()
    info(f"Enter {n} geographic locations (decimal degrees, WGS-84).")
    info("Example: lat=43.2567  lon=76.9286  (near Almaty)")
    print()
    locations = []
    for i in range(1, n + 1):
        print(f"{BOLD}  Point #{i}:{RESET}")
        while True:
            try:
                lat = parse_coord(input("    Latitude  (e.g. 43.2567): "))
                lon = parse_coord(input("    Longitude (e.g. 76.9286): "))
                if not (-90 <= lat <= 90):
                    warn("Latitude must be between -90 and 90.")
                    continue
                if not (-180 <= lon <= 180):
                    warn("Longitude must be between -180 and 180.")
                    continue
                locations.append((lat, lon))
                break
            except ValueError as e:
                warn(str(e))
        print()
    return locations


def secret_from_input() -> bytes:
    """Get secret from user — either mnemonic/seed phrase or raw hex."""
    print()
    print(f"{BOLD}Secret input options:{RESET}")
    print("  1) BIP-39 mnemonic / seed phrase (recommended)")
    print("  2) Raw hex string")
    print("  3) Plain text passphrase (will be SHA3-256 hashed)")
    print()
    choice = input("Choose [1/2/3]: ").strip()

    if choice == "1":
        phrase = getpass.getpass("  Enter seed phrase (hidden): ").strip()
        # Convert mnemonic to bytes via SHA3-256 (simplified — real BIP-39 uses PBKDF2)
        # For demo, we hash the phrase. Real impl should use BIP-39 PBKDF2.
        secret = hashlib.sha3_256(phrase.encode()).digest()
        warn("Note: using SHA3-256 of mnemonic. Real BIP-39 uses PBKDF2. This is a demo.")
    elif choice == "2":
        raw = input("  Enter hex secret: ").strip()
        try:
            secret = bytes.fromhex(raw)
        except ValueError:
            err("Invalid hex string.")
            sys.exit(1)
    elif choice == "3":
        passphrase = getpass.getpass("  Enter passphrase (hidden): ").strip()
        secret = hashlib.sha3_256(passphrase.encode()).digest()
    else:
        err("Invalid choice.")
        sys.exit(1)

    print()
    ok(f"Secret loaded: {len(secret) * 8} bits")
    return secret


# ─────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────

def cmd_setup():
    """Setup: split secret into geo-encrypted shards."""
    print(BANNER)
    print(f"{BOLD}=== SETUP MODE ==={RESET}")
    print()
    print("This will split your secret into N shards, each encrypted")
    print("with a key derived from a unique geographic location.")
    print("Recovery requires physical presence at K of N locations.")
    print()

    # Parameters
    while True:
        try:
            n = int(input("Number of shards (N) [recommended: 4]: ").strip() or "4")
            k = int(input(f"Recovery threshold (K) [recommended: 3, max: {n-1}]: ").strip() or "3")
            if 2 <= k < n:
                break
            warn(f"Need 2 ≤ K < N. Got K={k}, N={n}.")
        except ValueError:
            warn("Please enter valid integers.")

    print()
    info(f"Configuration: {k} of {n} locations required for recovery.")
    info(f"  → You can lose access to {n - k} location(s) and still recover.")

    # Canary shard option
    use_canary = input("\nEnable canary (duress) shard? [y/N]: ").strip().lower() == 'y'
    canary_idx = None
    canary_alert_config = {}
    canary_passphrase = None
    if use_canary:
        while True:
            try:
                canary_idx = int(input(f"  Which shard index is the canary? [1-{n}]: ").strip())
                if 1 <= canary_idx <= n:
                    break
                warn(f"Must be between 1 and {n}.")
            except ValueError:
                warn("Enter a number.")
        warn(f"Shard #{canary_idx} is the canary. Do NOT visit it during normal recovery!")
        print()

        # Alert configuration
        print(f"{BOLD}Configure canary alert channels:{RESET}")
        print("  When canary is triggered, alert fires in background.")
        print()

        # Telegram
        use_tg = input("  Telegram alert? [y/N]: ").strip().lower() == 'y'
        if use_tg:
            print(f"  {DIM}(Get token from @BotFather, chat_id from @userinfobot){RESET}")
            tg_token   = input("  Bot token: ").strip()
            tg_chat_id = input("  Chat ID:   ").strip()
            canary_alert_config["telegram_token"]   = tg_token
            canary_alert_config["telegram_chat_id"] = tg_chat_id
            ok("Telegram alert configured.")

        # Custom webhook
        use_webhook = input("  Custom HTTP webhook? [y/N]: ").strip().lower() == 'y'
        if use_webhook:
            webhook_url = input("  Webhook URL: ").strip()
            canary_alert_config["webhook_url"] = webhook_url
            ok("Webhook configured.")

        # Always: local file log
        ok(f"Local alert log always enabled: ~/.nagini/canary_alert.log")

        # Passphrase to encrypt canary config
        print()
        print(f"{BOLD}Set a passphrase to protect canary config:{RESET}")
        print(f"  {DIM}(You'll need this only during recovery if canary is triggered){RESET}")
        while True:
            cp1 = getpass.getpass("  Canary passphrase: ").strip()
            cp2 = getpass.getpass("  Confirm passphrase: ").strip()
            if cp1 == cp2 and cp1:
                canary_passphrase = cp1
                break
            warn("Passphrases don't match or empty. Try again.")
        print()

    # Collect secret
    secret = secret_from_input()

    # Collect locations
    print(f"{BOLD}Now enter the {n} geographic locations:{RESET}")
    locations = input_locations(n)

    # Run setup
    print(f"{BOLD}Generating shards and encrypting...{RESET}")
    blobs, public_id = nagini_setup(secret, locations, k)

    # Save blobs
    bundle_path = save_blobs(blobs)

    # Save canary config (encrypted, separate from blobs)
    if use_canary and canary_idx and canary_passphrase:
        canary_path = save_canary_config(
            public_id=public_id,
            canary_shard_index=canary_idx,
            alert_config=canary_alert_config,
            passphrase=canary_passphrase,
        )
        ok(f"Canary config saved (encrypted): {canary_path}")

    print()
    ok("Setup complete!")
    print()
    print(f"  {BOLD}Public ID:{RESET}  {CYAN}{public_id}{RESET}")
    print(f"  {BOLD}Blobs saved:{RESET} {bundle_path}")
    print()

    # Summary table
    print(f"{BOLD}Shard summary:{RESET}")
    print(f"  {'#':<4} {'Lat':>12} {'Lon':>13}  {'Canary?'}")
    print(f"  {'─'*4} {'─'*12} {'─'*13}  {'─'*7}")
    for i, (lat, lon) in enumerate(locations, 1):
        canary_mark = "← CANARY" if use_canary and i == canary_idx else ""
        print(f"  {i:<4} {lat:>12.4f}° {lon:>12.4f}°  {canary_mark}")
    print()

    warn("IMPORTANT: The geographic locations are NOT stored anywhere.")
    warn("You MUST remember or securely document the locations yourself.")
    warn("Backup the public_id and blob file separately from location descriptions.")

    if use_canary:
        print()
        warn(f"CANARY: Shard #{canary_idx} is a trap. If someone forces you to recover,")
        warn(f"        avoid this location. Visiting it will produce an INVALID secret.")

    print()
    info(f"To recover: python nagini.py recover --id {public_id}")


def cmd_recover(public_id: str):
    """Recovery: visit locations and reconstruct secret."""
    print(BANNER)
    print(f"{BOLD}=== RECOVERY MODE ==={RESET}")
    print()

    # Load blobs
    blobs = load_blobs(public_id)
    if not blobs:
        err(f"No bundle found for public_id: {public_id}")
        err(f"Looked in: {DEFAULT_STORE_DIR}")
        sys.exit(1)

    n = blobs[0].total_shards
    k = blobs[0].threshold
    info(f"Bundle loaded: {n} shards, threshold K={k}")
    info(f"You need to collect {k} shards by visiting {k} locations.")

    # Load canary config if exists
    canary_config = None
    canary_shard_index = None
    if has_canary_config(public_id):
        info(f"Canary protection detected for this bundle.")
        cp = getpass.getpass("  Enter canary passphrase (or Enter to skip): ").strip()
        if cp:
            canary_config = load_canary_config(public_id, cp)
            if canary_config:
                canary_shard_index = canary_config["canary_shard_index"]
                ok(f"Canary config loaded. Shard #{canary_shard_index} is protected.")
            else:
                warn("Wrong passphrase — canary protection disabled for this session.")
    print()

    collected_shares = []
    visited = set()

    while len(collected_shares) < k:
        remaining = k - len(collected_shares)
        print(f"{BOLD}Shards collected: {len(collected_shares)}/{k}  (need {remaining} more){RESET}")
        print()

        # Which shard to try?
        available = [b.shard_index for b in blobs if b.shard_index not in visited]
        print(f"Available shard indices: {available}")

        while True:
            try:
                idx = int(input("Enter shard index you're currently at: ").strip())
                if idx in visited:
                    warn(f"Shard #{idx} already collected. Choose another.")
                elif idx not in available:
                    warn(f"Invalid shard index. Available: {available}")
                else:
                    break
            except ValueError:
                warn("Enter a number.")

        blob = next(b for b in blobs if b.shard_index == idx)

        print(f"\n{BOLD}GPS Coordinates for Shard #{idx}:{RESET}")
        print(f"  (Enter your current GPS position at the location)")
        while True:
            try:
                lat = parse_coord(input("  Latitude:  "))
                lon = parse_coord(input("  Longitude: "))
                break
            except ValueError as e:
                warn(str(e))

        print()
        info(f"Attempting decryption with Fuzzy Extractor (±{blob.tile_size * 111000:.0f}m tolerance)...")

        shard_data = nagini_recover_shard(blob, lat, lon)

        if shard_data is None:
            warn(f"Decryption failed for shard #{idx}.")
            warn("Possible reasons:")
            warn("  - Coordinates too far from the setup location (>200m)")
            warn("  - Wrong shard index selected")
            warn("  - Corrupted blob")
            retry = input("Try different coordinates? [y/N]: ").strip().lower()
            if retry != 'y':
                visited.add(idx)
        else:
            # Check if this is a canary shard
            if canary_shard_index and idx == canary_shard_index:
                # Fire alert in background (attacker must not see any delay)
                fire_canary_alert(
                    public_id=public_id,
                    shard_index=idx,
                    alert_config=canary_config.get("alert_config", {}),
                )
                # Return fake shard — recovery will silently produce wrong secret
                shard_data = generate_fake_shard(len(shard_data), public_id, idx)
                ok(f"Shard #{idx} decrypted successfully!")  # Show nothing suspicious
            else:
                ok(f"Shard #{idx} decrypted successfully!")

            collected_shares.append((idx, shard_data))
            visited.add(idx)

        print()

    # Reconstruct
    print(f"{BOLD}All {k} shards collected. Reconstructing master secret...{RESET}")

    try:
        secret = nagini_reconstruct(collected_shares)
        print()
        print(f"{GREEN}{BOLD}{'═' * 50}{RESET}")
        print(f"{GREEN}{BOLD}  ✓ SECRET RECOVERED SUCCESSFULLY!{RESET}")
        print(f"{GREEN}{BOLD}{'═' * 50}{RESET}")
        print()
        print(f"  {BOLD}Secret (hex):{RESET}")
        print(f"  {CYAN}{secret.hex()}{RESET}")
        print()
        warn("Copy this secret now. It will NOT be stored anywhere.")
        warn("After you close this window, it is gone.")
    except Exception as e:
        err(f"Reconstruction failed: {e}")
        err("The collected shards may be from incompatible sets or corrupted.")
        sys.exit(1)


def cmd_list():
    """List all stored bundles."""
    print(BANNER)
    bundles = list_bundles()
    if not bundles:
        info(f"No bundles found in {DEFAULT_STORE_DIR}")
        return

    print(f"{BOLD}Stored bundles ({len(bundles)}):{RESET}")
    for public_id in bundles:
        blobs = load_blobs(public_id)
        if blobs:
            b = blobs[0]
            print(f"  {CYAN}{public_id}{RESET}  →  {b.total_shards} shards, threshold {b.threshold}")
        else:
            print(f"  {public_id}  → (unreadable)")


def cmd_info(public_id: str):
    """Show bundle info without decryption."""
    print(BANNER)
    blobs = load_blobs(public_id)
    if not blobs:
        err(f"Bundle not found: {public_id}")
        sys.exit(1)

    b = blobs[0]
    print(f"{BOLD}Bundle: {CYAN}{public_id}{RESET}")
    print()
    print(f"  Protocol version : {b.protocol_version}")
    print(f"  Total shards (N) : {b.total_shards}")
    print(f"  Threshold (K)    : {b.threshold}")
    print(f"  Tile size        : {b.tile_size}° (~{b.tile_size * 111000:.0f}m tolerance)")
    print()
    print(f"  {BOLD}Shards:{RESET}")
    for blob in blobs:
        ct_len = len(blob.ciphertext)
        print(f"    #{blob.shard_index}  ciphertext: {ct_len} bytes  salt: {blob.salt.hex()[:16]}...")
    print()
    info("No geographic data is stored in the blob. Location knowledge is in your memory.")


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def usage():
    print(BANNER)
    print(f"{BOLD}Usage:{RESET}")
    print("  python nagini.py setup")
    print("  python nagini.py recover --id <public_id>")
    print("  python nagini.py list")
    print("  python nagini.py info --id <public_id>")
    print()


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        usage()
        return

    cmd = args[0]

    if cmd == "setup":
        cmd_setup()

    elif cmd == "recover":
        if "--id" not in args:
            err("Missing --id <public_id>")
            usage()
            sys.exit(1)
        public_id = args[args.index("--id") + 1]
        cmd_recover(public_id)

    elif cmd == "list":
        cmd_list()

    elif cmd == "info":
        if "--id" not in args:
            err("Missing --id <public_id>")
            usage()
            sys.exit(1)
        public_id = args[args.index("--id") + 1]
        cmd_info(public_id)

    else:
        err(f"Unknown command: {cmd}")
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
