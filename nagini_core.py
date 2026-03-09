"""
Nagini Protocol v1.0
Geographic Secret Distribution for Cryptographic Key Recovery

Core cryptographic library:
  - GF(2^8) Shamir Secret Sharing
  - Geo-key derivation (SHA3-256 + HKDF)
  - AES-256-GCM authenticated encryption
  - Tile-based Fuzzy Extractor for GPS drift

STATUS: PROTOTYPE — NOT AUDITED. Do not use for real assets.
"""

import os
import struct
import hashlib
import json
import uuid
from typing import List, Tuple, Optional
from dataclasses import dataclass, asdict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ─────────────────────────────────────────────────────────
# GF(2^8) Arithmetic for Shamir Secret Sharing
# ─────────────────────────────────────────────────────────

GF_EXP = [0] * 512
GF_LOG = [0] * 256

def _init_gf():
    """Initialize GF(2^8) lookup tables with polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d)."""
    x = 1
    for i in range(255):
        GF_EXP[i] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11d
    for i in range(255, 512):
        GF_EXP[i] = GF_EXP[i - 255]

_init_gf()


def gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8)."""
    if a == 0 or b == 0:
        return 0
    return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]


def gf_div(a: int, b: int) -> int:
    """Divide a by b in GF(2^8)."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(2^8)")
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] - GF_LOG[b]) % 255]


def gf_pow(x: int, p: int) -> int:
    """x^p in GF(2^8)."""
    if x == 0:
        return 0
    return GF_EXP[(GF_LOG[x] * p) % 255]


def gf_inv(x: int) -> int:
    """Multiplicative inverse in GF(2^8)."""
    if x == 0:
        raise ZeroDivisionError("No inverse for 0 in GF(2^8)")
    return GF_EXP[255 - GF_LOG[x]]


# ─────────────────────────────────────────────────────────
# Shamir Secret Sharing over GF(2^8)
# ─────────────────────────────────────────────────────────

def _poly_eval(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial at x using Horner's method in GF(2^8)."""
    result = 0
    for coeff in reversed(coeffs):
        result = gf_mul(result, x) ^ coeff
    return result


def _lagrange_interpolate(x: int, xs: List[int], ys: List[int]) -> int:
    """Lagrange interpolation at point x over GF(2^8)."""
    result = 0
    for i, (xi, yi) in enumerate(zip(xs, ys)):
        num = yi
        den = 1
        for j, xj in enumerate(xs):
            if i != j:
                num = gf_mul(num, x ^ xj)
                den = gf_mul(den, xi ^ xj)
        result ^= gf_mul(num, gf_inv(den))
    return result


def shamir_split(secret: bytes, n: int, k: int) -> List[Tuple[int, bytes]]:
    """
    Split `secret` into N shards, threshold K.
    Returns list of (index, shard_bytes) where index is 1..N.
    """
    if k < 2 or k > n:
        raise ValueError(f"Invalid parameters: k={k}, n={n}. Need 2 <= k <= n.")
    if n > 255:
        raise ValueError("N cannot exceed 255.")

    shards = [(i, bytearray()) for i in range(1, n + 1)]

    for byte_val in secret:
        # Random polynomial of degree k-1 with constant term = byte_val
        coeffs = [byte_val] + [os.urandom(1)[0] for _ in range(k - 1)]
        for i, shard in shards:
            shard.append(_poly_eval(coeffs, i))

    return [(i, bytes(shard)) for i, shard in shards]


def shamir_combine(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Recover secret from list of (index, shard_bytes).
    Requires at least K shares (caller must provide exactly K).
    """
    if len(shares) == 0:
        raise ValueError("No shares provided.")
    shard_len = len(shares[0][1])
    if not all(len(s) == shard_len for _, s in shares):
        raise ValueError("All shards must have the same length.")

    xs = [i for i, _ in shares]
    secret = bytearray()
    for byte_idx in range(shard_len):
        ys = [s[byte_idx] for _, s in shares]
        secret.append(_lagrange_interpolate(0, xs, ys))

    return bytes(secret)


# ─────────────────────────────────────────────────────────
# Geo-Key Derivation
# ─────────────────────────────────────────────────────────

PROTOCOL_VERSION = b"nagini-v1"
PRECISION = 4       # 4 decimal places ≈ 11 meters
TILE_SIZE = 0.002   # degrees ≈ 200 meters


def _quantize_coord(coord: float, precision: int = PRECISION) -> float:
    """Round coordinate to given decimal precision."""
    factor = 10 ** precision
    return round(coord * factor) / factor


TILE_ROUND = 8  # decimal places for tile center rounding (avoids float drift)


def _coord_to_tile_center(coord: float, tile_size: float = TILE_SIZE) -> float:
    """Snap coordinate to center of its tile, rounded to avoid float drift."""
    import math
    tile_idx = math.floor(coord / tile_size)
    return round(tile_idx * tile_size + tile_size / 2, TILE_ROUND)


def _derive_key_from_coords(lat: float, lon: float, shard_index: int, salt: bytes) -> bytes:
    """
    Derive AES-256 encryption key from GPS coordinates.
    lat, lon — already quantized/tiled coordinates.
    """
    # geo_seed = SHA3-256(lat || lon || protocol_version || shard_index)
    lat_bytes = struct.pack('>d', lat)
    lon_bytes = struct.pack('>d', lon)
    idx_bytes = struct.pack('>B', shard_index)

    geo_seed = hashlib.sha3_256(
        lat_bytes + lon_bytes + PROTOCOL_VERSION + idx_bytes
    ).digest()

    # enc_key = HKDF-SHA256(geo_seed, salt, info='nagini-v1')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=PROTOCOL_VERSION,
    )
    return hkdf.derive(geo_seed)


def _get_tile_candidates(lat: float, lon: float, tile_size: float = TILE_SIZE) -> List[Tuple[float, float]]:
    """
    Return 9 candidate tile centers (center + 8 neighbors) for fuzzy matching.
    """
    import math
    base_lat = math.floor(lat / tile_size) * tile_size + tile_size / 2
    base_lon = math.floor(lon / tile_size) * tile_size + tile_size / 2

    candidates = []
    for dlat in [-tile_size, 0, tile_size]:
        for dlon in [-tile_size, 0, tile_size]:
            cand_lat = round(base_lat + dlat, TILE_ROUND)
            cand_lon = round(base_lon + dlon, TILE_ROUND)
            candidates.append((cand_lat, cand_lon))
    return candidates


# ─────────────────────────────────────────────────────────
# Blob: encrypted shard structure
# ─────────────────────────────────────────────────────────

@dataclass
class NaginiBlob:
    """Public blob stored in storage layer. Contains NO geographic information."""
    protocol_version: int       # 1
    shard_index: int            # 1..N
    total_shards: int           # N
    threshold: int              # K
    salt: bytes                 # 32 bytes, random
    tile_size: float            # Fuzzy Extractor tile size (degrees)
    ciphertext: bytes           # AES-256-GCM encrypted shard
    auth_tag_included: bool     # GCM tag is appended to ciphertext
    public_id: bytes            # 16 bytes, shared across all blobs of same secret

    def to_dict(self) -> dict:
        d = asdict(self)
        d['salt'] = self.salt.hex()
        d['ciphertext'] = self.ciphertext.hex()
        d['public_id'] = self.public_id.hex()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'NaginiBlob':
        return cls(
            protocol_version=d['protocol_version'],
            shard_index=d['shard_index'],
            total_shards=d['total_shards'],
            threshold=d['threshold'],
            salt=bytes.fromhex(d['salt']),
            tile_size=d['tile_size'],
            ciphertext=bytes.fromhex(d['ciphertext']),
            auth_tag_included=d['auth_tag_included'],
            public_id=bytes.fromhex(d['public_id']),
        )


def encrypt_shard(
    shard: bytes,
    shard_index: int,
    lat: float,
    lon: float,
    total_shards: int,
    threshold: int,
    public_id: bytes,
    tile_size: float = TILE_SIZE,
) -> NaginiBlob:
    """
    Encrypt a shard using coordinates-derived key.
    Coordinates are snapped to tile center before key derivation.
    """
    # Snap to tile center for reproducibility
    tile_lat = _coord_to_tile_center(lat, tile_size)
    tile_lon = _coord_to_tile_center(lon, tile_size)

    salt = os.urandom(32)
    key = _derive_key_from_coords(tile_lat, tile_lon, shard_index, salt)

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    # AAD = shard_index byte
    aad = struct.pack('>B', shard_index)
    ciphertext_with_tag = aesgcm.encrypt(nonce, shard, aad)

    # Store nonce prepended to ciphertext+tag
    ciphertext = nonce + ciphertext_with_tag

    return NaginiBlob(
        protocol_version=1,
        shard_index=shard_index,
        total_shards=total_shards,
        threshold=threshold,
        salt=salt,
        tile_size=tile_size,
        ciphertext=ciphertext,
        auth_tag_included=True,
        public_id=public_id,
    )


def decrypt_shard(blob: NaginiBlob, lat: float, lon: float) -> Optional[bytes]:
    """
    Try to decrypt a shard blob using provided GPS coordinates.
    Uses Fuzzy Extractor: tries 9 tile candidates.
    Returns decrypted shard bytes, or None if decryption fails for all candidates.
    """
    nonce = blob.ciphertext[:12]
    ciphertext_with_tag = blob.ciphertext[12:]
    aad = struct.pack('>B', blob.shard_index)

    candidates = _get_tile_candidates(lat, lon, blob.tile_size)

    for tile_lat, tile_lon in candidates:
        key = _derive_key_from_coords(tile_lat, tile_lon, blob.shard_index, blob.salt)
        aesgcm = AESGCM(key)
        try:
            shard = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
            return shard
        except Exception:
            continue

    return None  # All candidates failed


# ─────────────────────────────────────────────────────────
# High-Level Protocol API
# ─────────────────────────────────────────────────────────

def nagini_setup(
    secret: bytes,
    locations: List[Tuple[float, float]],
    threshold: int,
) -> Tuple[List[NaginiBlob], str]:
    """
    Setup: split secret and create encrypted blobs.

    Args:
        secret:    Master secret bytes (e.g., BIP-39 entropy or derived key)
        locations: List of (lat, lon) tuples, one per shard. len(locations) = N.
        threshold: K — minimum shards needed for recovery.

    Returns:
        (blobs, public_id_hex)
    """
    n = len(locations)
    if threshold < 2 or threshold > n:
        raise ValueError(f"Invalid threshold={threshold} for n={n} locations.")

    public_id = os.urandom(16)
    shards = shamir_split(secret, n, threshold)

    blobs = []
    for (shard_idx, shard_data), (lat, lon) in zip(shards, locations):
        blob = encrypt_shard(
            shard=shard_data,
            shard_index=shard_idx,
            lat=lat,
            lon=lon,
            total_shards=n,
            threshold=threshold,
            public_id=public_id,
        )
        blobs.append(blob)

    return blobs, public_id.hex()


def nagini_recover_shard(blob: NaginiBlob, lat: float, lon: float) -> Optional[bytes]:
    """
    Attempt to recover one shard by visiting its geographic location.
    Returns shard bytes or None if coordinates don't match.
    """
    return decrypt_shard(blob, lat, lon)


def nagini_reconstruct(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstruct the master secret from K or more (index, shard) pairs.
    """
    return shamir_combine(shares)
