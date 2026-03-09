"""
Nagini Protocol — Test Suite

Tests:
  1. GF(2^8) arithmetic
  2. Shamir Secret Sharing (split/combine, threshold, randomness)
  3. Geo-key derivation
  4. Fuzzy Extractor (tolerance, rejection)
  5. Full protocol round-trip
  6. Canary shard behavior
  7. Edge cases
"""

import os
import sys
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from nagini_core import (
    gf_mul, gf_div, gf_inv, gf_pow,
    shamir_split, shamir_combine,
    encrypt_shard, decrypt_shard,
    nagini_setup, nagini_recover_shard, nagini_reconstruct,
    _derive_key_from_coords, _get_tile_candidates,
    _coord_to_tile_center, TILE_SIZE,
)


PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"


def test(name: str, condition: bool, detail: str = ""):
    status = PASS if condition else FAIL
    suffix = f"  {detail}" if detail else ""
    print(f"  {status} {name}{suffix}")
    if not condition:
        raise AssertionError(f"FAILED: {name}")


def section(name: str):
    print(f"\n\033[1m{name}\033[0m")
    print("─" * 50)


# ─────────────────────────────────────────────────────────

def test_gf_arithmetic():
    section("1. GF(2^8) Arithmetic")

    # Identity
    test("gf_mul(x, 1) == x",     all(gf_mul(x, 1) == x for x in range(1, 256)))
    test("gf_mul(x, 0) == 0",     all(gf_mul(x, 0) == 0 for x in range(256)))

    # Commutativity
    test("gf_mul commutative",    gf_mul(123, 45) == gf_mul(45, 123))

    # Distributivity (a+b = a XOR b in GF)
    a, b, c = 73, 42, 199
    test("gf_mul distributive",   gf_mul(a, b ^ c) == gf_mul(a, b) ^ gf_mul(a, c))

    # Inverse: x * inv(x) == 1
    test("gf_inv: x * inv(x) = 1", all(gf_mul(x, gf_inv(x)) == 1 for x in range(1, 256)))

    # Division: div(mul(a,b), b) == a
    test("gf_div round-trip",     all(gf_div(gf_mul(a, b), b) == a for a in range(1, 50) for b in range(1, 50)))


def test_shamir():
    section("2. Shamir Secret Sharing")

    secret = os.urandom(32)

    # Basic 3-of-5
    shards = shamir_split(secret, 5, 3)
    test("Split produces N shards",      len(shards) == 5)
    test("Shard indices 1..N",           [i for i, _ in shards] == [1, 2, 3, 4, 5])
    test("Shard length == secret length", all(len(s) == len(secret) for _, s in shards))

    # Combine with exactly k
    recovered = shamir_combine(shards[:3])
    test("Recover with exactly K=3",     recovered == secret)

    # Different K subsets
    recovered2 = shamir_combine([shards[1], shards[3], shards[4]])
    test("Recover with different K subset", recovered2 == secret)

    # Combine with all N
    recovered_all = shamir_combine(shards)
    test("Recover with all N shards",    recovered_all == secret)

    # Randomness: same secret → different shards
    shards2 = shamir_split(secret, 5, 3)
    test("Shards are random (not deterministic)", shards[0][1] != shards2[0][1])

    # 2-of-2
    s2 = shamir_split(b"hello nagini!", 2, 2)
    r2 = shamir_combine(s2)
    test("2-of-2 scheme",                r2 == b"hello nagini!")

    # Various secret lengths
    for length in [16, 32, 64, 128]:
        s = os.urandom(length)
        shards = shamir_split(s, 4, 3)
        recovered = shamir_combine(shards[:3])
        test(f"Secret length {length} bytes",    recovered == s)


def test_geo_key():
    section("3. Geo-Key Derivation")

    lat, lon = 43.2567, 76.9286
    salt = os.urandom(32)

    key1 = _derive_key_from_coords(lat, lon, 1, salt)
    key2 = _derive_key_from_coords(lat, lon, 1, salt)
    test("Deterministic: same coords → same key", key1 == key2)
    test("Key is 32 bytes (AES-256)",              len(key1) == 32)

    # Different shard index → different key
    key3 = _derive_key_from_coords(lat, lon, 2, salt)
    test("Different shard index → different key",  key1 != key3)

    # Slightly different coords → completely different key
    key4 = _derive_key_from_coords(lat + 1.0, lon, 1, salt)
    test("Different coords → different key",       key1 != key4)

    # Different salt → different key
    key5 = _derive_key_from_coords(lat, lon, 1, os.urandom(32))
    test("Different salt → different key",         key1 != key5)


def test_fuzzy_extractor():
    section("4. Fuzzy Extractor (GPS Tolerance)")

    secret = os.urandom(32)
    # Use 2-of-2 to isolate one shard for testing
    shards = shamir_split(secret, 2, 2)
    shard_idx, shard_data = shards[0]  # Use first shard only
    public_id = os.urandom(16)

    lat, lon = 48.8584, 2.2945  # Eiffel Tower

    blob = encrypt_shard(shard_data, shard_idx, lat, lon, 1, 1, public_id)

    # Exact same coordinates
    result = decrypt_shard(blob, lat, lon)
    test("Exact coordinates: decryption succeeds",  result == shard_data)

    # Small offset within tile (< 100m)
    small_offset = 0.0005  # ~55m
    result2 = decrypt_shard(blob, lat + small_offset, lon)
    test("~55m offset: decryption succeeds (same tile)", result2 == shard_data)

    # Offset that crosses tile boundary but within neighbor (< 200m)
    # This tests the 8-neighbor lookup
    border_offset = TILE_SIZE * 0.99  # Just inside next tile
    result3 = decrypt_shard(blob, lat + border_offset, lon)
    test("Border-crossing offset: neighbor tile lookup", result3 == shard_data)

    # Large offset (> 400m) — should fail
    large_offset = 0.005  # ~550m
    result4 = decrypt_shard(blob, lat + large_offset, lon)
    test("~550m offset: decryption fails (correct!)",    result4 is None)

    # Completely wrong location
    result5 = decrypt_shard(blob, 51.5074, -0.1278)  # London
    test("Wrong continent: decryption fails",             result5 is None)


def test_full_protocol():
    section("5. Full Protocol Round-Trip")

    secret = hashlib.sha3_256(b"my precious seed phrase nobody knows").digest()

    # 5 real-ish locations (random offsets for test)
    locations = [
        (43.2567 + i * 0.5, 76.9286 + i * 0.3)
        for i in range(5)
    ]

    # Setup: 3-of-5
    blobs, public_id = nagini_setup(secret, locations, threshold=3)
    test("Setup: 5 blobs created",         len(blobs) == 5)
    test("Public ID: 32 hex chars",        len(public_id) == 32)
    test("All blobs have same public_id",  len(set(b.public_id for b in blobs)) == 1)

    # Recovery: visit locations 1, 3, 5 (indices 1, 3, 5)
    collected = []
    for blob in [blobs[0], blobs[2], blobs[4]]:
        idx = blob.shard_index
        lat, lon = locations[idx - 1]
        shard = nagini_recover_shard(blob, lat, lon)
        test(f"  Shard #{idx} recovered at location",  shard is not None)
        collected.append((idx, shard))

    recovered_secret = nagini_reconstruct(collected)
    test("Secret reconstructed correctly",  recovered_secret == secret)

    # Wrong location → fail
    wrong_shard = nagini_recover_shard(blobs[1], 0.0, 0.0)
    test("Wrong location → None returned", wrong_shard is None)

    # Only K-1 shards → wrong reconstruction
    partial = collected[:2]  # Only 2 of 3
    bad_secret = nagini_reconstruct(partial)  # Shamir with wrong k
    # Note: Shamir doesn't detect wrong k by itself — but we verify the result is wrong
    # (In practice the secret would decrypt to garbage at higher levels)
    test("K-1 shards → wrong secret (expected)", bad_secret != secret)


def test_edge_cases():
    section("6. Edge Cases")

    # Minimum config: 2-of-3
    secret = b"test secret 123!"
    locs = [(10.0, 20.0), (30.0, 40.0), (50.0, 60.0)]
    blobs, _ = nagini_setup(secret, locs, 2)
    test("2-of-3 setup succeeds",    len(blobs) == 3)

    shard0 = nagini_recover_shard(blobs[0], 10.0, 20.0)
    shard1 = nagini_recover_shard(blobs[1], 30.0, 40.0)
    recovered = nagini_reconstruct([(blobs[0].shard_index, shard0), (blobs[1].shard_index, shard1)])
    test("2-of-3 recovery succeeds",  recovered == secret)

    # Maximum supported shards
    secret_max = os.urandom(32)
    locs_max = [(float(i), float(i)) for i in range(7)]
    blobs_max, _ = nagini_setup(secret_max, locs_max, 5)
    test("7-shard setup succeeds",    len(blobs_max) == 7)

    # Single byte secret
    tiny_secret = b"\xAB"
    locs_tiny = [(1.0, 2.0), (3.0, 4.0), (5.0, 6.0)]
    blobs_tiny, _ = nagini_setup(tiny_secret, locs_tiny, 2)
    s0 = nagini_recover_shard(blobs_tiny[0], 1.0, 2.0)
    s1 = nagini_recover_shard(blobs_tiny[1], 3.0, 4.0)
    recovered_tiny = nagini_reconstruct([(blobs_tiny[0].shard_index, s0), (blobs_tiny[1].shard_index, s1)])
    test("Single-byte secret",        recovered_tiny == tiny_secret)

    # Different bundles don't interfere
    secret_a = os.urandom(32)
    secret_b = os.urandom(32)
    locs_ab = [(1.0, 1.0), (2.0, 2.0), (3.0, 3.0)]
    blobs_a, id_a = nagini_setup(secret_a, locs_ab, 2)
    blobs_b, id_b = nagini_setup(secret_b, locs_ab, 2)
    test("Different bundles have different IDs",  id_a != id_b)
    s_a = nagini_recover_shard(blobs_a[0], 1.0, 1.0)
    s_b = nagini_recover_shard(blobs_b[0], 1.0, 1.0)
    test("Blobs from different bundles differ",   s_a != s_b)


def test_serialization():
    section("7. Blob Serialization")
    from nagini_core import NaginiBlob
    import json

    secret = b"serialize me please"
    locs = [(48.8584, 2.2945), (51.5074, -0.1278), (40.7128, -74.0060)]
    blobs, pid = nagini_setup(secret, locs, 2)

    for blob in blobs:
        d = blob.to_dict()
        json_str = json.dumps(d)
        restored = NaginiBlob.from_dict(json.loads(json_str))
        test(f"Shard #{blob.shard_index}: JSON round-trip",
             restored.ciphertext == blob.ciphertext and
             restored.salt == blob.salt and
             restored.public_id == blob.public_id)


# ─────────────────────────────────────────────────────────

def main():
    print("\n\033[1m\033[96m NAGINI PROTOCOL — TEST SUITE \033[0m")
    print("=" * 50)

    tests = [
        test_gf_arithmetic,
        test_shamir,
        test_geo_key,
        test_fuzzy_extractor,
        test_full_protocol,
        test_edge_cases,
        test_serialization,
    ]

    failed = []
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed.append(str(e))
        except Exception as e:
            failed.append(f"{t.__name__}: {e}")
            import traceback
            traceback.print_exc()

    print()
    print("=" * 50)
    if not failed:
        print(f"\033[92m\033[1m ALL TESTS PASSED ✓\033[0m")
    else:
        print(f"\033[91m\033[1m {len(failed)} TEST(S) FAILED:\033[0m")
        for f in failed:
            print(f"  ✗ {f}")
    print()


if __name__ == "__main__":
    main()
