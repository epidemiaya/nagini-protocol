"""
Nagini Protocol — Storage Layer
Saves/loads blobs as JSON files locally.
Future: replace with IPFS / Arweave / blockchain storage.
"""

import json
import os
from pathlib import Path
from typing import List, Optional

from nagini_core import NaginiBlob


DEFAULT_STORE_DIR = Path.home() / ".nagini" / "blobs"


def save_blobs(blobs: List[NaginiBlob], store_dir: Path = DEFAULT_STORE_DIR) -> Path:
    """Save all blobs to local storage. Returns the directory path."""
    store_dir.mkdir(parents=True, exist_ok=True)

    public_id = blobs[0].public_id.hex()
    bundle_path = store_dir / f"{public_id}.json"

    data = {
        "public_id": public_id,
        "blobs": [b.to_dict() for b in blobs],
    }
    bundle_path.write_text(json.dumps(data, indent=2))
    return bundle_path


def load_blobs(public_id: str, store_dir: Path = DEFAULT_STORE_DIR) -> Optional[List[NaginiBlob]]:
    """Load blobs by public_id from local storage."""
    bundle_path = store_dir / f"{public_id}.json"
    if not bundle_path.exists():
        return None

    data = json.loads(bundle_path.read_text())
    return [NaginiBlob.from_dict(b) for b in data["blobs"]]


def list_bundles(store_dir: Path = DEFAULT_STORE_DIR) -> List[str]:
    """List all stored public_ids."""
    if not store_dir.exists():
        return []
    return [f.stem for f in store_dir.glob("*.json")]
