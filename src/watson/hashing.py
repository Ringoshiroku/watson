from __future__ import annotations

import hashlib
from pathlib import Path


def compute_hashes(file_path: Path) -> dict:
    data = Path(file_path).read_bytes()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
