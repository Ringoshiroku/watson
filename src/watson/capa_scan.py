# src/watson/capa_scan.py
from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


class CapaScanError(Exception):
    """Raised when capa fails to analyze a file."""


@contextlib.contextmanager
def _resolve_signatures_dir(signatures_dir: Optional[Path]):
    if signatures_dir is not None:
        yield signatures_dir
        return
    with tempfile.TemporaryDirectory() as tmp:
        yield tmp


def scan_file(
    file_path: Path,
    rules_dir: Path,
    capa_binary: str = "capa",
    signatures_dir: Optional[Path] = None,
    timeout: int = 120,
) -> list:
    with _resolve_signatures_dir(signatures_dir) as sigs_dir:
        try:
            result = subprocess.run(
                [capa_binary, "-j", "-r", str(rules_dir), "-s", str(sigs_dir), str(file_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CapaScanError(f"capa timed out after {timeout}s") from exc

    if result.returncode != 0:
        raise CapaScanError(result.stderr.strip() or f"capa exited with code {result.returncode}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CapaScanError(f"capa produced invalid JSON: {exc}") from exc

    return [
        {
            "rule": name,
            "namespace": entry["meta"].get("namespace"),
            "attack": entry["meta"].get("attack", []),
            "mbc": entry["meta"].get("mbc", []),
        }
        for name, entry in data.get("rules", {}).items()
    ]
