from __future__ import annotations

import json
import subprocess
from pathlib import Path

_STRING_CATEGORIES = ("static_strings", "stack_strings", "tight_strings", "decoded_strings")


class FlossScanError(Exception):
    """Raised when FLOSS fails to analyze a file."""


def scan_file(file_path: Path, floss_binary: str = "floss", timeout: int = 120) -> dict:
    try:
        result = subprocess.run(
            [floss_binary, "-j", "-q", str(file_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FlossScanError(f"floss timed out after {timeout}s") from exc

    if result.returncode != 0:
        raise FlossScanError(result.stderr.strip() or f"floss exited with code {result.returncode}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise FlossScanError(f"floss produced invalid JSON: {exc}") from exc


def flatten_strings(raw: dict) -> list:
    flattened = []
    for category in _STRING_CATEGORIES:
        for entry in raw["strings"][category]:
            flattened.append({"string": entry["string"], "source": category})
    return flattened


def save_raw_output(raw: dict, out_dir: Path, sha256: str) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{sha256}_floss.json"
    out_path.write_text(json.dumps(raw, indent=2))
    return out_path
