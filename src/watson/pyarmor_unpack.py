from __future__ import annotations

import subprocess
import sys
from pathlib import Path


class PyArmorUnpackError(Exception):
    """Raised when pyarmor-1shot fails to decrypt/decompile a directory."""


def _build_manifest(output_dir: Path) -> list:
    entries = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file():
            continue
        entries.append(
            {
                "path": path.relative_to(output_dir).as_posix(),
                "size": path.stat().st_size,
            }
        )
    return entries


def unpack_dir(
    input_dir: Path,
    output_dir: Path,
    shot_script: str,
    timeout: int = 300,
) -> list:
    output_dir = Path(output_dir)

    try:
        result = subprocess.run(
            [sys.executable, shot_script, str(input_dir), "--no-banner", "-o", str(output_dir)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PyArmorUnpackError(f"pyarmor-1shot timed out after {timeout}s") from exc
    except OSError as exc:
        raise PyArmorUnpackError(f"failed to run pyarmor-1shot: {exc}") from exc

    if result.returncode != 0:
        raise PyArmorUnpackError(result.stderr.strip() or f"pyarmor-1shot exited with code {result.returncode}")

    entries = _build_manifest(output_dir)
    if not entries:
        raise PyArmorUnpackError(result.stderr.strip() or "pyarmor-1shot produced no output files")
    return entries
