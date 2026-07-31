from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_PYARMOR_SIGNATURE = re.compile(rb"PY\d{6}")


class PyInstallerExtractError(Exception):
    """Raised when pyinstxtractor-ng fails to extract a file."""


def _looks_pyarmor_protected(path: Path) -> bool:
    if path.name.startswith("pyarmor_runtime"):
        return True
    try:
        content = path.read_bytes()
    except OSError:
        return False
    return _PYARMOR_SIGNATURE.search(content) is not None


def _build_manifest(output_dir: Path) -> list:
    entries = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file():
            continue
        entries.append(
            {
                "path": path.relative_to(output_dir).as_posix(),
                "size": path.stat().st_size,
                "pyarmor_protected": _looks_pyarmor_protected(path),
            }
        )
    return entries


def extract_file(
    file_path: Path,
    output_dir: Path,
    extractor_binary: str = "pyinstxtractor-ng",
    timeout: int = 120,
) -> list:
    output_dir = Path(output_dir)
    staged_input = output_dir / file_path.name
    shutil.copy2(file_path, staged_input)

    try:
        result = subprocess.run(
            [extractor_binary, staged_input.name],
            cwd=output_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PyInstallerExtractError(f"pyinstxtractor-ng timed out after {timeout}s") from exc
    except OSError as exc:
        raise PyInstallerExtractError(f"failed to run pyinstxtractor-ng: {exc}") from exc

    if result.returncode != 0:
        raise PyInstallerExtractError(result.stderr.strip() or f"pyinstxtractor-ng exited with code {result.returncode}")

    staged_input.unlink(missing_ok=True)
    return _build_manifest(output_dir)
