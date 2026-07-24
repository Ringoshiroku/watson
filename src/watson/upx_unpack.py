from __future__ import annotations

import subprocess
from pathlib import Path


class UpxUnpackError(Exception):
    """Raised when upx fails to decompress a file."""


def unpack_file(file_path: Path, output_path: Path, upx_binary: str = "upx", timeout: int = 60) -> None:
    try:
        result = subprocess.run(
            [upx_binary, "-d", "-q", "-o", str(output_path), str(file_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise UpxUnpackError(f"upx timed out after {timeout}s") from exc
    except OSError as exc:
        raise UpxUnpackError(f"failed to run upx: {exc}") from exc

    if result.returncode != 0:
        raise UpxUnpackError(result.stderr.strip() or f"upx exited with code {result.returncode}")
