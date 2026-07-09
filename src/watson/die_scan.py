from __future__ import annotations

import json
import subprocess
from pathlib import Path


class DieScanError(Exception):
    """Raised when Detect It Easy fails to analyze a file."""


def scan_file(file_path: Path, diec_binary: str = "diec", timeout: int = 60) -> list:
    try:
        result = subprocess.run(
            [diec_binary, "-j", str(file_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DieScanError(f"diec timed out after {timeout}s") from exc

    if result.returncode != 0:
        raise DieScanError(result.stderr.strip() or f"diec exited with code {result.returncode}")

    data = _parse_json(result.stdout)

    return [
        {
            "filetype": detect.get("filetype"),
            "values": [
                {
                    "type": value.get("type"),
                    "name": value.get("name"),
                    "version": value.get("version"),
                    "string": value.get("string"),
                }
                for value in detect.get("values") or []
            ],
        }
        for detect in data.get("detects") or []
    ]


def _parse_json(stdout: str) -> dict:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(stdout[start : end + 1])
            except json.JSONDecodeError as exc:
                raise DieScanError(f"diec produced invalid JSON: {exc}") from exc
        raise DieScanError("diec produced invalid JSON: no JSON object found in output")
