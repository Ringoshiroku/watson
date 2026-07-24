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
    except OSError as exc:
        raise DieScanError(f"failed to run diec: {exc}") from exc

    if result.returncode != 0:
        raise DieScanError(result.stderr.strip() or f"diec exited with code {result.returncode}")

    data = _parse_json(result.stdout)
    return _reshape_detects(data)


def _load_json_object(stdout: str):
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


def _parse_json(stdout: str) -> dict:
    data = _load_json_object(stdout)
    if not isinstance(data, dict):
        raise DieScanError(
            f"diec produced unexpected JSON (expected an object, got {type(data).__name__})"
        )
    return data


def _reshape_detects(data: dict) -> list:
    detects = []
    for detect in data.get("detects") or []:
        if not isinstance(detect, dict):
            continue
        values = []
        for value in detect.get("values") or []:
            if not isinstance(value, dict):
                continue
            values.append(
                {
                    "type": value.get("type"),
                    "name": value.get("name"),
                    "version": value.get("version"),
                    "string": value.get("string"),
                }
            )
        detects.append({"filetype": detect.get("filetype"), "values": values})
    return detects


_PACKER_DETECT_TYPES = {"packer", "protector"}


def identify_packers(detections: list) -> list:
    names = []
    for detect in detections:
        for value in detect.get("values") or []:
            if value.get("type") in _PACKER_DETECT_TYPES:
                name = value.get("name")
                if name and name not in names:
                    names.append(name)
    return names
