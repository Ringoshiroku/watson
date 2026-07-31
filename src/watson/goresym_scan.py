from __future__ import annotations

import json
import subprocess
from pathlib import Path


class GoReSymScanError(Exception):
    """Raised when GoReSym fails to analyze a file."""


def scan_file(file_path: Path, goresym_binary: str = "GoReSym", timeout: int = 60) -> dict:
    try:
        result = subprocess.run(
            [goresym_binary, "-t", "-p", str(file_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GoReSymScanError(f"GoReSym timed out after {timeout}s") from exc
    except OSError as exc:
        raise GoReSymScanError(f"failed to run GoReSym: {exc}") from exc

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise GoReSymScanError(f"GoReSym produced invalid JSON: {exc}") from exc


# GoReSym's own std/user function split isn't reliable (verified live: on a
# recent Go toolchain, internal/runtime/* packages leak into "UserFunctions"
# since GoReSym's bundled standard-package list predates that reorganization),
# so package inclusion here is decided entirely by matching against the
# binary's own declared module path and dependencies, not GoReSym's split.
_KNOWN_NOISE_PREFIXES = ("internal/", "runtime", "vendor/")


def _own_package_prefixes(build_info: dict) -> set:
    prefixes = {"main"}
    module_path = build_info.get("Path")
    if module_path:
        prefixes.add(module_path)
    for dep in build_info.get("Deps") or []:
        dep_path = dep.get("Path")
        if dep_path:
            prefixes.add(dep_path)
    return prefixes


def _is_own_package(package_name: str, own_prefixes: set) -> bool:
    if not package_name or package_name.startswith(_KNOWN_NOISE_PREFIXES):
        return False
    return any(
        package_name == prefix or package_name.startswith(prefix + "/")
        for prefix in own_prefixes
    )


def extract_build_info(raw: dict) -> dict | None:
    if "error" in raw:
        return None

    build_info = raw.get("BuildInfo") or {}
    go_version = build_info.get("GoVersion") or raw.get("Version")
    user_functions = raw.get("UserFunctions") or []
    if not go_version and not user_functions:
        return None

    main = build_info.get("Main") or {}
    dependencies = [
        {"path": dep.get("Path"), "version": dep.get("Version")}
        for dep in (build_info.get("Deps") or [])
    ]

    own_prefixes = _own_package_prefixes(build_info)
    packages: dict = {}
    for func in user_functions:
        package_name = func.get("PackageName") or ""
        if not _is_own_package(package_name, own_prefixes):
            continue
        full_name = func.get("FullName")
        if not full_name:
            continue
        packages.setdefault(package_name, set()).add(full_name)

    return {
        "go_version": go_version,
        "module_path": build_info.get("Path"),
        "module_version": main.get("Version"),
        "dependencies": dependencies,
        "packages": {name: sorted(funcs) for name, funcs in sorted(packages.items())},
    }


def save_goresym_raw(raw: dict, out_dir: Path, base_name: str) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{base_name}_goresym.json"
    out_path.write_text(json.dumps(raw, indent=2))
    return out_path
