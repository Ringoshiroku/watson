from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: Optional[str]
    reason: Optional[str]


def _is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _offer_pip_install(name: str, pip_package: str) -> bool:
    answer = input(f"{name} is not installed. install it now with 'pip install {pip_package}'? [y/N] ")
    if answer.strip().lower() != "y":
        return False
    result = subprocess.run([sys.executable, "-m", "pip", "install", pip_package])
    return result.returncode == 0


def find_binary(
    name: str,
    override_path: Optional[str] = None,
    pip_package: Optional[str] = None,
    offline: bool = False,
) -> ToolStatus:
    if override_path:
        if Path(override_path).is_file():
            return ToolStatus(name=name, available=True, path=override_path, reason=None)
        return ToolStatus(
            name=name,
            available=False,
            path=None,
            reason=f"configured path for {name} ({override_path}) does not exist",
        )

    found = shutil.which(name)
    if found:
        return ToolStatus(name=name, available=True, path=found, reason=None)

    if pip_package and not offline and _is_interactive():
        if _offer_pip_install(name, pip_package):
            found = shutil.which(name)
            if found:
                return ToolStatus(name=name, available=True, path=found, reason=None)

    reason = f"{name} not found on PATH"
    reason += f"; install with 'pip install {pip_package}'" if pip_package else "; install it manually"
    return ToolStatus(name=name, available=False, path=None, reason=reason)


def find_module(
    name: str,
    module_name: str,
    pip_package: Optional[str] = None,
    offline: bool = False,
) -> ToolStatus:
    if importlib.util.find_spec(module_name) is not None:
        return ToolStatus(name=name, available=True, path=module_name, reason=None)

    if pip_package and not offline and _is_interactive():
        if _offer_pip_install(name, pip_package):
            importlib.invalidate_caches()
            if importlib.util.find_spec(module_name) is not None:
                return ToolStatus(name=name, available=True, path=module_name, reason=None)

    reason = f"{module_name} python module not found"
    reason += f"; install with 'pip install {pip_package}'" if pip_package else "; install it manually"
    return ToolStatus(name=name, available=False, path=None, reason=reason)
