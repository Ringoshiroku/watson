from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: Optional[str]
    reason: Optional[str]


@dataclass
class Selection:
    keys: set
    via_all_shorthand: bool


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def confirm(prompt: str) -> bool:
    if not is_interactive():
        return False
    answer = input(f"{prompt} [y/N] ")
    return answer.strip().lower() == "y"


def select_options(prompt: str, options: list, all_key: str = "a", none_key: str = "n") -> Selection:
    if not is_interactive():
        return Selection(keys=set(), via_all_shorthand=False)
    print(prompt)
    for key, description in options:
        print(f"  {key}  {description}")
    print(f"  {all_key}  all of the above")
    print(f"  {none_key}  none")
    example = "".join(key for key, _ in options[:2])
    answer = input(f'type the letters you want (e.g. "{example}"), or leave blank for none: ')
    answer = answer.strip().lower()
    if all_key in answer:
        return Selection(keys={key for key, _ in options}, via_all_shorthand=True)
    if not answer or none_key in answer:
        return Selection(keys=set(), via_all_shorthand=False)
    return Selection(keys={key for key, _ in options if key in answer}, via_all_shorthand=False)


_PIP_FAILURE_HINTS = (
    (
        "externally-managed-environment",
        "hint: pip refused because this Python is externally managed (PEP 668). "
        "Confirm the Python running this command is really inside your venv, "
        "or create/activate one: python3 -m venv .venv && source .venv/bin/activate",
    ),
    (
        "setuptools.build_meta",
        "hint: pip's build step couldn't find setuptools (common on Python 3.12+ "
        "venvs, which no longer bundle it). Try: "
        "pip install --upgrade pip setuptools wheel",
    ),
)


def _offer_pip_install(name: str, pip_package: str) -> bool:
    answer = input(f"{name} is not installed. install it now with 'pip install {pip_package}'? [y/N] ")
    if answer.strip().lower() != "y":
        return False
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", pip_package],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print(result.stdout, end="")
    if result.returncode != 0:
        for signature, hint in _PIP_FAILURE_HINTS:
            if signature in result.stdout:
                print(hint)
    return result.returncode == 0


def _venv_scoped_which(name: str) -> Optional[str]:
    # console scripts pip-installs alongside the running interpreter (e.g. a
    # venv's bin/) aren't necessarily on PATH unless that venv is activated;
    # shutil.which alone misses them even though they're clearly "installed".
    venv_bin = Path(sys.executable).parent
    for candidate_name in (name, f"{name}.exe"):
        candidate = venv_bin / candidate_name
        if candidate.is_file():
            return str(candidate)
    return None


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

    found = shutil.which(name) or _venv_scoped_which(name)
    if found:
        return ToolStatus(name=name, available=True, path=found, reason=None)

    if pip_package and not offline and is_interactive():
        if _offer_pip_install(name, pip_package):
            found = shutil.which(name) or _venv_scoped_which(name)
            if found:
                return ToolStatus(name=name, available=True, path=found, reason=None)

    reason = f"{name} not found on PATH"
    reason += f"; install with 'pip install {pip_package}'" if pip_package else "; install it manually"
    return ToolStatus(name=name, available=False, path=None, reason=reason)


def _offer_git_clone(name: str, fetch_url: str, dest: Path) -> bool:
    git_path = shutil.which("git")
    if git_path is None:
        return False
    answer = input(f"{name} not found locally. fetch it now with 'git clone {fetch_url}'? [y/N] ")
    if answer.strip().lower() != "y":
        return False
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([git_path, "clone", "--depth", "1", "--progress", fetch_url, str(dest)])
    return result.returncode == 0


def find_or_fetch_dir(
    name: str,
    configured_path: Optional[Path],
    cache_dir: Path,
    fetch_url: Optional[str] = None,
    offline: bool = False,
) -> ToolStatus:
    if configured_path is not None:
        if Path(configured_path).is_dir():
            return ToolStatus(name=name, available=True, path=str(configured_path), reason=None)
        return ToolStatus(
            name=name,
            available=False,
            path=None,
            reason=f"configured path for {name} ({configured_path}) does not exist",
        )

    cache_dir = Path(cache_dir)
    if cache_dir.is_dir() and any(cache_dir.iterdir()):
        return ToolStatus(name=name, available=True, path=str(cache_dir), reason=None)

    if fetch_url and not offline and is_interactive():
        if _offer_git_clone(name, fetch_url, cache_dir):
            if cache_dir.is_dir() and any(cache_dir.iterdir()):
                return ToolStatus(name=name, available=True, path=str(cache_dir), reason=None)

    reason = f"{name} not found locally"
    reason += f"; fetch with 'git clone {fetch_url} {cache_dir}'" if fetch_url else "; provide a path manually"
    return ToolStatus(name=name, available=False, path=None, reason=reason)


def _offer_zip_download(name: str, archive_url: str, cache_dir: Path, binary_relpath: str) -> bool:
    answer = input(
        f"{name} not found locally. download the official portable build now from {archive_url}? [y/N] "
    )
    if answer.strip().lower() != "y":
        return False

    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            with urllib.request.urlopen(archive_url, timeout=60) as response:
                shutil.copyfileobj(response, tmp)
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmp_path) as archive:
            archive.extractall(cache_dir)
        target = Path(cache_dir) / binary_relpath
        if os.name == "posix" and target.is_file():
            target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except (OSError, zipfile.BadZipFile, urllib.error.URLError) as exc:
        print(f"download/extract failed: {exc}")
        return False
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    return (Path(cache_dir) / binary_relpath).is_file()


def find_or_fetch_zip_binary(
    name: str,
    binary_relpath: str,
    cache_dir: Path,
    archive_url: Optional[str],
    offline: bool = False,
) -> ToolStatus:
    cache_dir = Path(cache_dir)
    cached_binary = cache_dir / binary_relpath
    if cached_binary.is_file():
        return ToolStatus(name=name, available=True, path=str(cached_binary), reason=None)

    if archive_url and not offline and is_interactive():
        if _offer_zip_download(name, archive_url, cache_dir, binary_relpath):
            return ToolStatus(name=name, available=True, path=str(cached_binary), reason=None)

    reason = f"{name} not found locally"
    reason += f"; fetch the portable build from {archive_url}" if archive_url else "; install it manually"
    return ToolStatus(name=name, available=False, path=None, reason=reason)


def find_module(
    name: str,
    module_name: str,
    pip_package: Optional[str] = None,
    offline: bool = False,
) -> ToolStatus:
    if importlib.util.find_spec(module_name) is not None:
        return ToolStatus(name=name, available=True, path=module_name, reason=None)

    if pip_package and not offline and is_interactive():
        if _offer_pip_install(name, pip_package):
            importlib.invalidate_caches()
            if importlib.util.find_spec(module_name) is not None:
                return ToolStatus(name=name, available=True, path=module_name, reason=None)

    reason = f"{module_name} python module not found"
    reason += f"; install with 'pip install {pip_package}'" if pip_package else "; install it manually"
    return ToolStatus(name=name, available=False, path=None, reason=reason)


def missing_stdlib_modules(module_names: list) -> list:
    # find_spec alone isn't enough: bz2/sqlite3 are pure-Python wrappers
    # (bz2.py does `from _bz2 import ...`) whose spec exists even when the
    # underlying compiled C extension doesn't, so only a real import proves
    # the module actually works.
    missing = []
    for name in module_names:
        try:
            importlib.import_module(name)
        except ImportError:
            missing.append(name)
    return missing


def check_stdlib_modules(module_names: list) -> ToolStatus:
    # unlike a missing pip package, a missing stdlib extension (bz2, sqlite3,
    # readline, lzma, ...) means this interpreter itself was built without the
    # matching system -dev header, no pip install can fix that: it needs a
    # rebuild after installing the header, e.g. via pyenv.
    missing = missing_stdlib_modules(module_names)
    if not missing:
        return ToolStatus(name="python", available=True, path=sys.executable, reason=None)

    reason = (
        f"missing stdlib module(s): {', '.join(missing)}; this interpreter was likely built "
        "without their system -dev headers (see "
        "https://www.kali.org/docs/general-use/using-eol-python-versions/), rebuild it after "
        "installing them, e.g. 'pyenv uninstall <version> && pyenv install <version>' for a "
        "pyenv-managed interpreter"
    )
    return ToolStatus(name="python", available=False, path=sys.executable, reason=reason)
