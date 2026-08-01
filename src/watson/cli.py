from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
import tempfile
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version as _package_version
from pathlib import Path

from watson.case import (
    Case, ELFMetadata, Identity, PEMetadata, PyInstallerExtractionResult, StaticSection, UnpackingResult,
)
from watson.capa_scan import CapaScanError, scan_file as capa_scan_file
from watson.die_scan import DieScanError, identify_packers, scan_file as die_scan_file
from watson import upx_unpack
from watson.upx_unpack import UpxUnpackError
from watson import pyinstaller_extract
from watson.pyinstaller_extract import PyInstallerExtractError
from watson.elf_metadata import InvalidELFError, extract_elf_metadata
from watson.file_format import UnsupportedFormatError, detect_format
from watson.floss_scan import FlossScanError, flatten_strings, save_raw_output, scan_file as floss_scan_file
from watson import goresym_scan
from watson.goresym_scan import GoReSymScanError
from watson.hashing import compute_hashes
from watson.stringsifter_scan import StringSifterError, rank_strings, save_ranked_strings
from watson.classification import classify
from watson.ioc_strings import find_interesting_strings
from watson.pe_metadata import InvalidPEError, extract_pe_metadata
from watson.report import build_json_report, build_text_report
from watson import progress, tool_discovery
from watson.tool_discovery import (
    confirm,
    find_binary,
    find_module,
    find_or_fetch_binary,
    find_or_fetch_dir,
    find_or_fetch_zip_binary,
    select_options,
)
from watson.yara_scan import YaraScanError, scan_file

WATSON_HOME = Path.home() / ".watson"
YARA_RULES_CACHE = WATSON_HOME / "rules" / "yara-rules"
YARA_RULES_URL = "https://github.com/Yara-Rules/rules"
CAPA_RULES_CACHE = WATSON_HOME / "rules" / "capa-rules"
CAPA_RULES_URL = "https://github.com/mandiant/capa-rules"
CAPA_SIGS_REPO_CACHE = WATSON_HOME / "rules" / "capa-sigs-repo"
CAPA_SIGS_URL = "https://github.com/mandiant/capa"
DEFAULT_OUT_DIR = Path("cases")
DIE_VERSION = "3.21"
DIE_CACHE = WATSON_HOME / "tools" / "diec"
DIE_RELEASE_BASE = f"https://github.com/horsicq/DIE-engine/releases/download/{DIE_VERSION}"
DIE_WIN64_URL = f"{DIE_RELEASE_BASE}/die_win64_portable_{DIE_VERSION}_x64.zip"
DIE_WIN32_URL = f"{DIE_RELEASE_BASE}/die_win32_portable_{DIE_VERSION}_x86.zip"
GORESYM_VERSION = "v3.4"
GORESYM_CACHE = WATSON_HOME / "tools" / "goresym"
GORESYM_RELEASE_BASE = f"https://github.com/mandiant/GoReSym/releases/download/{GORESYM_VERSION}"
GORESYM_LINUX_URL = f"{GORESYM_RELEASE_BASE}/GoReSym-linux.zip"
GORESYM_WINDOWS_URL = f"{GORESYM_RELEASE_BASE}/GoReSym-windows.zip"
UPX_VERSION = "5.2.0"
UPX_CACHE = WATSON_HOME / "tools" / "upx"
UPX_RELEASE_BASE = f"https://github.com/upx/upx/releases/download/v{UPX_VERSION}"
UPX_WIN64_URL = f"{UPX_RELEASE_BASE}/upx-{UPX_VERSION}-win64.zip"
UPX_WIN32_URL = f"{UPX_RELEASE_BASE}/upx-{UPX_VERSION}-win32.zip"
PYINSTXTRACTOR_VERSION = "2026.07.03"
PYINSTXTRACTOR_CACHE = WATSON_HOME / "tools" / "pyinstxtractor"
PYINSTXTRACTOR_RELEASE_BASE = (
    f"https://github.com/pyinstxtractor/pyinstxtractor-ng/releases/download/{PYINSTXTRACTOR_VERSION}"
)
PYINSTXTRACTOR_LINUX_URL = f"{PYINSTXTRACTOR_RELEASE_BASE}/pyinstxtractor-ng"
PYINSTXTRACTOR_WINDOWS_URL = f"{PYINSTXTRACTOR_RELEASE_BASE}/pyinstxtractor-ng.exe"
PYARMOR1SHOT_VERSION = "v0.4.0"
PYARMOR1SHOT_CACHE = WATSON_HOME / "tools" / "pyarmor1shot"
PYARMOR1SHOT_RELEASE_BASE = (
    f"https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases/download/{PYARMOR1SHOT_VERSION}"
)
PYARMOR1SHOT_LINUX_URL = f"{PYARMOR1SHOT_RELEASE_BASE}/pyarmor-1shot-{PYARMOR1SHOT_VERSION}-linux-x86_64.zip"
PYARMOR1SHOT_WINDOWS_URL = f"{PYARMOR1SHOT_RELEASE_BASE}/pyarmor-1shot-{PYARMOR1SHOT_VERSION}-windows-x86_64.zip"
PYARMOR1SHOT_DARWIN_URL = f"{PYARMOR1SHOT_RELEASE_BASE}/pyarmor-1shot-{PYARMOR1SHOT_VERSION}-darwin-arm64.zip"
# modules whose absence means this interpreter was built without a matching
# system -dev header (bz2 breaks FLOSS's networkx import; the others are the
# same class of silent, build-time-only gap)
STDLIB_MODULES_TO_CHECK = ["bz2", "sqlite3", "readline", "lzma"]
# the -dev header each module's C extension needs to compile, for a concrete
# apt install hint (Debian/Kali/Ubuntu, where a from-source pyenv build is the
# realistic way to hit this at all)
STDLIB_MODULE_APT_PACKAGES = {
    "bz2": "libbz2-dev",
    "sqlite3": "libsqlite3-dev",
    "readline": "libreadline-dev",
    "lzma": "liblzma-dev",
}

# Same letters as the -y/-c/-f/-d short flags, so what you'd type at the prompt
# and what you'd pass on the command line to skip it match exactly.
CAPABILITY_OPTIONS = [
    ("y", "YARA rule scanning"),
    ("c", "capa capability / ATT&CK / MBC detection"),
    ("f", "FLOSS string extraction and IOC flagging"),
    ("d", "Detect It Easy packer/compiler/linker detection"),
    ("r", "StringSifter relevance ranking of extracted strings"),
    ("u", "auto-unpack UPX-packed samples and re-analyze the unpacked binary"),
    ("g", "GoReSym Go build info / dependency recovery"),
    ("p", "auto-extract PyInstaller-frozen samples and flag PyArmor-protected contents"),
]


def _capability_flags_suffix(
    attempt_yara, attempt_capa, run_floss, run_die, run_rank, run_unpack, run_goresym, run_extract_pyinstaller
) -> str:
    selected = {
        "y": attempt_yara, "c": attempt_capa, "f": run_floss,
        "d": run_die, "r": run_rank, "u": run_unpack, "g": run_goresym, "p": run_extract_pyinstaller,
    }
    return "".join(key for key, _ in CAPABILITY_OPTIONS if selected[key])


def _die_install_hint() -> str:
    system = platform.system()
    if system == "Linux":
        return (
            "on Debian/Kali/Ubuntu, install with 'sudo apt install detect-it-easy'; "
            "otherwise see https://github.com/horsicq/Detect-It-Easy"
        )
    if system == "Windows":
        return (
            "install with 'choco install die' (Chocolatey), or see "
            "https://github.com/horsicq/Detect-It-Easy/releases"
        )
    return "see https://github.com/horsicq/Detect-It-Easy for install instructions"


def _die_windows_archive_url() -> str | None:
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        return DIE_WIN64_URL
    if machine in ("x86", "i386", "i686"):
        return DIE_WIN32_URL
    return None


def _resolve_yara(rules_dir: Path | None, offline: bool) -> tuple[dict, Path | None]:
    yara_dir_status = find_or_fetch_dir(
        "YARA rules", rules_dir, cache_dir=YARA_RULES_CACHE, fetch_url=YARA_RULES_URL, offline=offline
    )
    if not yara_dir_status.available:
        return {"available": False, "reason": yara_dir_status.reason}, None

    yara_status = find_module("yara", "yara", pip_package="yara-python", offline=offline)
    if not yara_status.available:
        return {"available": False, "reason": yara_status.reason}, None

    return {"available": True, "reason": None}, Path(yara_dir_status.path)


def _resolve_capa(
    capa_rules_dir: Path | None, capa_sigs_dir: Path | None, offline: bool
) -> tuple[dict, Path | None, Path | None]:
    capa_rules_status = find_or_fetch_dir(
        "capa rules", capa_rules_dir, cache_dir=CAPA_RULES_CACHE, fetch_url=CAPA_RULES_URL, offline=offline
    )
    if not capa_rules_status.available:
        return {"available": False, "reason": capa_rules_status.reason}, None, None

    capa_status = find_binary("capa", pip_package="flare-capa", offline=offline)
    if not capa_status.available:
        return {"available": False, "reason": capa_status.reason}, None, None

    resolved_sigs_dir = capa_sigs_dir
    if resolved_sigs_dir is None:
        sigs_repo_status = find_or_fetch_dir(
            "capa FLIRT signatures",
            None,
            cache_dir=CAPA_SIGS_REPO_CACHE,
            fetch_url=CAPA_SIGS_URL,
            offline=offline,
        )
        if sigs_repo_status.available:
            resolved_sigs_dir = Path(sigs_repo_status.path) / "sigs"

    return {"available": True, "reason": None}, Path(capa_rules_status.path), resolved_sigs_dir


def _resolve_floss(offline: bool) -> dict:
    floss_status = find_binary("floss", pip_package="flare-floss", offline=offline)
    return {"available": floss_status.available, "reason": floss_status.reason}


def _resolve_die(offline: bool) -> tuple[dict, str | None]:
    die_status = find_binary("diec", pip_package=None, offline=offline)
    if not die_status.available and platform.system() == "Windows":
        die_status = find_or_fetch_zip_binary(
            "diec",
            "die/diec.exe",
            cache_dir=DIE_CACHE,
            archive_url=_die_windows_archive_url(),
            offline=offline,
        )
    if die_status.available:
        return {"available": True, "reason": None}, die_status.path
    return {"available": False, "reason": _die_install_hint()}, None


def _goresym_archive_url() -> str | None:
    system = platform.system()
    if system == "Linux":
        return GORESYM_LINUX_URL
    if system == "Windows":
        return GORESYM_WINDOWS_URL
    return None


def _goresym_binary_relpath() -> str:
    return "GoReSym.exe" if platform.system() == "Windows" else "GoReSym"


def _resolve_goresym(offline: bool) -> tuple[dict, str | None]:
    goresym_status = find_binary("GoReSym", pip_package=None, offline=offline)
    if not goresym_status.available:
        goresym_status = find_or_fetch_zip_binary(
            "GoReSym",
            _goresym_binary_relpath(),
            cache_dir=GORESYM_CACHE,
            archive_url=_goresym_archive_url(),
            offline=offline,
        )
    if goresym_status.available:
        return {"available": True, "reason": None}, goresym_status.path
    return {"available": False, "reason": goresym_status.reason}, None


def _upx_install_hint() -> str:
    system = platform.system()
    if system == "Linux":
        return (
            "on Debian/Kali/Ubuntu, install with 'sudo apt install upx-ucl'; "
            "otherwise see https://github.com/upx/upx/releases"
        )
    if system == "Windows":
        return (
            "install with 'choco install upx' (Chocolatey), or see "
            "https://github.com/upx/upx/releases"
        )
    return "see https://github.com/upx/upx/releases for install instructions"


def _resolve_upx(offline: bool) -> tuple[dict, str | None]:
    upx_status = find_binary("upx", pip_package=None, offline=offline)
    if not upx_status.available and platform.system() == "Windows":
        machine = platform.machine().lower()
        if machine in ("amd64", "x86_64"):
            archive_url, binary_relpath = UPX_WIN64_URL, f"upx-{UPX_VERSION}-win64/upx.exe"
        elif machine in ("x86", "i386", "i686"):
            archive_url, binary_relpath = UPX_WIN32_URL, f"upx-{UPX_VERSION}-win32/upx.exe"
        else:
            archive_url, binary_relpath = None, ""
        if archive_url:
            upx_status = find_or_fetch_zip_binary(
                "upx", binary_relpath, cache_dir=UPX_CACHE, archive_url=archive_url, offline=offline
            )
    if upx_status.available:
        return {"available": True, "reason": None}, upx_status.path
    return {"available": False, "reason": _upx_install_hint()}, None


def _pyinstxtractor_install_hint() -> str:
    return (
        "no OS package available; download the matching binary from "
        "https://github.com/pyinstxtractor/pyinstxtractor-ng/releases and place it on PATH, "
        "or run 'watson setup' to fetch it automatically (Linux/Windows only)"
    )


def _pyinstxtractor_binary_relpath() -> str:
    return "pyinstxtractor-ng.exe" if platform.system() == "Windows" else "pyinstxtractor-ng"


def _pyinstxtractor_download_url() -> str | None:
    system = platform.system()
    if system == "Linux":
        return PYINSTXTRACTOR_LINUX_URL
    if system == "Windows":
        return PYINSTXTRACTOR_WINDOWS_URL
    return None


def _resolve_pyinstxtractor(offline: bool) -> tuple[dict, str | None]:
    status = find_binary("pyinstxtractor-ng", pip_package=None, offline=offline)
    if not status.available:
        status = find_or_fetch_binary(
            "pyinstxtractor-ng",
            _pyinstxtractor_binary_relpath(),
            cache_dir=PYINSTXTRACTOR_CACHE,
            download_url=_pyinstxtractor_download_url(),
            offline=offline,
        )
    if status.available:
        return {"available": True, "reason": None}, status.path
    return {"available": False, "reason": _pyinstxtractor_install_hint()}, None


def _pyarmor1shot_install_hint() -> str:
    return (
        "no OS package available; download the matching build from "
        "https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases and place the "
        "'oneshot' directory somewhere stable, or run 'watson setup' to fetch it "
        "automatically (Linux x86_64, Windows x86_64, macOS arm64 only)"
    )


def _pyarmor1shot_binary_relpath() -> str | None:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "oneshot/pyarmor-1shot"
    if system == "Windows" and machine in ("amd64", "x86_64"):
        return "oneshot/pyarmor-1shot.exe"
    if system == "Darwin" and machine in ("arm64", "aarch64"):
        return "oneshot/pyarmor-1shot"
    return None


def _pyarmor1shot_download_url() -> str | None:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return PYARMOR1SHOT_LINUX_URL
    if system == "Windows" and machine in ("amd64", "x86_64"):
        return PYARMOR1SHOT_WINDOWS_URL
    if system == "Darwin" and machine in ("arm64", "aarch64"):
        return PYARMOR1SHOT_DARWIN_URL
    return None


def _resolve_pyarmor1shot(offline: bool) -> tuple[dict, str | None]:
    crypto_status = find_module("pycryptodome", "Crypto", pip_package="pycryptodome", offline=offline)
    if not crypto_status.available:
        return {"available": False, "reason": crypto_status.reason}, None

    binary_relpath = _pyarmor1shot_binary_relpath()
    if binary_relpath is None:
        return {"available": False, "reason": _pyarmor1shot_install_hint()}, None

    bundle_status = find_or_fetch_zip_binary(
        "pyarmor-1shot",
        binary_relpath,
        cache_dir=PYARMOR1SHOT_CACHE,
        archive_url=_pyarmor1shot_download_url(),
        offline=offline,
    )
    if not bundle_status.available:
        return {"available": False, "reason": bundle_status.reason}, None

    shot_script = str(Path(bundle_status.path).parent / "shot.py")
    return {"available": True, "reason": None}, shot_script


def _resolve_stringsifter(offline: bool) -> dict:
    stringsifter_status = find_binary("rank_strings", pip_package="stringsifter", offline=offline)
    return {"available": stringsifter_status.available, "reason": stringsifter_status.reason}


def _pyenv_version_from_executable() -> str | None:
    parts = Path(sys.executable).resolve().parts
    try:
        versions_idx = parts.index("versions")
    except ValueError:
        return None
    if versions_idx + 1 < len(parts):
        return parts[versions_idx + 1]
    return None


def _resolve_python_stdlib() -> dict:
    missing = tool_discovery.missing_stdlib_modules(STDLIB_MODULES_TO_CHECK)
    if not missing:
        return {"available": True, "reason": None}

    fix_steps = []
    if platform.system() == "Linux":
        packages = [STDLIB_MODULE_APT_PACKAGES[name] for name in missing if name in STDLIB_MODULE_APT_PACKAGES]
        if packages:
            fix_steps.append(f"sudo apt install {' '.join(packages)}")

    pyenv_version = _pyenv_version_from_executable()
    if pyenv_version:
        fix_steps.append(f"pyenv uninstall {pyenv_version} && pyenv install {pyenv_version}")
    else:
        fix_steps.append("rebuild this interpreter after installing the headers above")

    reason = f"missing stdlib module(s): {', '.join(missing)}. fix: {' && '.join(fix_steps)}"
    return {"available": False, "reason": reason}


def _resolve_capability_selection(
    rules_dir: Path | None,
    capa_rules_dir: Path | None,
    run_floss: bool | None,
    run_die: bool | None,
    run_yara: bool | None,
    run_capa: bool | None,
    run_rank: bool | None,
    run_unpack: bool | None,
    run_goresym: bool | None,
    run_extract_pyinstaller: bool | None,
    subject: str,
) -> tuple:
    attempt_yara = True if run_yara is None else run_yara
    attempt_capa = True if run_capa is None else run_capa
    forced_verbose = False

    # only ask once, up front, when nothing about which analyses to run was
    # already decided via flags; explicit flags (any one of them) skip this
    # entirely and fall through to each capability's own resolution below,
    # same as before this prompt existed
    if (
        rules_dir is None
        and capa_rules_dir is None
        and run_floss is None
        and run_die is None
        and run_yara is None
        and run_capa is None
        and run_rank is None
        and run_unpack is None
        and run_goresym is None
        and run_extract_pyinstaller is None
        and tool_discovery.is_interactive()
    ):
        print("anything not yet installed will be skipped; run 'watson setup' first to install it")
        selection = select_options("which analyses do you want to run?", CAPABILITY_OPTIONS)
        attempt_yara = "y" in selection.keys
        attempt_capa = "c" in selection.keys
        run_floss = "f" in selection.keys
        run_die = "d" in selection.keys
        run_rank = "r" in selection.keys
        run_unpack = "u" in selection.keys
        run_goresym = "g" in selection.keys
        run_extract_pyinstaller = "p" in selection.keys
        forced_verbose = selection.via_all_shorthand

    if run_floss is None:
        run_floss = confirm(
            f"run FLOSS string extraction on {subject} (finds strings, flags possible IOCs)?"
        )

    if run_die is None:
        run_die = confirm(
            f"run Detect It Easy packer/compiler/linker detection on {subject}?"
        )

    if run_rank is None:
        run_rank = confirm(
            f"rank extracted strings by relevance on {subject} using StringSifter?"
        )

    if run_unpack is None:
        run_unpack = confirm(
            f"auto-unpack {subject} with UPX and re-analyze the unpacked binary if UPX packing is detected?"
        )

    if run_goresym is None:
        run_goresym = confirm(
            f"recover Go build info / dependencies from {subject} using GoReSym (Go binaries only)?"
        )

    if run_extract_pyinstaller is None:
        run_extract_pyinstaller = confirm(
            f"extract PyInstaller-frozen contents from {subject} if detected (needs Detect It Easy to run)?"
        )

    return (
        attempt_yara, attempt_capa, run_floss, run_die, run_rank, run_unpack, run_goresym, run_extract_pyinstaller,
        forced_verbose,
    )


def build_case(
    file_path: Path,
    rules_dir: Path | None = None,
    capa_rules_dir: Path | None = None,
    capa_sigs_dir: Path | None = None,
    run_floss: bool | None = None,
    run_die: bool | None = None,
    run_yara: bool | None = None,
    run_capa: bool | None = None,
    run_rank: bool | None = None,
    run_unpack: bool | None = None,
    run_goresym: bool | None = None,
    run_extract_pyinstaller: bool | None = None,
) -> tuple:
    hashes = compute_hashes(file_path)
    file_format = detect_format(file_path)

    if file_format == "pe":
        metadata = extract_pe_metadata(file_path)
        pe_metadata = PEMetadata(
            machine=metadata["machine"],
            compile_timestamp=metadata["compile_timestamp"],
            sections=metadata["sections"],
            imports=metadata["imports"],
            has_digital_signature=metadata["has_digital_signature"],
            machine_name=metadata["machine_name"],
            likely_packed=metadata["likely_packed"],
        )
        elf_metadata = None
        imphash = metadata["imphash"]
        machine_for_classification = pe_metadata.machine
        likely_packed = pe_metadata.likely_packed
        is_unsigned = not pe_metadata.has_digital_signature
    elif file_format == "elf":
        metadata = extract_elf_metadata(file_path)
        elf_metadata = ELFMetadata(
            machine=metadata["machine"],
            machine_name=metadata["machine_name"],
            entry_point=metadata["entry_point"],
            interpreter=metadata["interpreter"],
            is_pie=metadata["is_pie"],
            is_stripped=metadata["is_stripped"],
            sections=metadata["sections"],
            needed_libraries=metadata["needed_libraries"],
            dynamic_symbols=metadata["dynamic_symbols"],
            likely_packed=metadata["likely_packed"],
            has_digital_signature=metadata["has_digital_signature"],
        )
        pe_metadata = None
        imphash = None
        machine_for_classification = elf_metadata.machine
        likely_packed = elf_metadata.likely_packed
        is_unsigned = False
    else:
        raise UnsupportedFormatError(f"{file_path} is not a recognized PE or ELF file")

    identity = Identity(
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        imphash=imphash,
        file_name=file_path.name,
    )

    (
        attempt_yara, attempt_capa, run_floss, run_die, run_rank, run_unpack, run_goresym, run_extract_pyinstaller,
        forced_verbose,
    ) = _resolve_capability_selection(
        rules_dir, capa_rules_dir, run_floss, run_die, run_yara, run_capa,
        run_rank, run_unpack, run_goresym, run_extract_pyinstaller, file_path.name,
    )

    tools = {}
    tools["python"] = _resolve_python_stdlib()
    yara_matches = []

    if attempt_yara:
        tools["yara"], resolved_yara_dir = _resolve_yara(rules_dir, offline=True)
        if tools["yara"]["available"]:
            try:
                with progress.stage("YARA scan"):
                    yara_matches = scan_file(file_path, resolved_yara_dir)
            except YaraScanError as exc:
                tools["yara"] = {"available": False, "reason": f"yara scan failed: {exc}"}
    else:
        tools["yara"] = {
            "available": False,
            "reason": "not requested (skipped at the analysis-selection prompt)",
        }

    capabilities = []

    if attempt_capa:
        tools["capa"], resolved_capa_rules_dir, resolved_sigs_dir = _resolve_capa(
            capa_rules_dir, capa_sigs_dir, offline=True
        )
        if tools["capa"]["available"]:
            try:
                with progress.stage("capa analysis"):
                    capabilities = capa_scan_file(
                        file_path, resolved_capa_rules_dir, signatures_dir=resolved_sigs_dir
                    )
            except CapaScanError as exc:
                tools["capa"] = {"available": False, "reason": f"capa scan failed: {exc}"}
    else:
        tools["capa"] = {
            "available": False,
            "reason": "not requested (skipped at the analysis-selection prompt)",
        }

    interesting_strings = []
    floss_raw = None

    if run_floss:
        tools["floss"] = _resolve_floss(offline=True)
        if tools["floss"]["available"]:
            try:
                with progress.stage("FLOSS string extraction"):
                    floss_raw = floss_scan_file(file_path)
                interesting_strings = find_interesting_strings(flatten_strings(floss_raw))
            except FlossScanError as exc:
                tools["floss"] = {"available": False, "reason": f"floss scan failed: {exc}"}
                floss_raw = None
    else:
        tools["floss"] = {
            "available": False,
            "reason": "floss not requested (use --floss)",
        }

    ranked_strings_full = None

    if run_rank:
        if floss_raw is None:
            tools["stringsifter"] = {
                "available": False,
                "reason": "floss did not run (string ranking needs FLOSS's output)",
            }
        else:
            tools["stringsifter"] = _resolve_stringsifter(offline=True)
            if tools["stringsifter"]["available"]:
                try:
                    with progress.stage("StringSifter ranking"):
                        ranked_strings_full = rank_strings(flatten_strings(floss_raw))
                except StringSifterError as exc:
                    tools["stringsifter"] = {
                        "available": False,
                        "reason": f"stringsifter ranking failed: {exc}",
                    }
                    ranked_strings_full = None
    else:
        tools["stringsifter"] = {
            "available": False,
            "reason": "stringsifter not requested (use --rank-strings)",
        }

    die_detections = []

    if run_die:
        tools["diec"], resolved_diec_path = _resolve_die(offline=True)
        if tools["diec"]["available"]:
            try:
                with progress.stage("Detect It Easy scan"):
                    die_detections = die_scan_file(file_path, diec_binary=resolved_diec_path)
            except DieScanError as exc:
                tools["diec"] = {"available": False, "reason": f"diec scan failed: {exc}"}
                die_detections = []
    else:
        tools["diec"] = {
            "available": False,
            "reason": "diec not requested (use --diec)",
        }

    unpacking = None

    if run_unpack:
        tools["upx"], resolved_upx_path = _resolve_upx(offline=True)
        if tools["upx"]["available"] and "UPX" in identify_packers(die_detections):
            tmp_fd, tmp_path_str = tempfile.mkstemp(suffix=file_path.suffix)
            os.close(tmp_fd)
            tmp_path = Path(tmp_path_str)
            try:
                upx_unpack.unpack_file(file_path, tmp_path, upx_binary=resolved_upx_path)
                unpacking = UnpackingResult(tool="upx", success=True, output_path=str(tmp_path))
            except UpxUnpackError as exc:
                tmp_path.unlink(missing_ok=True)
                unpacking = UnpackingResult(tool="upx", success=False, reason=str(exc))
    else:
        tools["upx"] = {
            "available": False,
            "reason": "unpack not requested (use --unpack)",
        }

    pyinstaller_extraction = None
    pyinstaller_output_dir = None

    if run_extract_pyinstaller:
        if not run_die:
            tools["pyinstxtractor"] = {
                "available": False,
                "reason": "extraction not attempted (needs --diec to have run and identify PyInstaller)",
            }
        else:
            tools["pyinstxtractor"], resolved_pyinstxtractor_path = _resolve_pyinstxtractor(offline=True)
            if tools["pyinstxtractor"]["available"] and "PyInstaller" in identify_packers(die_detections):
                pyinstaller_output_dir = Path(tempfile.mkdtemp())
                try:
                    entries = pyinstaller_extract.extract_file(
                        file_path, pyinstaller_output_dir, extractor_binary=resolved_pyinstxtractor_path
                    )
                    pyinstaller_extraction = PyInstallerExtractionResult(
                        tool="pyinstxtractor-ng",
                        success=True,
                        output_dir=str(pyinstaller_output_dir),
                        entries=entries,
                    )
                except PyInstallerExtractError as exc:
                    shutil.rmtree(pyinstaller_output_dir, ignore_errors=True)
                    pyinstaller_output_dir = None
                    pyinstaller_extraction = PyInstallerExtractionResult(
                        tool="pyinstxtractor-ng", success=False, reason=str(exc)
                    )
    else:
        tools["pyinstxtractor"] = {
            "available": False,
            "reason": "extraction not requested (use --extract-pyinstaller)",
        }

    go_build_info: dict = {}
    goresym_raw = None

    if run_goresym:
        tools["goresym"], resolved_goresym_path = _resolve_goresym(offline=True)
        if tools["goresym"]["available"]:
            try:
                with progress.stage("GoReSym Go build info recovery"):
                    goresym_raw = goresym_scan.scan_file(file_path, goresym_binary=resolved_goresym_path)
                go_build_info = goresym_scan.extract_build_info(goresym_raw) or {}
                if not go_build_info:
                    goresym_raw = None
            except GoReSymScanError as exc:
                tools["goresym"] = {"available": False, "reason": f"goresym scan failed: {exc}"}
                goresym_raw = None
    else:
        tools["goresym"] = {
            "available": False,
            "reason": "goresym not requested (use --goresym)",
        }

    classification = classify(
        yara_matches,
        capabilities,
        likely_packed,
        tools,
        machine_for_classification,
        file_format,
        is_unsigned=is_unsigned,
        die_packer_names=identify_packers(die_detections),
    )

    static = StaticSection(
        pe_metadata=pe_metadata,
        elf_metadata=elf_metadata,
        yara_matches=yara_matches,
        tools=tools,
        capabilities=capabilities,
        interesting_strings=interesting_strings,
        classification=classification,
        die_detections=die_detections,
        ranked_strings=(ranked_strings_full or [])[:20],
        unpacking=unpacking,
        go_build_info=go_build_info,
        pyinstaller_extraction=pyinstaller_extraction,
    )
    resolved_capabilities = (attempt_yara, attempt_capa, run_floss, run_die, run_rank, run_goresym)
    flags_suffix = _capability_flags_suffix(
        attempt_yara, attempt_capa, run_floss, run_die, run_rank, bool(run_unpack), run_goresym,
        bool(run_extract_pyinstaller),
    )
    return (
        Case(identity=identity, static=static),
        floss_raw,
        forced_verbose,
        ranked_strings_full,
        flags_suffix,
        resolved_capabilities,
        goresym_raw,
        pyinstaller_output_dir,
    )


def _watson_version() -> str:
    try:
        return _package_version("watson")
    except PackageNotFoundError:
        return "unknown"


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watson")
    parser.add_argument(
        "-V", "--version", action="version", version=f"watson {_watson_version()}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single PE or ELF file")
    analyze_parser.add_argument(
        "file",
        type=Path,
        help="Path to a PE or ELF file, or a directory to recursively analyze every file inside",
    )
    analyze_parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="Directory to write output to (default cases; omit to be asked interactively)",
    )
    analyze_parser.add_argument(
        "-y",
        "--rules-dir",
        type=Path,
        default=None,
        help="Directory of YARA rule files to scan the sample with",
    )
    analyze_parser.add_argument(
        "-c",
        "--capa-rules-dir",
        type=Path,
        default=None,
        help="Directory of capa rule files to scan the sample with",
    )
    analyze_parser.add_argument(
        "-s",
        "--capa-sigs-dir",
        type=Path,
        default=None,
        help="Directory of capa FLIRT signature files, improves library-function identification",
    )
    analyze_parser.add_argument(
        "-f",
        "--floss",
        action="store_true",
        default=None,
        help=(
            "Run FLOSS to extract all strings (including deobfuscated stack/tight/decoded "
            "strings); only IOC-like matches appear in the report, the full raw output is "
            "written to <out>/<basename>_floss.json. Omit to be asked interactively."
        ),
    )
    analyze_parser.add_argument(
        "-d",
        "--diec",
        action="store_true",
        default=None,
        help=(
            "Run Detect It Easy for packer/compiler/linker detection (needs diec on PATH, "
            "not pip-installable). Omit to be asked interactively."
        ),
    )
    analyze_parser.add_argument(
        "-r",
        "--rank-strings",
        action="store_true",
        default=None,
        help=(
            "Rank FLOSS's extracted strings by relevance using StringSifter (needs --floss to "
            "have run; the top 20 appear in the report, the complete ranking is written to "
            "<out>/<basename>_ranked_strings.json). Omit to be asked interactively."
        ),
    )
    analyze_parser.add_argument(
        "-u",
        "--unpack",
        action="store_true",
        default=None,
        help=(
            "If Detect It Easy identifies UPX packing, unpack the sample and "
            "automatically re-analyze the unpacked binary as a second case "
            "(needs --diec to have run and upx on PATH). Omit to be asked "
            "interactively."
        ),
    )
    analyze_parser.add_argument(
        "-g",
        "--goresym",
        action="store_true",
        default=None,
        help=(
            "Run GoReSym to recover Go build info (module path, dependencies with "
            "versions, own-package function names) from Go binaries; no effect on "
            "non-Go samples. The complete raw recovery data is written to "
            "<out>/<basename>_goresym.json. Omit to be asked interactively."
        ),
    )
    analyze_parser.add_argument(
        "-p",
        "--extract-pyinstaller",
        action="store_true",
        default=None,
        help=(
            "If Detect It Easy identifies PyInstaller framing, extract the sample's bundled "
            "contents with pyinstxtractor-ng and record a manifest, flagging any entries that "
            "look PyArmor-protected (needs --diec to have run). Omit to be asked interactively."
        ),
    )
    analyze_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Show full YARA match detail (string offsets and matched bytes) in the text report",
    )

    setup_parser = subparsers.add_parser("setup", help="Check and install optional analysis tools")

    args = parser.parse_args(argv)

    if args.command == "analyze":
        return _run_analyze(
            args.file,
            args.out,
            args.rules_dir,
            args.capa_rules_dir,
            args.capa_sigs_dir,
            args.floss,
            args.diec,
            args.rank_strings,
            args.unpack,
            args.goresym,
            args.extract_pyinstaller,
            args.verbose,
        )

    if args.command == "setup":
        return _run_setup()

    return 1


def _resolve_out_dir(out_dir: Path | None) -> Path:
    if out_dir is not None:
        return out_dir
    if confirm("use a custom output directory instead of ./cases?"):
        custom = input("output directory: ").strip()
        if custom:
            return Path(custom)
    return DEFAULT_OUT_DIR


def _run_setup() -> int:
    print("Checking optional analysis tools...")
    in_venv = sys.prefix != sys.base_prefix
    print(f"Running under: {sys.executable} (virtual environment: {'yes' if in_venv else 'no'})")
    print()

    tools = {}
    tools["python"] = _resolve_python_stdlib()
    tools["yara"], _ = _resolve_yara(None, offline=False)
    tools["capa"], _, _ = _resolve_capa(None, None, offline=False)
    tools["floss"] = _resolve_floss(offline=False)
    tools["diec"], _ = _resolve_die(offline=False)
    tools["goresym"], _ = _resolve_goresym(offline=False)
    tools["pyinstxtractor"], _ = _resolve_pyinstxtractor(offline=False)
    tools["pyarmor1shot"], _ = _resolve_pyarmor1shot(offline=False)
    tools["stringsifter"] = _resolve_stringsifter(offline=False)

    print()
    print("Summary")
    print("-------")
    for name, status in tools.items():
        state = "available" if status["available"] else "unavailable"
        line = f"  {name}: {state}"
        if status["reason"]:
            line += f" ({status['reason']})"
        print(line)

    print()
    print("Run 'watson analyze <file>' when ready.")
    return 0


def _run_analyze(
    file_path: Path,
    out_dir: Path | None,
    rules_dir: Path | None,
    capa_rules_dir: Path | None,
    capa_sigs_dir: Path | None,
    run_floss: bool | None,
    run_die: bool | None,
    run_rank: bool | None,
    run_unpack: bool | None,
    run_goresym: bool | None,
    run_extract_pyinstaller: bool | None,
    verbose: bool,
) -> int:
    if file_path.is_dir():
        return _run_batch(
            file_path,
            out_dir,
            rules_dir,
            capa_rules_dir,
            capa_sigs_dir,
            run_floss,
            run_die,
            run_rank,
            run_unpack,
            run_goresym,
            run_extract_pyinstaller,
            verbose,
        )

    if not file_path.is_file():
        print(f"error: {file_path} is not a file or directory", file=sys.stderr)
        return 1

    out_dir = _resolve_out_dir(out_dir)

    try:
        (
            case, floss_raw, forced_verbose, ranked_strings_full, flags_suffix,
            resolved_capabilities, goresym_raw, pyinstaller_output_dir,
        ) = build_case(
            file_path, rules_dir, capa_rules_dir, capa_sigs_dir, run_floss, run_die,
            run_rank=run_rank, run_unpack=run_unpack, run_goresym=run_goresym,
            run_extract_pyinstaller=run_extract_pyinstaller,
        )
    except (InvalidPEError, InvalidELFError, UnsupportedFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    effective_verbose = verbose or forced_verbose

    now = datetime.now()
    unpacked_text_report = None

    if case.static.unpacking is not None and case.static.unpacking.success:
        out_dir.mkdir(parents=True, exist_ok=True)
        unpacked_path = out_dir / f"{case.output_basename(now, flags_suffix)}_unpacked{file_path.suffix}"
        shutil.move(case.static.unpacking.output_path, unpacked_path)
        case.static.unpacking.output_path = str(unpacked_path)

        (
            attempt_yara, attempt_capa, run_floss_resolved, run_die_resolved,
            run_rank_resolved, run_goresym_resolved,
        ) = resolved_capabilities
        try:
            (
                unpacked_case, unpacked_floss_raw, _, unpacked_ranked_strings_full,
                unpacked_flags_suffix, _, unpacked_goresym_raw, _,
            ) = build_case(
                unpacked_path, rules_dir, capa_rules_dir, capa_sigs_dir, run_floss_resolved, run_die_resolved,
                attempt_yara, attempt_capa, run_rank_resolved, run_unpack=False,
                run_goresym=run_goresym_resolved,
            )
        except (InvalidPEError, InvalidELFError, UnsupportedFormatError) as exc:
            case.static.unpacking.reason = f"unpacked but re-analysis failed: {exc}"
        else:
            case.static.unpacking.unpacked_sha256 = unpacked_case.identity.sha256

            unpacked_now = datetime.now()
            if unpacked_floss_raw is not None:
                save_raw_output(unpacked_floss_raw, out_dir, unpacked_case.output_basename(unpacked_now, unpacked_flags_suffix))
            if unpacked_ranked_strings_full is not None:
                save_ranked_strings(
                    unpacked_ranked_strings_full, out_dir, unpacked_case.output_basename(unpacked_now, unpacked_flags_suffix)
                )
            if unpacked_goresym_raw is not None:
                goresym_scan.save_goresym_raw(
                    unpacked_goresym_raw, out_dir, unpacked_case.output_basename(unpacked_now, unpacked_flags_suffix)
                )
            unpacked_text_report = build_text_report(unpacked_case, verbose=effective_verbose)
            unpacked_case.save(
                out_dir, unpacked_now, data=build_json_report(unpacked_case),
                text_report=unpacked_text_report, flags=unpacked_flags_suffix,
            )

    if case.static.pyinstaller_extraction is not None and case.static.pyinstaller_extraction.success:
        out_dir.mkdir(parents=True, exist_ok=True)
        extracted_dir = out_dir / f"{case.output_basename(now, flags_suffix)}_pyinstaller_extracted"
        shutil.move(str(pyinstaller_output_dir), str(extracted_dir))
        case.static.pyinstaller_extraction.output_dir = str(extracted_dir)

    if floss_raw is not None:
        save_raw_output(floss_raw, out_dir, case.output_basename(now, flags_suffix))
    if ranked_strings_full is not None:
        save_ranked_strings(ranked_strings_full, out_dir, case.output_basename(now, flags_suffix))
    if goresym_raw is not None:
        goresym_scan.save_goresym_raw(goresym_raw, out_dir, case.output_basename(now, flags_suffix))

    text_report = build_text_report(case, verbose=effective_verbose)
    case.save(out_dir, now, data=build_json_report(case), text_report=text_report, flags=flags_suffix)
    print(text_report)

    if unpacked_text_report is not None:
        print()
        print("=" * 30)
        print("Unpacked binary analysis")
        print("=" * 30)
        print(unpacked_text_report)

    return 0


def _build_batch_summary(total: int, analyzed: int, skipped: int, failed: list, unpacked: int) -> str:
    lines = [
        "Batch summary",
        "-------------",
        f"scanned: {total} files",
        f"  analyzed: {analyzed}",
        f"  skipped (not a valid PE or ELF): {skipped}",
        f"  failed: {len(failed)}",
        f"  unpacked: {unpacked}",
    ]
    if failed:
        lines.append("")
        lines.append("Failed:")
        for name, reason in failed:
            lines.append(f"  {name}: {reason}")
    return "\n".join(lines)


def _run_batch(
    dir_path: Path,
    out_dir: Path | None,
    rules_dir: Path | None,
    capa_rules_dir: Path | None,
    capa_sigs_dir: Path | None,
    run_floss: bool | None,
    run_die: bool | None,
    run_rank: bool | None,
    run_unpack: bool | None,
    run_goresym: bool | None,
    run_extract_pyinstaller: bool | None,
    verbose: bool,
) -> int:
    out_dir = _resolve_out_dir(out_dir)
    files = sorted(path for path in dir_path.rglob("*") if path.is_file())

    (
        attempt_yara, attempt_capa, run_floss, run_die, run_rank, run_unpack, run_goresym, run_extract_pyinstaller,
        forced_verbose,
    ) = _resolve_capability_selection(
        rules_dir, capa_rules_dir, run_floss, run_die, None, None, run_rank,
        run_unpack, run_goresym, run_extract_pyinstaller, "this batch",
    )
    effective_verbose = verbose or forced_verbose
    flags_suffix = _capability_flags_suffix(
        attempt_yara, attempt_capa, run_floss, run_die, run_rank, bool(run_unpack), run_goresym,
        bool(run_extract_pyinstaller),
    )

    total = len(files)
    analyzed = 0
    skipped = 0
    failed = []
    unpacked = 0

    for index, file_path in enumerate(files, start=1):
        try:
            (
                case, floss_raw, _, ranked_strings_full, _, resolved_capabilities, goresym_raw,
                pyinstaller_output_dir,
            ) = build_case(
                file_path,
                rules_dir,
                capa_rules_dir,
                capa_sigs_dir,
                run_floss,
                run_die,
                attempt_yara,
                attempt_capa,
                run_rank,
                run_unpack=run_unpack,
                run_goresym=run_goresym,
                run_extract_pyinstaller=run_extract_pyinstaller,
            )
        except (InvalidPEError, InvalidELFError, UnsupportedFormatError):
            skipped += 1
            print(f"[{index}/{total}] {file_path.name}: skipped (not a valid PE or ELF)", file=sys.stderr)
            continue
        except Exception as exc:
            # a single file's tool crash or read failure shouldn't take the
            # whole batch down; record it and keep going
            failed.append((file_path.name, str(exc)))
            print(f"[{index}/{total}] {file_path.name}: failed ({exc})", file=sys.stderr)
            continue

        now = datetime.now()
        unpacked_text_note = ""

        if case.static.unpacking is not None and case.static.unpacking.success:
            out_dir.mkdir(parents=True, exist_ok=True)
            unpacked_path = out_dir / f"{case.output_basename(now, flags_suffix)}_unpacked{file_path.suffix}"
            shutil.move(case.static.unpacking.output_path, unpacked_path)
            case.static.unpacking.output_path = str(unpacked_path)

            (
                r_attempt_yara, r_attempt_capa, r_run_floss, r_run_die, r_run_rank, r_run_goresym,
            ) = resolved_capabilities
            try:
                (
                    unpacked_case, unpacked_floss_raw, _, unpacked_ranked_strings_full,
                    unpacked_flags_suffix, _, unpacked_goresym_raw, _,
                ) = build_case(
                    unpacked_path, rules_dir, capa_rules_dir, capa_sigs_dir, r_run_floss, r_run_die,
                    r_attempt_yara, r_attempt_capa, r_run_rank, run_unpack=False,
                    run_goresym=r_run_goresym,
                )
            except (InvalidPEError, InvalidELFError, UnsupportedFormatError) as exc:
                case.static.unpacking.reason = f"unpacked but re-analysis failed: {exc}"
                unpacked += 1
                unpacked_text_note = " [unpacked, re-analysis failed]"
            else:
                case.static.unpacking.unpacked_sha256 = unpacked_case.identity.sha256

                unpacked_now = datetime.now()
                if unpacked_floss_raw is not None:
                    save_raw_output(unpacked_floss_raw, out_dir, unpacked_case.output_basename(unpacked_now, unpacked_flags_suffix))
                if unpacked_ranked_strings_full is not None:
                    save_ranked_strings(
                        unpacked_ranked_strings_full, out_dir,
                        unpacked_case.output_basename(unpacked_now, unpacked_flags_suffix),
                    )
                if unpacked_goresym_raw is not None:
                    goresym_scan.save_goresym_raw(
                        unpacked_goresym_raw, out_dir,
                        unpacked_case.output_basename(unpacked_now, unpacked_flags_suffix),
                    )
                unpacked_text_report = build_text_report(unpacked_case, verbose=effective_verbose)
                unpacked_case.save(
                    out_dir, unpacked_now, data=build_json_report(unpacked_case),
                    text_report=unpacked_text_report, flags=unpacked_flags_suffix,
                )
                unpacked += 1
                unpacked_text_note = " [unpacked]"

        if case.static.pyinstaller_extraction is not None and case.static.pyinstaller_extraction.success:
            out_dir.mkdir(parents=True, exist_ok=True)
            extracted_dir = out_dir / f"{case.output_basename(now, flags_suffix)}_pyinstaller_extracted"
            shutil.move(str(pyinstaller_output_dir), str(extracted_dir))
            case.static.pyinstaller_extraction.output_dir = str(extracted_dir)
            unpacked_text_note += " [pyinstaller extracted]"

        if floss_raw is not None:
            save_raw_output(floss_raw, out_dir, case.output_basename(now, flags_suffix))
        if ranked_strings_full is not None:
            save_ranked_strings(ranked_strings_full, out_dir, case.output_basename(now, flags_suffix))
        if goresym_raw is not None:
            goresym_scan.save_goresym_raw(goresym_raw, out_dir, case.output_basename(now, flags_suffix))

        text_report = build_text_report(case, verbose=effective_verbose)
        case.save(out_dir, now, data=build_json_report(case), text_report=text_report, flags=flags_suffix)

        analyzed += 1
        verdict = case.static.classification["verdict"]
        risk = case.static.classification["risk"]
        print(f"[{index}/{total}] {file_path.name}: {verdict} ({risk} risk){unpacked_text_note}", file=sys.stderr)

    summary = _build_batch_summary(total, analyzed, skipped, failed, unpacked)
    print(summary)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_timestamp = datetime.now().strftime("%H-%M-%S-%d-%m-%Y")
    (out_dir / f"{summary_timestamp}-batch-summary.txt").write_text(summary + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
