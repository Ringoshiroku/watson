from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime
from pathlib import Path

from watson.case import Case, Identity, PEMetadata, StaticSection
from watson.capa_scan import CapaScanError, scan_file as capa_scan_file
from watson.die_scan import DieScanError, scan_file as die_scan_file
from watson.floss_scan import FlossScanError, flatten_strings, save_raw_output, scan_file as floss_scan_file
from watson.hashing import compute_hashes
from watson.classification import classify
from watson.ioc_strings import find_interesting_strings
from watson.pe_metadata import InvalidPEError, extract_pe_metadata
from watson.report import build_json_report, build_text_report
from watson import progress, tool_discovery
from watson.tool_discovery import (
    confirm,
    find_binary,
    find_module,
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

# Same letters as the -y/-c/-f/-d short flags, so what you'd type at the prompt
# and what you'd pass on the command line to skip it match exactly.
CAPABILITY_OPTIONS = [
    ("y", "YARA rule scanning (needs a rule set, fetched if missing)"),
    ("c", "capa capability / ATT&CK / MBC detection (needs capa + a rule set)"),
    ("f", "FLOSS string extraction and IOC flagging"),
    ("d", "Detect It Easy packer/compiler/linker detection (needs diec installed)"),
]


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


def build_case(
    file_path: Path,
    rules_dir: Path | None = None,
    capa_rules_dir: Path | None = None,
    capa_sigs_dir: Path | None = None,
    run_floss: bool | None = None,
    run_die: bool | None = None,
) -> tuple:
    hashes = compute_hashes(file_path)
    metadata = extract_pe_metadata(file_path)

    identity = Identity(
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        imphash=metadata["imphash"],
        file_name=file_path.name,
    )
    pe_metadata = PEMetadata(
        machine=metadata["machine"],
        compile_timestamp=metadata["compile_timestamp"],
        sections=metadata["sections"],
        imports=metadata["imports"],
        has_digital_signature=metadata["has_digital_signature"],
        machine_name=metadata["machine_name"],
        likely_packed=metadata["likely_packed"],
    )

    attempt_yara = True
    attempt_capa = True

    # only ask once, up front, when nothing about which analyses to run was
    # already decided via flags; explicit flags (any one of them) skip this
    # entirely and fall through to each capability's own resolution below,
    # same as before this prompt existed
    if (
        rules_dir is None
        and capa_rules_dir is None
        and run_floss is None
        and run_die is None
        and tool_discovery.is_interactive()
    ):
        selection = select_options("which analyses do you want to run?", CAPABILITY_OPTIONS)
        attempt_yara = "y" in selection.keys
        attempt_capa = "c" in selection.keys
        run_floss = "f" in selection.keys
        run_die = "d" in selection.keys

    tools = {}
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

    if run_floss is None:
        run_floss = confirm(
            f"run FLOSS string extraction on {file_path.name} (finds strings, flags possible IOCs)?"
        )

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

    die_detections = []

    if run_die is None:
        run_die = confirm(
            f"run Detect It Easy packer/compiler/linker detection on {file_path.name}?"
        )

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

    classification = classify(
        yara_matches, capabilities, pe_metadata.likely_packed, tools, pe_metadata.machine
    )

    static = StaticSection(
        pe_metadata=pe_metadata,
        yara_matches=yara_matches,
        tools=tools,
        capabilities=capabilities,
        interesting_strings=interesting_strings,
        classification=classification,
        die_detections=die_detections,
    )
    return Case(identity=identity, static=static), floss_raw


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watson")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single PE file")
    analyze_parser.add_argument("file", type=Path, help="Path to the PE file to analyze")
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
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Show full YARA match detail (string offsets and matched bytes) in the text report",
    )

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
            args.verbose,
        )

    return 1


def _resolve_out_dir(out_dir: Path | None) -> Path:
    if out_dir is not None:
        return out_dir
    if confirm("use a custom output directory instead of ./cases?"):
        custom = input("output directory: ").strip()
        if custom:
            return Path(custom)
    return DEFAULT_OUT_DIR


def _run_analyze(
    file_path: Path,
    out_dir: Path | None,
    rules_dir: Path | None,
    capa_rules_dir: Path | None,
    capa_sigs_dir: Path | None,
    run_floss: bool | None,
    run_die: bool | None,
    verbose: bool,
) -> int:
    if not file_path.is_file():
        print(f"error: {file_path} is not a file", file=sys.stderr)
        return 1

    out_dir = _resolve_out_dir(out_dir)

    try:
        case, floss_raw = build_case(
            file_path, rules_dir, capa_rules_dir, capa_sigs_dir, run_floss, run_die
        )
    except InvalidPEError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    now = datetime.now()
    if floss_raw is not None:
        save_raw_output(floss_raw, out_dir, case.output_basename(now))

    text_report = build_text_report(case, verbose=verbose)
    case.save(out_dir, now, data=build_json_report(case), text_report=text_report)
    print(text_report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
