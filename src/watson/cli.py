from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from watson.case import Case, Identity, PEMetadata, StaticSection
from watson.capa_scan import CapaScanError, scan_file as capa_scan_file
from watson.floss_scan import FlossScanError, flatten_strings, save_raw_output, scan_file as floss_scan_file
from watson.hashing import compute_hashes
from watson.ioc_strings import find_interesting_strings
from watson.pe_metadata import InvalidPEError, extract_pe_metadata
from watson.report import build_text_report
from watson import progress, tool_discovery
from watson.tool_discovery import confirm, find_binary, find_module, find_or_fetch_dir, select_options
from watson.yara_scan import YaraScanError, scan_file

WATSON_HOME = Path.home() / ".watson"
YARA_RULES_CACHE = WATSON_HOME / "rules" / "yara-rules"
YARA_RULES_URL = "https://github.com/Yara-Rules/rules"
CAPA_RULES_CACHE = WATSON_HOME / "rules" / "capa-rules"
CAPA_RULES_URL = "https://github.com/mandiant/capa-rules"
CAPA_SIGS_REPO_CACHE = WATSON_HOME / "rules" / "capa-sigs-repo"
CAPA_SIGS_URL = "https://github.com/mandiant/capa"
DEFAULT_OUT_DIR = Path("cases")

# Same letters as the -y/-c/-f short flags, so what you'd type at the prompt
# and what you'd pass on the command line to skip it match exactly.
CAPABILITY_OPTIONS = [
    ("y", "YARA rule scanning (needs a rule set, fetched if missing)"),
    ("c", "capa capability / ATT&CK / MBC detection (needs capa + a rule set)"),
    ("f", "FLOSS string extraction and IOC flagging"),
]


def build_case(
    file_path: Path,
    rules_dir: Path | None = None,
    capa_rules_dir: Path | None = None,
    capa_sigs_dir: Path | None = None,
    run_floss: bool | None = None,
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
    if rules_dir is None and capa_rules_dir is None and run_floss is None and tool_discovery.is_interactive():
        selected = select_options("which analyses do you want to run?", CAPABILITY_OPTIONS)
        attempt_yara = "y" in selected
        attempt_capa = "c" in selected
        run_floss = "f" in selected

    tools = {}
    yara_matches = []

    if attempt_yara:
        yara_dir_status = find_or_fetch_dir(
            "YARA rules", rules_dir, cache_dir=YARA_RULES_CACHE, fetch_url=YARA_RULES_URL
        )
        if yara_dir_status.available:
            yara_status = find_module("yara", "yara", pip_package="yara-python")
            tools["yara"] = {"available": yara_status.available, "reason": yara_status.reason}
            if yara_status.available:
                try:
                    with progress.stage("YARA scan"):
                        yara_matches = scan_file(file_path, Path(yara_dir_status.path))
                except YaraScanError as exc:
                    tools["yara"] = {"available": False, "reason": f"yara scan failed: {exc}"}
        else:
            tools["yara"] = {"available": False, "reason": yara_dir_status.reason}
    else:
        tools["yara"] = {
            "available": False,
            "reason": "not requested (skipped at the analysis-selection prompt)",
        }

    capabilities = []

    if attempt_capa:
        capa_rules_status = find_or_fetch_dir(
            "capa rules", capa_rules_dir, cache_dir=CAPA_RULES_CACHE, fetch_url=CAPA_RULES_URL
        )
        if capa_rules_status.available:
            capa_status = find_binary("capa", pip_package="flare-capa")
            tools["capa"] = {"available": capa_status.available, "reason": capa_status.reason}
            if capa_status.available:
                resolved_sigs_dir = capa_sigs_dir
                if resolved_sigs_dir is None:
                    sigs_repo_status = find_or_fetch_dir(
                        "capa FLIRT signatures",
                        None,
                        cache_dir=CAPA_SIGS_REPO_CACHE,
                        fetch_url=CAPA_SIGS_URL,
                    )
                    if sigs_repo_status.available:
                        resolved_sigs_dir = Path(sigs_repo_status.path) / "sigs"
                try:
                    with progress.stage("capa analysis"):
                        capabilities = capa_scan_file(
                            file_path, Path(capa_rules_status.path), signatures_dir=resolved_sigs_dir
                        )
                except CapaScanError as exc:
                    tools["capa"] = {"available": False, "reason": f"capa scan failed: {exc}"}
        else:
            tools["capa"] = {"available": False, "reason": capa_rules_status.reason}
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
        floss_status = find_binary("floss", pip_package="flare-floss")
        tools["floss"] = {"available": floss_status.available, "reason": floss_status.reason}
        if floss_status.available:
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

    static = StaticSection(
        pe_metadata=pe_metadata,
        yara_matches=yara_matches,
        tools=tools,
        capabilities=capabilities,
        interesting_strings=interesting_strings,
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
    verbose: bool,
) -> int:
    if not file_path.is_file():
        print(f"error: {file_path} is not a file", file=sys.stderr)
        return 1

    out_dir = _resolve_out_dir(out_dir)

    try:
        case, floss_raw = build_case(file_path, rules_dir, capa_rules_dir, capa_sigs_dir, run_floss)
    except InvalidPEError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    now = datetime.now()
    if floss_raw is not None:
        save_raw_output(floss_raw, out_dir, case.output_basename(now))

    case.save(out_dir, now)
    print(build_text_report(case, verbose=verbose))
    return 0


if __name__ == "__main__":
    sys.exit(main())
