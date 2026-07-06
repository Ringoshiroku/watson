from __future__ import annotations

import argparse
import sys
from pathlib import Path

from watson.case import Case, Identity, PEMetadata, StaticSection
from watson.capa_scan import CapaScanError, scan_file as capa_scan_file
from watson.hashing import compute_hashes
from watson.pe_metadata import InvalidPEError, extract_pe_metadata
from watson.report import build_text_report
from watson.tool_discovery import find_binary, find_module
from watson.yara_scan import YaraScanError, scan_file


def build_case(
    file_path: Path, rules_dir: Path | None = None, capa_rules_dir: Path | None = None
) -> Case:
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
    )

    tools = {}
    yara_matches = []

    if rules_dir is not None:
        yara_status = find_module("yara", "yara", pip_package="yara-python")
        tools["yara"] = {"available": yara_status.available, "reason": yara_status.reason}
        if yara_status.available:
            try:
                yara_matches = scan_file(file_path, rules_dir)
            except YaraScanError as exc:
                tools["yara"] = {"available": False, "reason": f"yara scan failed: {exc}"}
    else:
        tools["yara"] = {
            "available": False,
            "reason": "no rules directory provided (use --rules-dir)",
        }

    capabilities = []

    if capa_rules_dir is not None:
        capa_status = find_binary("capa", pip_package="flare-capa")
        tools["capa"] = {"available": capa_status.available, "reason": capa_status.reason}
        if capa_status.available:
            try:
                capabilities = capa_scan_file(file_path, capa_rules_dir)
            except CapaScanError as exc:
                tools["capa"] = {"available": False, "reason": f"capa scan failed: {exc}"}
    else:
        tools["capa"] = {
            "available": False,
            "reason": "no capa rules directory provided (use --capa-rules-dir)",
        }

    static = StaticSection(
        pe_metadata=pe_metadata,
        yara_matches=yara_matches,
        tools=tools,
        capabilities=capabilities,
    )
    return Case(identity=identity, static=static)


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watson")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single PE file")
    analyze_parser.add_argument("file", type=Path, help="Path to the PE file to analyze")
    analyze_parser.add_argument(
        "--out", type=Path, default=Path("cases"), help="Directory to write the case JSON to"
    )
    analyze_parser.add_argument(
        "--rules-dir",
        type=Path,
        default=None,
        help="Directory of .yar YARA rule files to scan the sample with",
    )
    analyze_parser.add_argument(
        "--capa-rules-dir",
        type=Path,
        default=None,
        help="Directory of capa rule files to scan the sample with",
    )

    args = parser.parse_args(argv)

    if args.command == "analyze":
        return _run_analyze(args.file, args.out, args.rules_dir, args.capa_rules_dir)

    return 1


def _run_analyze(
    file_path: Path, out_dir: Path, rules_dir: Path | None, capa_rules_dir: Path | None
) -> int:
    if not file_path.is_file():
        print(f"error: {file_path} is not a file", file=sys.stderr)
        return 1

    try:
        case = build_case(file_path, rules_dir, capa_rules_dir)
    except InvalidPEError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    case.save(out_dir)
    print(build_text_report(case))
    return 0


if __name__ == "__main__":
    sys.exit(main())
