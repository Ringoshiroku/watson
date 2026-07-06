from __future__ import annotations

import argparse
import sys
from pathlib import Path

from watson.case import Case, Identity, PEMetadata, StaticSection
from watson.hashing import compute_hashes
from watson.pe_metadata import InvalidPEError, extract_pe_metadata
from watson.report import build_text_report


def build_case(file_path: Path) -> Case:
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
    return Case(identity=identity, static=StaticSection(pe_metadata=pe_metadata))


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watson")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single PE file")
    analyze_parser.add_argument("file", type=Path, help="Path to the PE file to analyze")
    analyze_parser.add_argument(
        "--out", type=Path, default=Path("cases"), help="Directory to write the case JSON to"
    )

    args = parser.parse_args(argv)

    if args.command == "analyze":
        return _run_analyze(args.file, args.out)

    return 1


def _run_analyze(file_path: Path, out_dir: Path) -> int:
    if not file_path.is_file():
        print(f"error: {file_path} is not a file", file=sys.stderr)
        return 1

    try:
        case = build_case(file_path)
    except InvalidPEError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    case.save(out_dir)
    print(build_text_report(case))
    return 0


if __name__ == "__main__":
    sys.exit(main())
