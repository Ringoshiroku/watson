from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pefile


class InvalidPEError(Exception):
    """Raised when the target file is not a valid PE binary."""


_MACHINE_NAMES = {
    0x14C: "x86 (I386)",
    0x8664: "x64 (AMD64)",
    0x1C0: "ARM",
    0x1C4: "ARM Thumb-2",
    0xAA64: "ARM64",
    0x200: "Itanium",
}

_PACKED_ENTROPY_THRESHOLD = 7.2


def _machine_name(code: int) -> str:
    return _MACHINE_NAMES.get(code, f"unknown ({hex(code)})")


def _is_likely_packed(sections: list) -> bool:
    return any(section["entropy"] >= _PACKED_ENTROPY_THRESHOLD for section in sections)


def extract_pe_metadata(file_path: Path) -> dict:
    try:
        pe = pefile.PE(str(file_path))
    except pefile.PEFormatError as exc:
        raise InvalidPEError(f"{file_path} is not a valid PE file: {exc}") from exc

    try:
        machine = hex(pe.FILE_HEADER.Machine)
        compile_timestamp = _format_timestamp(pe.FILE_HEADER.TimeDateStamp)
        sections = [
            {
                "name": section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 4),
            }
            for section in pe.sections
        ]
        imports = _extract_imports(pe)
        has_digital_signature = _has_digital_signature(pe)
        imphash = pe.get_imphash() or None

        return {
            "machine": machine,
            "machine_name": _machine_name(pe.FILE_HEADER.Machine),
            "compile_timestamp": compile_timestamp,
            "sections": sections,
            "imports": imports,
            "has_digital_signature": has_digital_signature,
            "imphash": imphash,
            "likely_packed": _is_likely_packed(sections),
        }
    finally:
        pe.close()


def _format_timestamp(raw_timestamp: int) -> Optional[str]:
    if raw_timestamp <= 0:
        return None
    return datetime.fromtimestamp(raw_timestamp, tz=timezone.utc).isoformat()


def _extract_imports(pe: "pefile.PE") -> dict:
    imports: dict = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("ascii", errors="replace")
        functions = [
            imp.name.decode("ascii", errors="replace")
            for imp in entry.imports
            if imp.name is not None
        ]
        imports[dll_name] = functions

    return imports


def _has_digital_signature(pe: "pefile.PE") -> bool:
    security_dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    try:
        entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_index]
    except IndexError:
        return False
    return entry.VirtualAddress != 0 and entry.Size != 0
