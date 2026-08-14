from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Optional

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile


class InvalidELFError(Exception):
    """Raised when the target file is not a valid ELF binary."""


_MACHINE_NAMES = {
    "EM_386": "x86 (I386)",
    "EM_X86_64": "x64 (AMD64)",
    "EM_ARM": "ARM",
    "EM_AARCH64": "ARM64",
}

_PACKED_ENTROPY_THRESHOLD = 7.2
_MODULE_SIGNATURE_MAGIC = b"~Module signature appended~\n"


def _machine_name(e_machine: str) -> str:
    return _MACHINE_NAMES.get(e_machine, f"unknown ({e_machine})")


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_likely_packed(sections: list) -> bool:
    return any(section["entropy"] >= _PACKED_ENTROPY_THRESHOLD for section in sections)


def _has_module_signature(file_path: Path) -> bool:
    magic_len = len(_MODULE_SIGNATURE_MAGIC)
    if Path(file_path).stat().st_size < magic_len:
        return False
    with open(file_path, "rb") as f:
        f.seek(-magic_len, 2)
        trailer = f.read()
    return trailer == _MODULE_SIGNATURE_MAGIC


def _extract_interpreter(elf: ELFFile) -> Optional[str]:
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_INTERP":
            return segment.get_interp_name()
    return None


def _extract_sections(elf: ELFFile) -> list:
    sections = []
    for section in elf.iter_sections():
        if section.name == "":
            continue
        data = section.data()
        sections.append(
            {
                "name": section.name,
                "virtual_size": section["sh_size"],
                "raw_size": len(data),
                "entropy": round(_shannon_entropy(data), 4),
            }
        )
    return sections


def _extract_segments(elf: ELFFile) -> list:
    return [
        {
            "vaddr": segment["p_vaddr"],
            "offset": segment["p_offset"],
            "filesz": segment["p_filesz"],
        }
        for segment in elf.iter_segments()
        if segment["p_type"] == "PT_LOAD"
    ]


def _extract_needed_libraries(elf: ELFFile) -> list:
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is None:
        return []
    return [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == "DT_NEEDED"]


def _extract_dynamic_symbols(elf: ELFFile) -> list:
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return []
    return [
        symbol.name
        for symbol in dynsym.iter_symbols()
        if symbol["st_shndx"] == "SHN_UNDEF" and symbol.name
    ]


def extract_elf_metadata(file_path: Path) -> dict:
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            machine = elf.header["e_machine"]
            entry_point = hex(elf.header["e_entry"])
            is_pie = elf.header["e_type"] == "ET_DYN"
            is_stripped = elf.get_section_by_name(".symtab") is None
            interpreter = _extract_interpreter(elf)
            sections = _extract_sections(elf)
            segments = _extract_segments(elf)
            needed_libraries = _extract_needed_libraries(elf)
            dynamic_symbols = _extract_dynamic_symbols(elf)
    except ELFError as exc:
        raise InvalidELFError(f"{file_path} is not a valid ELF file: {exc}") from exc

    return {
        "machine": machine,
        "machine_name": _machine_name(machine),
        "entry_point": entry_point,
        "interpreter": interpreter,
        "is_pie": is_pie,
        "is_stripped": is_stripped,
        "sections": sections,
        "segments": segments,
        "needed_libraries": needed_libraries,
        "dynamic_symbols": dynamic_symbols,
        "likely_packed": _is_likely_packed(sections),
        "has_digital_signature": _has_module_signature(file_path),
    }
