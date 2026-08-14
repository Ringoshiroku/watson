from __future__ import annotations

from typing import Optional


def pe_file_offset_to_va(offset: int, image_base: int, sections: list) -> Optional[int]:
    for section in sections:
        start = section["raw_offset"]
        end = start + section["raw_size"]
        if start <= offset < end:
            return image_base + section["rva"] + (offset - start)
    return None


def elf_file_offset_to_va(offset: int, segments: list) -> Optional[int]:
    for segment in segments:
        start = segment["offset"]
        end = start + segment["filesz"]
        if start <= offset < end:
            return segment["vaddr"] + (offset - start)
    return None
