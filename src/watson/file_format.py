from __future__ import annotations

from pathlib import Path

_PE_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"


class UnsupportedFormatError(Exception):
    """Raised when a file is neither a recognized PE nor ELF file."""


def detect_format(file_path: Path) -> str:
    with open(file_path, "rb") as f:
        header = f.read(4)
    if header.startswith(_ELF_MAGIC):
        return "elf"
    if header[:2] == _PE_MAGIC:
        return "pe"
    return "unknown"
