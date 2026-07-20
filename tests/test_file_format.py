from watson.file_format import detect_format


def test_detect_format_identifies_pe(tmp_path):
    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 62)

    assert detect_format(pe_file) == "pe"


def test_detect_format_identifies_elf(tmp_path):
    elf_file = tmp_path / "sample.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 12)

    assert detect_format(elf_file) == "elf"


def test_detect_format_returns_unknown_for_neither(tmp_path):
    other_file = tmp_path / "sample.bin"
    other_file.write_bytes(b"not a recognized binary at all")

    assert detect_format(other_file) == "unknown"


def test_detect_format_returns_unknown_for_empty_file(tmp_path):
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")

    assert detect_format(empty_file) == "unknown"
