from watson.elf_metadata import _is_likely_packed, _machine_name, extract_elf_metadata, InvalidELFError


def test_extract_elf_metadata_reads_real_elf(compiled_elf):
    metadata = extract_elf_metadata(compiled_elf)

    assert metadata["machine"] == "EM_X86_64"
    assert metadata["machine_name"] == "x64 (AMD64)"
    assert metadata["entry_point"].startswith("0x")
    assert metadata["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert metadata["is_pie"] is True
    assert metadata["is_stripped"] is False
    assert len(metadata["sections"]) > 0
    assert any(s["name"] == ".text" for s in metadata["sections"])
    assert len(metadata["segments"]) > 0
    assert any(seg["filesz"] > 0 for seg in metadata["segments"])
    assert "libc.so.6" in metadata["needed_libraries"]
    assert "puts" in metadata["dynamic_symbols"]
    assert metadata["likely_packed"] is False
    assert metadata["has_digital_signature"] is False


def test_extract_elf_metadata_reads_static_elf(compiled_elf_static):
    metadata = extract_elf_metadata(compiled_elf_static)

    assert metadata["is_pie"] is False
    assert metadata["interpreter"] is None
    assert metadata["needed_libraries"] == []


def test_machine_name_maps_known_codes():
    assert _machine_name("EM_X86_64") == "x64 (AMD64)"
    assert _machine_name("EM_386") == "x86 (I386)"
    assert _machine_name("EM_AARCH64") == "ARM64"


def test_machine_name_falls_back_for_unknown_code():
    assert "unknown" in _machine_name("EM_MADEUP").lower()


def test_is_likely_packed_true_when_any_section_entropy_high():
    sections = [{"entropy": 3.1}, {"entropy": 7.6}]

    assert _is_likely_packed(sections) is True


def test_is_likely_packed_false_when_all_sections_low_entropy():
    sections = [{"entropy": 3.1}, {"entropy": 5.9}]

    assert _is_likely_packed(sections) is False


def test_is_likely_packed_false_for_no_sections():
    assert _is_likely_packed([]) is False


def test_extract_elf_metadata_rejects_truncated_elf(tmp_path):
    bad_file = tmp_path / "truncated.elf"
    bad_file.write_bytes(b"\x7fELF" + b"\x00" * 10)

    try:
        extract_elf_metadata(bad_file)
        assert False, "expected InvalidELFError"
    except InvalidELFError:
        pass


def test_extract_elf_metadata_detects_module_signature_trailer(compiled_elf):
    signed = compiled_elf.parent / "signed_hello_elf"
    signed.write_bytes(compiled_elf.read_bytes() + b"~Module signature appended~\n")

    metadata = extract_elf_metadata(signed)

    assert metadata["has_digital_signature"] is True
