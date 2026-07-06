from watson.pe_metadata import extract_pe_metadata, InvalidPEError


def test_extract_pe_metadata_reads_real_pe(compiled_pe):
    metadata = extract_pe_metadata(compiled_pe)

    assert metadata["machine"] == "0x8664"
    assert metadata["compile_timestamp"] is not None
    assert len(metadata["sections"]) > 0
    assert any(s["name"].startswith(".text") for s in metadata["sections"])
    assert len(metadata["imports"]) > 0
    assert any(functions for functions in metadata["imports"].values())
    assert "msvcrt.dll" in {dll.lower() for dll in metadata["imports"]}
    assert metadata["has_digital_signature"] is False
    assert metadata["imphash"] is not None


def test_extract_pe_metadata_rejects_non_pe_file(tmp_path):
    bad_file = tmp_path / "not_a_pe.bin"
    bad_file.write_bytes(b"not a pe file at all")

    try:
        extract_pe_metadata(bad_file)
        assert False, "expected InvalidPEError"
    except InvalidPEError:
        pass
