from types import SimpleNamespace

import pefile

from watson.pe_metadata import (
    _extract_requested_execution_level,
    _is_likely_packed,
    _machine_name,
    _MAX_MANIFEST_SIZE,
    extract_pe_metadata,
    InvalidPEError,
)


def _fake_pe_with_manifest_resource(manifest_bytes: bytes):
    # mimics the pefile DIRECTORY_ENTRY_RESOURCE shape that
    # _extract_requested_execution_level walks: a type-level entry (RT_MANIFEST)
    # -> an id-level entry -> a lang-level leaf entry with .data.struct
    # (OffsetToData, Size), backed by a fake get_data that slices the same
    # way pefile's bounds-checked accessor would.
    leaf = SimpleNamespace(
        data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=0, Size=len(manifest_bytes)))
    )
    lang_entry = SimpleNamespace(directory=SimpleNamespace(entries=[leaf]))
    id_entry = SimpleNamespace(
        name=None,
        struct=SimpleNamespace(Id=pefile.RESOURCE_TYPE.get("RT_MANIFEST")),
        directory=SimpleNamespace(entries=[lang_entry]),
    )
    pe = SimpleNamespace(DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[id_entry]))
    pe.get_data = lambda offset, size: manifest_bytes[offset : offset + size]
    return pe


def test_extract_requested_execution_level_rejects_manifest_with_doctype_entity():
    hostile_manifest = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE foo [<!ENTITY x "bomb">]>\n'
        b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
        b"<trustInfo><security><requestedPrivileges>"
        b'<requestedExecutionLevel level="requireAdministrator"/>'
        b"</requestedPrivileges></security></trustInfo></assembly>"
    )
    pe = _fake_pe_with_manifest_resource(hostile_manifest)

    assert _extract_requested_execution_level(pe) is None


def test_extract_requested_execution_level_rejects_oversized_manifest():
    oversized_manifest = b"<assembly>" + b" " * (_MAX_MANIFEST_SIZE + 1) + b"</assembly>"
    pe = _fake_pe_with_manifest_resource(oversized_manifest)

    assert _extract_requested_execution_level(pe) is None


def test_extract_requested_execution_level_reads_well_formed_manifest():
    manifest = (
        b'<?xml version="1.0"?>\n'
        b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
        b"<trustInfo><security><requestedPrivileges>"
        b'<requestedExecutionLevel level="requireAdministrator"/>'
        b"</requestedPrivileges></security></trustInfo></assembly>"
    )
    pe = _fake_pe_with_manifest_resource(manifest)

    assert _extract_requested_execution_level(pe) == "requireAdministrator"


def test_extract_pe_metadata_reads_real_pe(compiled_pe):
    metadata = extract_pe_metadata(compiled_pe)

    assert metadata["machine"] == "0x8664"
    assert metadata["machine_name"] == "x64 (AMD64)"
    assert metadata["compile_timestamp"] is not None
    assert len(metadata["sections"]) > 0
    assert any(s["name"].startswith(".text") for s in metadata["sections"])
    assert len(metadata["imports"]) > 0
    assert any(functions for functions in metadata["imports"].values())
    assert "msvcrt.dll" in {dll.lower() for dll in metadata["imports"]}
    assert metadata["has_digital_signature"] is False
    assert metadata["imphash"] is not None
    # a freshly compiled hello-world binary is not packed
    assert metadata["likely_packed"] is False
    assert metadata["company_name"] is None
    assert metadata["product_name"] is None
    assert metadata["original_filename"] is None
    assert metadata["internal_name"] is None
    assert metadata["file_description"] is None
    assert metadata["requested_execution_level"] is None


def test_extract_pe_metadata_reads_versioninfo_and_manifest(masquerading_pe):
    metadata = extract_pe_metadata(masquerading_pe)

    assert metadata["company_name"] == "Watson Test Company"
    assert metadata["product_name"] == "Watson Test Fixture Product"
    assert metadata["original_filename"] == "original-fixture-name.exe"
    assert metadata["internal_name"] == "fixture-internal-name"
    assert metadata["file_description"] == "Watson test fixture for VERSIONINFO extraction"
    assert metadata["requested_execution_level"] == "requireAdministrator"


def test_machine_name_maps_known_codes():
    assert _machine_name(0x8664) == "x64 (AMD64)"
    assert _machine_name(0x14C) == "x86 (I386)"
    assert _machine_name(0xAA64) == "ARM64"


def test_machine_name_falls_back_for_unknown_code():
    assert "unknown" in _machine_name(0xDEAD).lower()
    assert "0xdead" in _machine_name(0xDEAD).lower()


def test_is_likely_packed_true_when_any_section_entropy_high():
    sections = [{"entropy": 3.1}, {"entropy": 7.6}]

    assert _is_likely_packed(sections) is True


def test_is_likely_packed_false_when_all_sections_low_entropy():
    sections = [{"entropy": 3.1}, {"entropy": 5.9}]

    assert _is_likely_packed(sections) is False


def test_is_likely_packed_false_for_no_sections():
    assert _is_likely_packed([]) is False


def test_extract_pe_metadata_rejects_non_pe_file(tmp_path):
    bad_file = tmp_path / "not_a_pe.bin"
    bad_file.write_bytes(b"not a pe file at all")

    try:
        extract_pe_metadata(bad_file)
        assert False, "expected InvalidPEError"
    except InvalidPEError:
        pass
