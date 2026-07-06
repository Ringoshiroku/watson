from watson.case import Case, Identity, PEMetadata, StaticSection
from watson.report import build_json_report, build_text_report


def _sample_case() -> Case:
    identity = Identity(
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        imphash="d" * 32,
        file_name="sample.exe",
    )
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp="2026-01-01T00:00:00+00:00",
        sections=[
            {"name": ".text", "virtual_size": 4096, "raw_size": 4096, "entropy": 6.1234},
        ],
        imports={"msvcrt.dll": ["printf"]},
        has_digital_signature=False,
    )
    return Case(identity=identity, static=StaticSection(pe_metadata=pe_metadata))


def test_build_json_report_round_trips_case_data():
    case = _sample_case()

    report = build_json_report(case)

    assert report["identity"]["sha256"] == "a" * 64
    assert report["static"]["pe_metadata"]["machine"] == "0x8664"


def test_build_text_report_contains_key_sections():
    case = _sample_case()

    report = build_text_report(case)

    assert "sample.exe" in report
    assert "a" * 64 in report
    assert ".text" in report
    assert "msvcrt.dll" in report


def _sample_case_with_yara_and_tools() -> Case:
    identity = Identity(
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        imphash="d" * 32,
        file_name="sample.exe",
    )
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp="2026-01-01T00:00:00+00:00",
        sections=[
            {"name": ".text", "virtual_size": 4096, "raw_size": 4096, "entropy": 6.1234},
        ],
        imports={"msvcrt.dll": ["printf"]},
        has_digital_signature=False,
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        yara_matches=[{"rule": "watson_test_fixture_string", "tags": [], "matches": []}],
        tools={"yara": {"available": True, "reason": None}},
    )
    return Case(identity=identity, static=static)


def test_build_text_report_shows_tools_and_yara_matches():
    case = _sample_case_with_yara_and_tools()

    report = build_text_report(case)

    assert "yara: available" in report
    assert "watson_test_fixture_string" in report


def test_build_text_report_shows_no_yara_matches_when_empty():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        tools={"yara": {"available": False, "reason": "no rules directory provided (use --rules-dir)"}},
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert "yara: unavailable (no rules directory provided (use --rules-dir))" in report
    assert "none" in report


def _sample_case_with_capabilities() -> Case:
    identity = Identity(
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        imphash="d" * 32,
        file_name="sample.exe",
    )
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp="2026-01-01T00:00:00+00:00",
        sections=[
            {"name": ".text", "virtual_size": 4096, "raw_size": 4096, "entropy": 6.1234},
        ],
        imports={"msvcrt.dll": ["printf"]},
        has_digital_signature=False,
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[
            {"rule": "watson test fixture string", "namespace": "watson/test", "attack": [], "mbc": []}
        ],
    )
    return Case(identity=identity, static=static)


def test_build_text_report_shows_capabilities():
    case = _sample_case_with_capabilities()

    report = build_text_report(case)

    assert "watson test fixture string" in report


def test_build_text_report_shows_no_capabilities_when_empty():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(pe_metadata=pe_metadata)
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert "Capabilities" in report
    assert "none" in report
