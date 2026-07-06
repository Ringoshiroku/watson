import json

from watson.case import Case, Identity, PEMetadata, StaticSection


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


def test_case_round_trips_through_dict():
    case = _sample_case()

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.identity.sha256 == "a" * 64
    assert restored.static.pe_metadata.sections[0]["name"] == ".text"
    assert restored.static.pe_metadata.imports == {"msvcrt.dll": ["printf"]}


def test_case_save_writes_json_named_by_sha256(tmp_path):
    case = _sample_case()

    out_path = case.save(tmp_path)

    assert out_path == tmp_path / f"{'a' * 64}.json"
    assert out_path.exists()
    on_disk = json.loads(out_path.read_text())
    assert on_disk["identity"]["sha256"] == "a" * 64


def test_case_load_reads_back_a_saved_case(tmp_path):
    case = _sample_case()
    out_path = case.save(tmp_path)

    loaded = Case.load(out_path)

    assert loaded.identity.sha256 == case.identity.sha256
    assert loaded.static.pe_metadata.machine == "0x8664"


def test_static_section_defaults_yara_matches_and_tools_when_omitted():
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp=None,
        sections=[],
        imports={},
        has_digital_signature=False,
    )

    static = StaticSection(pe_metadata=pe_metadata)

    assert static.yara_matches == []
    assert static.tools == {}


def test_case_round_trips_yara_matches_and_tools():
    identity = Identity(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe")
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        yara_matches=[{"rule": "test_rule", "tags": [], "matches": []}],
        tools={"yara": {"available": True, "reason": None}},
    )
    case = Case(identity=identity, static=static)

    restored = Case.from_dict(case.to_dict())

    assert restored.static.yara_matches == [{"rule": "test_rule", "tags": [], "matches": []}]
    assert restored.static.tools == {"yara": {"available": True, "reason": None}}


def test_case_load_tolerates_old_format_json_missing_new_fields(tmp_path):
    old_format_data = {
        "identity": {
            "sha256": "a" * 64,
            "sha1": "b" * 40,
            "md5": "c" * 32,
            "imphash": None,
            "file_name": "sample.exe",
        },
        "static": {
            "pe_metadata": {
                "machine": "0x8664",
                "compile_timestamp": None,
                "sections": [],
                "imports": {},
                "has_digital_signature": False,
            }
        },
    }
    case_path = tmp_path / (("a" * 64) + ".json")
    case_path.write_text(json.dumps(old_format_data))

    loaded = Case.load(case_path)

    assert loaded.static.yara_matches == []
    assert loaded.static.tools == {}


def test_static_section_defaults_capabilities_when_omitted():
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp=None,
        sections=[],
        imports={},
        has_digital_signature=False,
    )

    static = StaticSection(pe_metadata=pe_metadata)

    assert static.capabilities == []


def test_case_round_trips_capabilities():
    identity = Identity(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe")
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[{"rule": "watson test fixture string", "namespace": "watson/test", "attack": [], "mbc": []}],
    )
    case = Case(identity=identity, static=static)

    restored = Case.from_dict(case.to_dict())

    assert restored.static.capabilities == [
        {"rule": "watson test fixture string", "namespace": "watson/test", "attack": [], "mbc": []}
    ]


def test_case_load_tolerates_json_missing_capabilities_field(tmp_path):
    data_without_capabilities = {
        "identity": {
            "sha256": "a" * 64,
            "sha1": "b" * 40,
            "md5": "c" * 32,
            "imphash": None,
            "file_name": "sample.exe",
        },
        "static": {
            "pe_metadata": {
                "machine": "0x8664",
                "compile_timestamp": None,
                "sections": [],
                "imports": {},
                "has_digital_signature": False,
            },
            "yara_matches": [],
            "tools": {},
        },
    }
    case_path = tmp_path / (("a" * 64) + ".json")
    case_path.write_text(json.dumps(data_without_capabilities))

    loaded = Case.load(case_path)

    assert loaded.static.capabilities == []


def test_static_section_defaults_interesting_strings_when_omitted():
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp=None,
        sections=[],
        imports={},
        has_digital_signature=False,
    )

    static = StaticSection(pe_metadata=pe_metadata)

    assert static.interesting_strings == []


def test_case_round_trips_interesting_strings():
    identity = Identity(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe")
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        interesting_strings=[{"string": "192.168.1.1", "source": "static_strings", "reason": "ip"}],
    )
    case = Case(identity=identity, static=static)

    restored = Case.from_dict(case.to_dict())

    assert restored.static.interesting_strings == [
        {"string": "192.168.1.1", "source": "static_strings", "reason": "ip"}
    ]


def test_case_load_tolerates_json_missing_interesting_strings_field(tmp_path):
    data_without_interesting_strings = {
        "identity": {
            "sha256": "a" * 64,
            "sha1": "b" * 40,
            "md5": "c" * 32,
            "imphash": None,
            "file_name": "sample.exe",
        },
        "static": {
            "pe_metadata": {
                "machine": "0x8664",
                "compile_timestamp": None,
                "sections": [],
                "imports": {},
                "has_digital_signature": False,
            },
            "yara_matches": [],
            "tools": {},
            "capabilities": [],
        },
    }
    case_path = tmp_path / (("a" * 64) + ".json")
    case_path.write_text(json.dumps(data_without_interesting_strings))

    loaded = Case.load(case_path)

    assert loaded.static.interesting_strings == []
