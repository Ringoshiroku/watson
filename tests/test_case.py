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
