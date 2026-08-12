import json

from watson.case import Case, ELFMetadata, Identity, PEMetadata, StaticSection


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


def test_case_round_trips_unpacking_result_through_dict():
    from watson.case import UnpackingResult

    case = _sample_case()
    case.static.unpacking = UnpackingResult(
        tool="upx", success=True, output_path="/tmp/unpacked.exe", unpacked_sha256="f" * 64
    )

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.unpacking == UnpackingResult(
        tool="upx", success=True, output_path="/tmp/unpacked.exe", unpacked_sha256="f" * 64
    )


def test_case_round_trips_absent_unpacking_result_as_none():
    case = _sample_case()

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.unpacking is None


def test_case_round_trips_signature_verification_through_dict():
    from watson.case import SignatureVerification

    case = _sample_case()
    case.static.signature_verification = SignatureVerification(
        tool="signify",
        status="invalid",
        verification_result="CERTIFICATE_ERROR",
        signer_subject="CN=Example Signer",
        signer_issuer="CN=Example Root",
        valid_from="2026-01-01T00:00:00+00:00",
        valid_to="2027-01-01T00:00:00+00:00",
        error="untrusted root",
    )

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.signature_verification == SignatureVerification(
        tool="signify",
        status="invalid",
        verification_result="CERTIFICATE_ERROR",
        signer_subject="CN=Example Signer",
        signer_issuer="CN=Example Root",
        valid_from="2026-01-01T00:00:00+00:00",
        valid_to="2027-01-01T00:00:00+00:00",
        error="untrusted root",
    )


def test_case_round_trips_absent_signature_verification_as_none():
    case = _sample_case()

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.signature_verification is None


def test_case_round_trips_pe_metadata_versioninfo_fields_through_dict():
    case = _sample_case()
    case.static.pe_metadata.company_name = "Watson Test Company"
    case.static.pe_metadata.product_name = "Watson Test Product"
    case.static.pe_metadata.original_filename = "legit.exe"
    case.static.pe_metadata.internal_name = "legit"
    case.static.pe_metadata.file_description = "Watson Test Description"
    case.static.pe_metadata.requested_execution_level = "requireAdministrator"

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.pe_metadata.company_name == "Watson Test Company"
    assert restored.static.pe_metadata.product_name == "Watson Test Product"
    assert restored.static.pe_metadata.original_filename == "legit.exe"
    assert restored.static.pe_metadata.internal_name == "legit"
    assert restored.static.pe_metadata.file_description == "Watson Test Description"
    assert restored.static.pe_metadata.requested_execution_level == "requireAdministrator"


def test_case_round_trips_pe_metadata_versioninfo_fields_default_to_none():
    case = _sample_case()

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.pe_metadata.company_name is None
    assert restored.static.pe_metadata.requested_execution_level is None


def test_case_round_trips_masquerade_check_through_dict():
    from watson.case import MasqueradeCheck

    case = _sample_case()
    case.static.masquerade_check = MasqueradeCheck(
        filename_mismatch=True,
        claimed_vendor_mismatch=True,
        claimed_vendor="Microsoft Corporation",
        requested_execution_level="requireAdministrator",
    )

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.masquerade_check == MasqueradeCheck(
        filename_mismatch=True,
        claimed_vendor_mismatch=True,
        claimed_vendor="Microsoft Corporation",
        requested_execution_level="requireAdministrator",
    )


def test_case_round_trips_absent_masquerade_check_as_none():
    case = _sample_case()

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.masquerade_check is None


def test_case_save_writes_json_named_by_timestamp_and_filename(tmp_path):
    from datetime import datetime

    case = _sample_case()

    out_path = case.save(tmp_path, now=datetime(2026, 7, 9, 14, 23, 5))

    assert out_path == tmp_path / f"14-23-05-09-07-2026-sample-exe-{'c' * 32}.json"
    assert out_path.exists()
    on_disk = json.loads(out_path.read_text())
    assert on_disk["identity"]["sha256"] == "a" * 64


def test_case_save_appends_flags_suffix_when_given(tmp_path):
    from datetime import datetime

    case = _sample_case()

    out_path = case.save(tmp_path, now=datetime(2026, 7, 9, 14, 23, 5), flags="ycfdr")

    assert out_path == tmp_path / f"14-23-05-09-07-2026-sample-exe-{'c' * 32}-ycfdr.json"


def test_case_output_basename_appends_flags_suffix_when_given():
    from datetime import datetime

    case = _sample_case()

    basename = case.output_basename(now=datetime(2026, 7, 9, 14, 23, 5), flags="yc")

    assert basename == f"14-23-05-09-07-2026-sample-exe-{'c' * 32}-yc"


def test_case_output_basename_omits_suffix_when_flags_empty():
    from datetime import datetime

    case = _sample_case()

    basename = case.output_basename(now=datetime(2026, 7, 9, 14, 23, 5))

    assert basename == f"14-23-05-09-07-2026-sample-exe-{'c' * 32}"


def test_case_save_sanitizes_dots_so_it_never_looks_like_a_double_extension(tmp_path):
    from datetime import datetime

    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="rb.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    case = Case(identity=identity, static=StaticSection(pe_metadata=pe_metadata))

    out_path = case.save(tmp_path, now=datetime(2026, 7, 9, 14, 23, 5))

    assert out_path == tmp_path / f"14-23-05-09-07-2026-rb-exe-{'c' * 32}.json"
    assert out_path.name.count(".") == 1


def test_case_save_writes_text_report_when_provided(tmp_path):
    from datetime import datetime

    case = _sample_case()

    out_path = case.save(
        tmp_path, now=datetime(2026, 7, 9, 14, 23, 5), text_report="hello report text"
    )

    txt_path = tmp_path / f"14-23-05-09-07-2026-sample-exe-{'c' * 32}.txt"
    assert txt_path.exists()
    assert txt_path.read_text() == "hello report text"
    assert out_path == tmp_path / f"14-23-05-09-07-2026-sample-exe-{'c' * 32}.json"


def test_case_save_does_not_write_text_report_when_omitted(tmp_path):
    from datetime import datetime

    case = _sample_case()

    case.save(tmp_path, now=datetime(2026, 7, 9, 14, 23, 5))

    txt_path = tmp_path / f"14-23-05-09-07-2026-sample-exe-{'c' * 32}.txt"
    assert not txt_path.exists()


def test_case_save_defaults_to_current_time_when_not_given(tmp_path):
    case = _sample_case()

    out_path = case.save(tmp_path)

    assert out_path.name.endswith(f"-sample-exe-{'c' * 32}.json")


def test_case_save_writes_explicit_data_when_given(tmp_path):
    from datetime import datetime

    case = _sample_case()

    out_path = case.save(tmp_path, now=datetime(2026, 7, 9, 14, 23, 5), data={"custom": "payload"})

    on_disk = json.loads(out_path.read_text())
    assert on_disk == {"custom": "payload"}


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


def test_pe_metadata_defaults_machine_name_and_likely_packed_when_omitted():
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp=None,
        sections=[],
        imports={},
        has_digital_signature=False,
    )

    assert pe_metadata.machine_name == ""
    assert pe_metadata.likely_packed is False


def test_case_round_trips_machine_name_and_likely_packed():
    identity = Identity(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe")
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp=None,
        sections=[],
        imports={},
        has_digital_signature=False,
        machine_name="x64 (AMD64)",
        likely_packed=True,
    )
    case = Case(identity=identity, static=StaticSection(pe_metadata=pe_metadata))

    restored = Case.from_dict(case.to_dict())

    assert restored.static.pe_metadata.machine_name == "x64 (AMD64)"
    assert restored.static.pe_metadata.likely_packed is True


def test_case_load_tolerates_old_format_json_missing_machine_name_and_likely_packed(tmp_path):
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

    assert loaded.static.pe_metadata.machine_name == ""
    assert loaded.static.pe_metadata.likely_packed is False


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


def test_static_section_defaults_classification_to_none_when_omitted():
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp=None,
        sections=[],
        imports={},
        has_digital_signature=False,
    )

    static = StaticSection(pe_metadata=pe_metadata)

    assert static.classification is None


def test_case_round_trips_classification():
    identity = Identity(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe")
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        classification={"verdict": "trojan", "risk": "medium", "reasoning": ["example"]},
    )
    case = Case(identity=identity, static=static)

    restored = Case.from_dict(case.to_dict())

    assert restored.static.classification == {
        "verdict": "trojan",
        "risk": "medium",
        "reasoning": ["example"],
    }


def test_case_load_tolerates_json_missing_classification_field(tmp_path):
    data_without_classification = {
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
            "interesting_strings": [],
        },
    }
    case_path = tmp_path / (("a" * 64) + ".json")
    case_path.write_text(json.dumps(data_without_classification))

    loaded = Case.load(case_path)

    assert loaded.static.classification is None


def test_static_section_defaults_die_detections_when_omitted():
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp=None,
        sections=[],
        imports={},
        has_digital_signature=False,
    )

    static = StaticSection(pe_metadata=pe_metadata)

    assert static.die_detections == []


def test_case_round_trips_die_detections():
    identity = Identity(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe")
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        die_detections=[
            {
                "filetype": "PE64",
                "values": [
                    {"type": "Packer", "name": "UPX", "version": "3.96", "string": None},
                ],
            }
        ],
    )
    case = Case(identity=identity, static=static)

    restored = Case.from_dict(case.to_dict())

    assert restored.static.die_detections == [
        {
            "filetype": "PE64",
            "values": [
                {"type": "Packer", "name": "UPX", "version": "3.96", "string": None},
            ],
        }
    ]


def test_case_load_tolerates_json_missing_die_detections_field(tmp_path):
    data_without_die_detections = {
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
            "interesting_strings": [],
            "classification": None,
        },
    }
    case_path = tmp_path / (("a" * 64) + ".json")
    case_path.write_text(json.dumps(data_without_die_detections))

    loaded = Case.load(case_path)

    assert loaded.static.die_detections == []


def test_static_section_defaults_ranked_strings_when_omitted():
    pe_metadata = PEMetadata(
        machine="0x8664",
        compile_timestamp=None,
        sections=[],
        imports={},
        has_digital_signature=False,
    )

    static = StaticSection(pe_metadata=pe_metadata)

    assert static.ranked_strings == []


def test_case_round_trips_ranked_strings():
    identity = Identity(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe")
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        ranked_strings=[
            {"string": "cmd.exe /c whoami", "source": "decoded_strings", "score": 95.5},
        ],
    )
    case = Case(identity=identity, static=static)

    restored = Case.from_dict(case.to_dict())

    assert restored.static.ranked_strings == [
        {"string": "cmd.exe /c whoami", "source": "decoded_strings", "score": 95.5},
    ]


def test_case_load_tolerates_json_missing_ranked_strings_field(tmp_path):
    data_without_ranked_strings = {
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
            "interesting_strings": [],
            "classification": None,
            "die_detections": [],
        },
    }
    case_path = tmp_path / (("a" * 64) + ".json")
    case_path.write_text(json.dumps(data_without_ranked_strings))

    loaded = Case.load(case_path)

    assert loaded.static.ranked_strings == []


def _sample_elf_case() -> Case:
    identity = Identity(
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        imphash=None,
        file_name="sample.elf",
    )
    elf_metadata = ELFMetadata(
        machine="EM_X86_64",
        machine_name="x64 (AMD64)",
        entry_point="0x1050",
        interpreter="/lib64/ld-linux-x86-64.so.2",
        is_pie=True,
        is_stripped=False,
        sections=[
            {"name": ".text", "virtual_size": 4096, "raw_size": 4096, "entropy": 6.1234},
        ],
        needed_libraries=["libc.so.6"],
        dynamic_symbols=["puts"],
    )
    return Case(identity=identity, static=StaticSection(elf_metadata=elf_metadata))


def test_case_round_trips_elf_metadata():
    case = _sample_elf_case()

    data = case.to_dict()
    restored = Case.from_dict(data)

    assert restored.static.pe_metadata is None
    assert restored.static.elf_metadata.machine == "EM_X86_64"
    assert restored.static.elf_metadata.needed_libraries == ["libc.so.6"]
    assert restored.static.elf_metadata.dynamic_symbols == ["puts"]


def test_case_load_tolerates_pe_only_json_missing_elf_metadata(tmp_path):
    old_format_data = {
        "identity": {
            "sha256": "a" * 64,
            "sha1": "b" * 40,
            "md5": "c" * 32,
            "imphash": "d" * 32,
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

    assert loaded.static.pe_metadata.machine == "0x8664"
    assert loaded.static.elf_metadata is None


def test_case_round_trips_pyinstaller_extraction():
    from watson.case import PyInstallerExtractionResult

    case = _sample_case()
    case.static.pyinstaller_extraction = PyInstallerExtractionResult(
        tool="pyinstxtractor-ng",
        success=True,
        output_dir="/tmp/out_extracted",
        entries=[
            {"path": "main.pyc", "size": 128, "pyarmor_protected": True},
            {"path": "python311.dll", "size": 4096, "pyarmor_protected": False},
        ],
    )

    restored = Case.from_dict(case.to_dict())

    assert restored.static.pyinstaller_extraction == case.static.pyinstaller_extraction


def test_case_round_trips_absent_pyinstaller_extraction():
    case = _sample_case()

    restored = Case.from_dict(case.to_dict())

    assert restored.static.pyinstaller_extraction is None


def test_case_round_trips_failed_pyinstaller_extraction():
    from watson.case import PyInstallerExtractionResult

    case = _sample_case()
    case.static.pyinstaller_extraction = PyInstallerExtractionResult(
        tool="pyinstxtractor-ng", success=False, reason="pyinstxtractor-ng not found locally"
    )

    restored = Case.from_dict(case.to_dict())

    assert restored.static.pyinstaller_extraction == case.static.pyinstaller_extraction


def test_case_round_trips_pyarmor_unpacking():
    from watson.case import PyArmorUnpackResult

    case = _sample_case()
    case.static.pyarmor_unpacking = PyArmorUnpackResult(
        tool="pyarmor-1shot",
        success=True,
        output_dir="/tmp/out_pyarmor_unpacked",
        entries=[
            {"path": "main.pyc.1shot.py", "size": 512},
            {"path": "main.pyc.1shot.seq", "size": 256},
        ],
    )

    restored = Case.from_dict(case.to_dict())

    assert restored.static.pyarmor_unpacking == case.static.pyarmor_unpacking


def test_case_round_trips_absent_pyarmor_unpacking():
    case = _sample_case()

    restored = Case.from_dict(case.to_dict())

    assert restored.static.pyarmor_unpacking is None


def test_case_round_trips_failed_pyarmor_unpacking():
    from watson.case import PyArmorUnpackResult

    case = _sample_case()
    case.static.pyarmor_unpacking = PyArmorUnpackResult(
        tool="pyarmor-1shot", success=False, reason="pyarmor-1shot produced no output files"
    )

    restored = Case.from_dict(case.to_dict())

    assert restored.static.pyarmor_unpacking == case.static.pyarmor_unpacking


def test_static_section_go_build_info_defaults_to_empty_dict():
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(pe_metadata=pe_metadata)

    assert static.go_build_info == {}


def test_case_round_trips_go_build_info():
    identity = Identity(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe")
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        go_build_info={
            "go_version": "go1.24.4",
            "module_path": "example",
            "module_version": "(devel)",
            "dependencies": [],
            "packages": {"main": ["main.main"]},
        },
    )
    case = Case(identity=identity, static=static)

    restored = Case.from_dict(case.to_dict())

    assert restored.static.go_build_info == static.go_build_info
