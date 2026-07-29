from watson.case import Case, ELFMetadata, Identity, PEMetadata, StaticSection
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


def test_build_text_report_renders_elf_metadata_section():
    case = _sample_elf_case()

    report = build_text_report(case)

    assert "sample.elf" in report
    assert "ELF Metadata" in report
    assert "Machine: EM_X86_64 (x64 (AMD64))" in report
    assert "Entry Point: 0x1050" in report
    assert "Interpreter: /lib64/ld-linux-x86-64.so.2" in report
    assert "PIE: True" in report
    assert "Stripped: False" in report
    assert ".text" in report
    assert "Needed Libraries" in report
    assert "  libc.so.6" in report
    assert "Dynamic Symbols" in report
    assert "  puts" in report
    assert "PE Metadata" not in report
    assert "Imports" not in report


def test_build_json_report_round_trips_elf_case_data():
    case = _sample_elf_case()

    report = build_json_report(case)

    assert report["static"]["elf_metadata"]["machine"] == "EM_X86_64"
    assert report["static"]["pe_metadata"] is None


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


def test_build_text_report_shows_machine_name_and_packed_flag():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
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

    report = build_text_report(case)

    assert "x64 (AMD64)" in report
    assert "Likely Packed: True" in report


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


def test_build_text_report_shows_summary_section():
    case = _sample_case_with_yara_and_tools()

    report = build_text_report(case)

    assert "Summary" in report
    assert "YARA: 1 rule(s) matched" in report
    assert "  YARA rules: watson_test_fixture_string" in report


def test_summary_section_appears_before_tools_section():
    case = _sample_case_with_yara_and_tools()

    report = build_text_report(case)

    assert report.index("Summary") < report.index("Tools")


def test_build_json_report_includes_summary():
    case = _sample_case_with_yara_and_tools()

    report = build_json_report(case)

    assert report["summary"]["yara_matches"] == {
        "count": 1,
        "rules": ["watson_test_fixture_string"],
    }


def test_build_json_report_summary_counts_capabilities_by_tactic():
    case = _sample_case_with_capabilities()

    report = build_json_report(case)

    assert report["summary"]["capabilities"] == {"count": 1, "tactics": {"Ungrouped": 1}}


def test_build_json_report_summary_counts_strings_by_reason():
    case = _sample_case_with_interesting_strings()

    report = build_json_report(case)

    assert report["summary"]["interesting_strings"] == {"count": 1, "by_reason": {"url": 1}}


def test_build_text_report_shows_tools_and_yara_matches():
    case = _sample_case_with_yara_and_tools()

    report = build_text_report(case)

    assert "yara: available" in report
    assert "watson_test_fixture_string" in report


def test_build_text_report_renders_unpacking_section_on_success():
    from watson.case import UnpackingResult

    case = _sample_case()
    case.static.unpacking = UnpackingResult(
        tool="upx", success=True, output_path="/out/sample_unpacked.exe", unpacked_sha256="f" * 64
    )

    text_report = build_text_report(case)

    assert "Unpacking" in text_report
    assert "tool: upx" in text_report
    assert "result: succeeded" in text_report
    assert "output: /out/sample_unpacked.exe" in text_report
    assert f"unpacked sha256: {'f' * 64}" in text_report


def test_build_text_report_renders_unpacking_section_on_failure():
    from watson.case import UnpackingResult

    case = _sample_case()
    case.static.unpacking = UnpackingResult(tool="upx", success=False, reason="upx exited with code 2")

    text_report = build_text_report(case)

    assert "Unpacking" in text_report
    assert "result: failed" in text_report
    assert "reason: upx exited with code 2" in text_report


def test_build_text_report_omits_unpacking_section_when_absent():
    case = _sample_case()

    text_report = build_text_report(case)

    assert "Unpacking" not in text_report


def _sample_case_with_yara_match_detail() -> Case:
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        yara_matches=[
            {
                "rule": "suspicious_string",
                "tags": ["malware"],
                "matches": [
                    {"identifier": "$a", "offset": 4096, "matched_data": "evil.example.com"},
                ],
            }
        ],
        tools={"yara": {"available": True, "reason": None}},
    )
    return Case(identity=identity, static=static)


def test_build_text_report_shows_yara_match_detail_when_verbose():
    case = _sample_case_with_yara_match_detail()

    report = build_text_report(case, verbose=True)

    assert "malware" in report
    assert "0x1000" in report or "4096" in report
    assert "evil.example.com" in report


def test_build_text_report_hides_yara_match_detail_by_default():
    case = _sample_case_with_yara_match_detail()

    report = build_text_report(case)

    assert "malware" in report
    assert "suspicious_string" in report
    assert "evil.example.com" not in report


def test_build_text_report_renders_suppressed_match_marker_without_crashing():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        yara_matches=[
            {
                "rule": "noisy_rule",
                "tags": [],
                "matches": [
                    {"identifier": "$r", "offset": 4096, "matched_data": "AAAA"},
                    {"identifier": "$r", "offset": None, "matched_data": "...5 more instance(s) suppressed"},
                ],
            }
        ],
        tools={"yara": {"available": True, "reason": None}},
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case, verbose=True)

    assert "5 more instance(s) suppressed" in report


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


def test_build_text_report_shows_capability_attack_and_mbc_mapping():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[
            {
                "rule": "query registry",
                "namespace": "host-interaction/registry",
                "attack": ["Discovery::Query Registry [T1012]"],
                "mbc": ["Collection::Data from Local System [C0004]"],
            }
        ],
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert "Discovery::Query Registry [T1012]" in report
    assert "Collection::Data from Local System [C0004]" in report


def test_build_text_report_shows_capability_attack_and_mbc_as_structured_dicts():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[
            {
                "rule": "parse PE header",
                "namespace": "load-code/pe",
                "attack": [
                    {
                        "parts": ["Execution", "Shared Modules"],
                        "tactic": "Execution",
                        "technique": "Shared Modules",
                        "subtechnique": "",
                        "id": "T1129",
                    }
                ],
                "mbc": [
                    {
                        "parts": ["Memory", "Allocate Memory"],
                        "objective": "Memory",
                        "behavior": "Allocate Memory",
                        "method": "",
                        "id": "C0007",
                    }
                ],
            }
        ],
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert "Execution::Shared Modules [T1129]" in report
    assert "Memory::Allocate Memory [C0007]" in report
    assert "{'parts'" not in report


def test_build_text_report_groups_capabilities_by_attack_tactic():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[
            {
                "rule": "query registry",
                "namespace": "host-interaction/registry",
                "attack": ["Discovery::Query Registry [T1012]"],
                "mbc": [],
            },
            {
                "rule": "connect to socket",
                "namespace": "communication/socket",
                "attack": ["Command and Control::Non-Standard Port [T1571]"],
                "mbc": [],
            },
        ],
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert "\nDiscovery\n" in report
    assert "\nCommand and Control\n" in report
    assert "query registry" in report
    assert "connect to socket" in report


def test_build_text_report_shows_multi_tactic_capability_under_each_tactic():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[
            {
                "rule": "inject into remote process",
                "namespace": "host-interaction/process/inject",
                "attack": [
                    "Defense Evasion::Process Injection [T1055]",
                    "Privilege Escalation::Process Injection [T1055]",
                ],
                "mbc": [],
            }
        ],
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert report.count("inject into remote process") == 2
    assert "\nDefense Evasion\n" in report
    assert "\nPrivilege Escalation\n" in report


def _sample_case_with_capability_evidence() -> Case:
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[
            {
                "rule": "delay execution",
                "namespace": "anti-analysis/anti-debugging",
                "attack": [],
                "mbc": [],
                "evidence": [
                    {"feature": "api", "value": "Sleep", "addresses": [1342177894], "more_addresses": 0},
                    {"feature": "api", "value": "WaitForSingleObject", "addresses": [], "more_addresses": 0},
                ],
            }
        ],
    )
    return Case(identity=identity, static=static)


def test_build_text_report_shows_capa_evidence_when_verbose():
    case = _sample_case_with_capability_evidence()

    report = build_text_report(case, verbose=True)

    assert f"api: Sleep @ {hex(1342177894)}" in report
    assert "api: WaitForSingleObject" in report


def test_build_text_report_hides_capa_evidence_by_default():
    case = _sample_case_with_capability_evidence()

    report = build_text_report(case)

    assert "delay execution" in report
    assert "api: Sleep" not in report


def test_build_text_report_shows_more_addresses_suffix():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[
            {
                "rule": "delay execution",
                "namespace": "anti-analysis/anti-debugging",
                "attack": [],
                "mbc": [],
                "evidence": [
                    {"feature": "api", "value": "Sleep", "addresses": [1, 2], "more_addresses": 3},
                ],
            }
        ],
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case, verbose=True)

    assert "(+3 more)" in report


def test_build_text_report_puts_ungrouped_tactic_bucket_last():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        capabilities=[
            {"rule": "no mapping capability", "namespace": "misc", "attack": [], "mbc": []},
            {
                "rule": "query registry",
                "namespace": "host-interaction/registry",
                "attack": ["Discovery::Query Registry [T1012]"],
                "mbc": [],
            },
        ],
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert report.index("Discovery") < report.index("Ungrouped")


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


def _sample_case_with_classification() -> Case:
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        classification={
            "verdict": "ransomware",
            "risk": "high",
            "reasoning": [
                "capa detected Cryptography and Impact behavior (MBC), consistent with ransomware"
            ],
        },
    )
    return Case(identity=identity, static=static)


def test_build_text_report_shows_classification_section():
    case = _sample_case_with_classification()

    report = build_text_report(case)

    assert "Classification" in report
    assert "Verdict: ransomware" in report
    assert "Risk: high" in report
    assert (
        "  - capa detected Cryptography and Impact behavior (MBC), consistent with ransomware"
        in report
    )


def test_build_text_report_shows_detection_line_when_present():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        classification={
            "verdict": "ransomware",
            "risk": "high",
            "reasoning": ["some reason"],
            "detection": "Ransomware:Win64/CryptoImpact.capa",
        },
    )
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert "Detection: Ransomware:Win64/CryptoImpact.capa" in report
    assert report.index("Detection:") < report.index("Verdict:")


def test_build_text_report_omits_detection_line_when_absent():
    case = _sample_case_with_classification()

    report = build_text_report(case)

    assert "Detection:" not in report


def test_classification_section_appears_before_sample_section():
    case = _sample_case_with_classification()

    report = build_text_report(case)

    assert report.index("Classification") < report.index("Sample")


def test_build_text_report_shows_not_computed_when_classification_missing():
    case = _sample_case()

    report = build_text_report(case)

    assert "Classification" in report
    assert "not computed" in report


def _sample_case_with_interesting_strings() -> Case:
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
        interesting_strings=[
            {"string": "http://evil.example.com/payload.bin", "source": "decoded_strings", "reason": "url"}
        ],
    )
    return Case(identity=identity, static=static)


def test_build_text_report_groups_interesting_strings_by_reason():
    case = _sample_case_with_interesting_strings()

    report = build_text_report(case)

    assert "\nurl\n" in report
    assert "  http://evil.example.com/payload.bin (decoded_strings)" in report


def test_build_text_report_shows_no_interesting_strings_when_empty():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(pe_metadata=pe_metadata)
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert "Interesting Strings" in report
    assert "none" in report


def _sample_case_with_die_detections() -> Case:
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        die_detections=[
            {
                "filetype": "PE64",
                "values": [
                    {"type": "Compiler", "name": "Microsoft Visual C/C++", "version": "19.29", "string": None},
                    {"type": "Packer", "name": "UPX", "version": "3.96", "string": None},
                ],
            }
        ],
    )
    return Case(identity=identity, static=static)


def test_build_text_report_shows_die_detections():
    case = _sample_case_with_die_detections()

    report = build_text_report(case)

    assert "Detect It Easy" in report
    assert "File Type: PE64" in report
    assert "Compiler: Microsoft Visual C/C++ (19.29)" in report
    assert "Packer: UPX (3.96)" in report


def test_die_section_appears_after_pe_metadata_and_before_sections():
    case = _sample_case_with_die_detections()

    report = build_text_report(case)

    assert report.index("PE Metadata") < report.index("Detect It Easy") < report.index("Sections")


def test_build_text_report_shows_no_die_detections_when_empty():
    case = _sample_case()

    report = build_text_report(case)

    assert "Detect It Easy" in report


def _sample_case_with_ranked_strings() -> Case:
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash="d" * 32, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(
        pe_metadata=pe_metadata,
        ranked_strings=[
            {"string": "cmd.exe /c whoami", "source": "decoded_strings", "score": 95.5},
        ],
    )
    return Case(identity=identity, static=static)


def test_build_text_report_shows_ranked_strings():
    case = _sample_case_with_ranked_strings()

    report = build_text_report(case)

    assert "Ranked Strings" in report
    assert "95.50  cmd.exe /c whoami (decoded_strings)" in report


def test_build_text_report_shows_no_ranked_strings_when_empty():
    identity = Identity(
        sha256="a" * 64, sha1="b" * 40, md5="c" * 32, imphash=None, file_name="sample.exe"
    )
    pe_metadata = PEMetadata(
        machine="0x8664", compile_timestamp=None, sections=[], imports={}, has_digital_signature=False
    )
    static = StaticSection(pe_metadata=pe_metadata)
    case = Case(identity=identity, static=static)

    report = build_text_report(case)

    assert "Ranked Strings" in report
    assert report.rstrip().endswith("none")
