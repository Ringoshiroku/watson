from pathlib import Path

import pytest

from watson.yara_scan import YaraScanError, scan_file

RULES_DIR = Path(__file__).parent / "fixtures" / "rules"


def test_scan_file_finds_match_in_compiled_pe(compiled_pe):
    matches = scan_file(compiled_pe, RULES_DIR)

    assert len(matches) == 1
    assert matches[0]["rule"] == "watson_test_fixture_string"
    assert matches[0]["matches"][0]["identifier"] == "$a"
    assert matches[0]["matches"][0]["matched_data"] == "hello from watson test fixture"


def test_scan_file_returns_empty_list_when_rules_dir_has_no_rules(tmp_path, compiled_pe):
    empty_rules_dir = tmp_path / "empty_rules"
    empty_rules_dir.mkdir()

    matches = scan_file(compiled_pe, empty_rules_dir)

    assert matches == []


def test_scan_file_raises_yara_scan_error_for_malformed_rule(tmp_path, compiled_pe):
    bad_rules_dir = tmp_path / "bad_rules"
    bad_rules_dir.mkdir()
    (bad_rules_dir / "bad.yar").write_text(
        "rule broken { condition: this_is_not_a_real_identifier }"
    )

    with pytest.raises(YaraScanError):
        scan_file(compiled_pe, bad_rules_dir)


def test_scan_file_skips_one_malformed_rule_and_still_matches_the_rest(tmp_path, compiled_pe):
    mixed_rules_dir = tmp_path / "mixed_rules"
    mixed_rules_dir.mkdir()
    (mixed_rules_dir / "bad.yar").write_text(
        "rule broken { condition: this_is_not_a_real_identifier }"
    )
    (mixed_rules_dir / "good.yar").write_text(_FIXTURE_RULE)

    matches = scan_file(compiled_pe, mixed_rules_dir)

    assert len(matches) == 1
    assert matches[0]["rule"] == "watson_test_fixture_string"


_FIXTURE_RULE = (
    "rule watson_test_fixture_string\n"
    "{\n"
    "    strings:\n"
    '        $a = "hello from watson test fixture"\n'
    "    condition:\n"
    "        $a\n"
    "}\n"
)


def test_scan_file_matches_all_good_rules_after_skipping_one_malformed_rule(tmp_path, compiled_pe):
    mixed_rules_dir = tmp_path / "mixed_rules_multi"
    mixed_rules_dir.mkdir()
    (mixed_rules_dir / "bad.yar").write_text(
        "rule broken { condition: this_is_not_a_real_identifier }"
    )
    (mixed_rules_dir / "good_one.yar").write_text(_FIXTURE_RULE)
    (mixed_rules_dir / "good_two.yar").write_text(
        "rule watson_test_fixture_second\n"
        "{\n"
        "    strings:\n"
        '        $a = "hello from watson test fixture"\n'
        "    condition:\n"
        "        $a\n"
        "}\n"
    )

    matches = scan_file(compiled_pe, mixed_rules_dir)

    matched_rule_names = {match["rule"] for match in matches}
    assert matched_rule_names == {"watson_test_fixture_string", "watson_test_fixture_second"}


def test_scan_file_finds_rules_in_nested_subdirectories(tmp_path, compiled_pe):
    rules_dir = tmp_path / "community_rules"
    nested = rules_dir / "malware" / "trojans"
    nested.mkdir(parents=True)
    (nested / "fixture.yar").write_text(_FIXTURE_RULE)

    matches = scan_file(compiled_pe, rules_dir)

    assert len(matches) == 1
    assert matches[0]["rule"] == "watson_test_fixture_string"


def test_scan_file_finds_rules_with_yara_extension(tmp_path, compiled_pe):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "fixture.yara").write_text(_FIXTURE_RULE)

    matches = scan_file(compiled_pe, rules_dir)

    assert len(matches) == 1
    assert matches[0]["rule"] == "watson_test_fixture_string"
