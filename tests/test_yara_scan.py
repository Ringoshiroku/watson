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
