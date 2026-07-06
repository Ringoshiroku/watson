from pathlib import Path

from watson.yara_scan import scan_file

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
