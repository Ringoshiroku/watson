import json
from pathlib import Path

from watson.cli import main


def test_analyze_writes_case_and_prints_report(compiled_pe, tmp_path, capsys):
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "Watson Static Analysis Report" in captured.out
    assert compiled_pe.name in captured.out

    case_files = list(out_dir.glob("*.json"))
    assert len(case_files) == 1
    case_data = json.loads(case_files[0].read_text())
    assert case_data["identity"]["file_name"] == compiled_pe.name


def test_analyze_rejects_non_pe_file(tmp_path, capsys):
    bad_file = tmp_path / "not_a_pe.bin"
    bad_file.write_bytes(b"not a pe file at all")

    exit_code = main(["analyze", str(bad_file)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "not a valid PE file" in captured.err


def test_analyze_rejects_missing_file(tmp_path, capsys):
    missing = tmp_path / "does_not_exist.exe"

    exit_code = main(["analyze", str(missing)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "is not a file" in captured.err


def test_analyze_with_rules_dir_reports_yara_match(compiled_pe, tmp_path, capsys):
    out_dir = tmp_path / "cases"
    rules_dir = Path(__file__).parent / "fixtures" / "rules"

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--rules-dir", str(rules_dir)]
    )

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "watson_test_fixture_string" in captured.out
    assert "yara: available" in captured.out

    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["yara"]["available"] is True
    assert len(case_data["static"]["yara_matches"]) == 1


def test_analyze_without_rules_dir_reports_yara_unavailable(compiled_pe, tmp_path, capsys):
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "yara: unavailable" in captured.out

    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["yara"]["available"] is False
    assert case_data["static"]["yara_matches"] == []


def test_analyze_with_malformed_yara_rule_degrades_gracefully(compiled_pe, tmp_path, capsys):
    out_dir = tmp_path / "cases"
    bad_rules_dir = tmp_path / "bad_rules"
    bad_rules_dir.mkdir()
    (bad_rules_dir / "bad.yar").write_text(
        "rule broken { condition: this_is_not_a_real_identifier }"
    )

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--rules-dir", str(bad_rules_dir)]
    )

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "yara: unavailable" in captured.out

    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["yara"]["available"] is False
    assert "yara scan failed" in case_data["static"]["tools"]["yara"]["reason"]
