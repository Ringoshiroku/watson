import json
import shutil
from pathlib import Path

import pytest

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


def test_analyze_without_rules_dir_reports_yara_unavailable(compiled_pe, tmp_path, capsys, monkeypatch):
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "yara-cache")

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


requires_capa = pytest.mark.skipif(shutil.which("capa") is None, reason="capa not installed")


@requires_capa
def test_analyze_with_capa_rules_dir_reports_capability(compiled_pe, tmp_path, capsys):
    out_dir = tmp_path / "cases"
    capa_rules_dir = Path(__file__).parent / "fixtures" / "capa_rules"

    exit_code = main(
        [
            "analyze",
            str(compiled_pe),
            "--out",
            str(out_dir),
            "--capa-rules-dir",
            str(capa_rules_dir),
        ]
    )

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "watson test fixture string" in captured.out
    assert "capa: available" in captured.out

    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["capa"]["available"] is True
    assert len(case_data["static"]["capabilities"]) == 1


def test_analyze_without_capa_rules_dir_reports_capa_unavailable(compiled_pe, tmp_path, capsys, monkeypatch):
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "capa-cache")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "capa: unavailable" in captured.out

    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["capa"]["available"] is False
    assert case_data["static"]["capabilities"] == []


requires_floss = pytest.mark.skipif(shutil.which("floss") is None, reason="floss not installed")


@requires_floss
def test_analyze_with_floss_flag_writes_raw_sidecar_and_reports_available(
    compiled_pe, tmp_path, capsys
):
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir), "--floss"])

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "floss: available" in captured.out
    assert "Interesting Strings" in captured.out

    case_files = [p for p in out_dir.glob("*.json") if not p.name.endswith("_floss.json")]
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["floss"]["available"] is True
    assert "interesting_strings" in case_data["static"]

    sha256 = case_data["identity"]["sha256"]
    sidecar_path = out_dir / f"{sha256}_floss.json"
    assert sidecar_path.exists()
    sidecar_data = json.loads(sidecar_path.read_text())
    static_strings = [entry["string"] for entry in sidecar_data["strings"]["static_strings"]]
    assert "hello from watson test fixture" in static_strings


@requires_capa
def test_analyze_with_capa_sigs_dir_passes_signatures_through(compiled_pe, tmp_path, capsys):
    out_dir = tmp_path / "cases"
    capa_rules_dir = Path(__file__).parent / "fixtures" / "capa_rules"
    capa_sigs_dir = tmp_path / "sigs"
    capa_sigs_dir.mkdir()

    exit_code = main(
        [
            "analyze",
            str(compiled_pe),
            "--out",
            str(out_dir),
            "--capa-rules-dir",
            str(capa_rules_dir),
            "--capa-sigs-dir",
            str(capa_sigs_dir),
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "capa: available" in captured.out


def test_analyze_prompts_to_fetch_yara_rules_when_missing_and_interactive(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "yara-cache")
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "yara: unavailable" in captured.out
    assert "git clone" in captured.out


def test_analyze_reuses_already_fetched_yara_rules_without_prompting(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    out_dir = tmp_path / "cases"
    cache_dir = tmp_path / "yara-cache"
    cache_dir.mkdir()
    fixture_rule = (Path(__file__).parent / "fixtures" / "rules" / "watson_test_fixture.yar").read_text()
    (cache_dir / "fixture.yar").write_text(fixture_rule)
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", cache_dir)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when the cache dir is already populated")

    monkeypatch.setattr("builtins.input", fail_if_called)

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "yara: available" in captured.out
    assert "watson_test_fixture_string" in captured.out


@requires_capa
def test_analyze_reuses_already_fetched_capa_rules_without_prompting(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", Path(__file__).parent / "fixtures" / "capa_rules")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when the cache dir is already populated")

    monkeypatch.setattr("builtins.input", fail_if_called)

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "capa: available" in captured.out
    assert "watson test fixture string" in captured.out


@requires_floss
def test_analyze_prompts_to_run_floss_when_interactive_and_confirmed(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "floss: available" in captured.out


def test_analyze_skips_floss_when_interactive_and_declined(compiled_pe, tmp_path, capsys, monkeypatch):
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "floss: unavailable" in captured.out


def test_analyze_with_explicit_floss_flag_never_prompts(compiled_pe, tmp_path, capsys, monkeypatch):
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when --floss is explicit")

    monkeypatch.setattr("builtins.input", fail_if_called)

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir), "--floss"])

    assert exit_code == 0


def test_analyze_without_floss_flag_reports_floss_unavailable(compiled_pe, tmp_path, capsys):
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "floss: unavailable" in captured.out

    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["floss"]["available"] is False
    assert case_data["static"]["interesting_strings"] == []
    assert not list(out_dir.glob("*_floss.json"))
