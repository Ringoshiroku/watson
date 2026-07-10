import json
import shutil
from pathlib import Path

import pytest

from watson.cli import build_case, main


def _isolate_rule_caches(monkeypatch, tmp_path):
    # real ~/.watson/rules/* may already be populated on this machine from
    # prior interactive fetches; point the caches at guaranteed-empty dirs so
    # tests that don't pass --rules-dir/--capa-rules-dir stay fast and
    # deterministic instead of silently running a real scan
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "unused-yara-cache")
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")


def test_analyze_writes_case_and_prints_report(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
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


def test_analyze_with_rules_dir_reports_yara_match(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
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


def test_analyze_saved_case_json_includes_summary(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    rules_dir = Path(__file__).parent / "fixtures" / "rules"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(rules_dir)])

    assert exit_code == 0
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert "summary" in case_data
    assert case_data["summary"]["yara_matches"]["count"] == 1


def test_analyze_with_short_flags_reports_yara_match(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    rules_dir = Path(__file__).parent / "fixtures" / "rules"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(rules_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "watson_test_fixture_string" in captured.out


def test_analyze_without_rules_dir_reports_yara_unavailable(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "yara: unavailable" in captured.out

    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["yara"]["available"] is False
    assert case_data["static"]["yara_matches"] == []


def test_analyze_with_malformed_yara_rule_degrades_gracefully(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
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
def test_analyze_with_capa_rules_dir_reports_capability(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
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
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

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
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
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

    sidecar_candidates = list(out_dir.glob("*_floss.json"))
    assert len(sidecar_candidates) == 1
    sidecar_path = sidecar_candidates[0]
    # same base name as the case file, not the sha256, so the filename itself
    # says what was scanned
    assert sidecar_path.name == case_files[0].name.replace(".json", "_floss.json")
    sidecar_data = json.loads(sidecar_path.read_text())
    static_strings = [entry["string"] for entry in sidecar_data["strings"]["static_strings"]]
    assert "hello from watson test fixture" in static_strings


def test_analyze_case_filename_uses_timestamp_and_binary_name_not_hash(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    case_files = list(out_dir.glob("*.json"))
    assert len(case_files) == 1
    name = case_files[0].name
    case_data = json.loads(case_files[0].read_text())
    md5 = case_data["identity"]["md5"]
    # hh-mm-ss-DD-MM-YYYY-<sanitized name>-<md5>.json, dots replaced with
    # dashes so it never reads like a double extension
    assert name.count(".") == 1
    assert name.endswith(f"-{compiled_pe.stem}-{compiled_pe.suffix.lstrip('.')}-{md5}.json")
    sha256_only_name = out_dir / f"{case_data['identity']['sha256']}.json"
    assert not sha256_only_name.exists()


@requires_capa
def test_analyze_with_capa_sigs_dir_passes_signatures_through(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
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


def test_analyze_prompts_which_analyses_to_run_when_nothing_specified(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    # answer "n" to the analysis-selection prompt: nothing selected, nothing
    # else should ever prompt after that
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "which analyses do you want to run?" in captured.out
    assert "yara: unavailable" in captured.out
    assert "capa: unavailable" in captured.out
    assert "floss: unavailable" in captured.out


def test_analyze_selecting_yara_when_missing_reports_unavailable_without_fetch_prompt(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    out_dir = tmp_path / "cases"
    cache_dir = tmp_path / "yara-cache"
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", cache_dir)
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    # only ONE answer is needed now: select yara at the analysis prompt.
    # analyze never offers to fetch anymore, so there is no second prompt to answer.
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "yara: unavailable" in captured.out
    assert "capa: unavailable" in captured.out
    assert "floss: unavailable" in captured.out
    assert not cache_dir.exists()


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
def test_analyze_prompts_which_analyses_and_runs_floss_when_selected(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "f")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "floss: available" in captured.out
    assert "yara: unavailable" in captured.out
    assert "capa: unavailable" in captured.out


def test_analyze_skips_everything_when_analysis_prompt_declined(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "floss: unavailable" in captured.out


def test_analyze_with_explicit_floss_flag_never_prompts(compiled_pe, tmp_path, capsys, monkeypatch):
    out_dir = tmp_path / "cases"
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when --floss is explicit")

    monkeypatch.setattr("builtins.input", fail_if_called)

    exit_code = main(
        [
            "analyze",
            str(compiled_pe),
            "--out",
            str(out_dir),
            "--rules-dir",
            str(empty_dir),
            "--capa-rules-dir",
            str(empty_dir),
            "--capa-sigs-dir",
            str(empty_dir),
            "--floss",
            "--diec",
        ]
    )

    assert exit_code == 0


def test_analyze_without_floss_flag_reports_floss_unavailable(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
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


def test_analyze_prompts_for_custom_out_dir_when_not_given(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    custom_dir = tmp_path / "my-custom-cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    # first answer: yes, use a custom dir; second: the path; third: decline
    # the analysis-selection prompt so the run stays fast
    answers = iter(["y", str(custom_dir), "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    exit_code = main(["analyze", str(compiled_pe)])

    assert exit_code == 0
    assert list(custom_dir.glob("*.json"))


def test_analyze_defaults_to_cases_dir_when_out_prompt_declined(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    answers = iter(["n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    exit_code = main(["analyze", str(compiled_pe)])

    assert exit_code == 0
    assert list((tmp_path / "cases").glob("*.json"))


def test_analyze_with_explicit_out_flag_never_prompts_for_output_dir(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    answers = iter(["n"])  # only the analysis-selection prompt should fire
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    assert list(out_dir.glob("*.json"))


def test_analyze_shows_scan_progress_lines(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    rules_dir = Path(__file__).parent / "fixtures" / "rules"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(rules_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "running YARA scan..." in captured.err
    assert "done: YARA scan" in captured.err


def test_analyze_verbose_flag_shows_yara_match_detail(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    rules_dir = Path(__file__).parent / "fixtures" / "rules"

    exit_code = main(
        ["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(rules_dir), "-v"]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "hello from watson test fixture" in captured.out


def test_analyze_without_verbose_hides_yara_match_detail(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    rules_dir = Path(__file__).parent / "fixtures" / "rules"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(rules_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "watson_test_fixture_string" in captured.out
    assert "hello from watson test fixture" not in captured.out


def test_analyze_includes_classification_in_report_and_saved_case(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    rules_dir = Path(__file__).parent / "fixtures" / "rules"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(rules_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Classification" in captured.out
    assert "Verdict:" in captured.out

    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["classification"] is not None
    assert "verdict" in case_data["static"]["classification"]


def test_analyze_classification_is_unclassified_when_nothing_matches(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    empty_rules_dir = tmp_path / "empty-rules"
    empty_rules_dir.mkdir()

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(empty_rules_dir)])

    assert exit_code == 0
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["classification"]["verdict"] == "unclassified"


def test_analyze_without_diec_flag_reports_diec_not_requested(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    rules_dir = Path(__file__).parent / "fixtures" / "rules"
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(rules_dir)])

    assert exit_code == 0
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["diec"]["reason"] == "diec not requested (use --diec)"
    assert case_data["static"]["die_detections"] == []


def test_analyze_diec_unavailable_reason_mentions_apt_on_linux(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    original_which = shutil.which
    monkeypatch.setattr(
        "watson.tool_discovery.shutil.which",
        lambda name: None if name == "diec" else original_which(name),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Linux")
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-d"])

    assert exit_code == 0
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert "apt install detect-it-easy" in case_data["static"]["tools"]["diec"]["reason"]
    assert case_data["static"]["die_detections"] == []


def test_analyze_diec_unavailable_reason_mentions_chocolatey_on_windows(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    original_which = shutil.which
    monkeypatch.setattr(
        "watson.tool_discovery.shutil.which",
        lambda name: None if name == "diec" else original_which(name),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Windows")
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-d"])

    assert exit_code == 0
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert "choco install die" in case_data["static"]["tools"]["diec"]["reason"]


def test_analyze_diec_attempts_windows_zip_fetch_when_missing_on_windows(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    original_which = shutil.which
    monkeypatch.setattr(
        "watson.tool_discovery.shutil.which",
        lambda name: None if name == "diec" else original_which(name),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Windows")
    monkeypatch.setattr("watson.cli.platform.machine", lambda: "AMD64")

    calls = []

    def fake_fetch(name, binary_relpath, cache_dir, archive_url, offline=False):
        calls.append((name, binary_relpath, str(cache_dir), archive_url, offline))
        from watson.tool_discovery import ToolStatus

        return ToolStatus(name=name, available=False, path=None, reason="download declined")

    monkeypatch.setattr("watson.cli.find_or_fetch_zip_binary", fake_fetch)
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-d"])

    assert exit_code == 0
    assert len(calls) == 1
    name, binary_relpath, cache_dir, archive_url, offline = calls[0]
    assert binary_relpath == "die/diec.exe"
    assert archive_url == (
        "https://github.com/horsicq/DIE-engine/releases/download/3.21/die_win64_portable_3.21_x64.zip"
    )
    assert offline is True
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert "choco install die" in case_data["static"]["tools"]["diec"]["reason"]


def test_analyze_diec_passes_resolved_path_to_scan_file(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    fake_diec = tmp_path / "fake_diec"
    fake_diec.write_text('#!/bin/sh\necho \'{"detects": []}\'\n')
    fake_diec.chmod(0o755)

    original_which = shutil.which
    monkeypatch.setattr(
        "watson.tool_discovery.shutil.which",
        lambda name: str(fake_diec) if name == "diec" else original_which(name),
    )
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-d"])

    assert exit_code == 0
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["diec"]["available"] is True
    assert case_data["static"]["die_detections"] == []


def test_analyze_all_shorthand_at_prompt_forces_verbose_output(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    out_dir = tmp_path / "cases"
    cache_dir = tmp_path / "yara-cache"
    cache_dir.mkdir()
    fixture_rule = (Path(__file__).parent / "fixtures" / "rules" / "watson_test_fixture.yar").read_text()
    (cache_dir / "fixture.yar").write_text(fixture_rule)
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", cache_dir)
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    # -v was never passed, but picking "a" should force the same detail on
    assert "hello from watson test fixture" in captured.out


def test_analyze_selecting_all_capabilities_individually_does_not_force_verbose(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    out_dir = tmp_path / "cases"
    cache_dir = tmp_path / "yara-cache"
    cache_dir.mkdir()
    fixture_rule = (Path(__file__).parent / "fixtures" / "rules" / "watson_test_fixture.yar").read_text()
    (cache_dir / "fixture.yar").write_text(fixture_rule)
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", cache_dir)
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "ycfd")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "watson_test_fixture_string" in captured.out
    assert "hello from watson test fixture" not in captured.out


def test_analyze_explicit_flags_never_force_verbose(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    rules_dir = Path(__file__).parent / "fixtures" / "rules"

    exit_code = main(
        ["analyze", str(compiled_pe), "-o", str(out_dir), "-y", str(rules_dir), "-f", "-d"]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "watson_test_fixture_string" in captured.out
    assert "hello from watson test fixture" not in captured.out


def test_setup_reports_summary_for_all_four_tools(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "unused-yara-cache")
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")

    exit_code = main(["setup"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Summary" in captured.out
    assert "yara:" in captured.out
    assert "capa:" in captured.out
    assert "floss:" in captured.out
    assert "diec:" in captured.out
    assert "watson analyze" in captured.out


def test_setup_non_interactive_fetches_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "unused-yara-cache")
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("setup should not prompt when not interactive")

    monkeypatch.setattr("builtins.input", fail_if_called)

    exit_code = main(["setup"])

    assert exit_code == 0
    assert not (tmp_path / "unused-yara-cache").exists()


def test_setup_reuses_already_populated_yara_cache_without_prompting(tmp_path, capsys, monkeypatch):
    cache_dir = tmp_path / "yara-cache"
    cache_dir.mkdir()
    (cache_dir / "fixture.yar").write_text("rule fixture { condition: true }")
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", cache_dir)
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")

    exit_code = main(["setup"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "yara: available" in captured.out


def test_build_case_respects_explicit_run_yara_and_run_capa_false(compiled_pe, monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when run_yara/run_capa/run_floss/run_die are all explicit")

    monkeypatch.setattr("builtins.input", fail_if_called)

    case, floss_raw, forced_verbose = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False
    )

    assert case.static.tools["yara"] == {
        "available": False,
        "reason": "not requested (skipped at the analysis-selection prompt)",
    }
    assert case.static.tools["capa"] == {
        "available": False,
        "reason": "not requested (skipped at the analysis-selection prompt)",
    }
    assert forced_verbose is False


def test_build_case_explicit_run_yara_run_capa_still_prompts_for_floss_and_die_once_each(
    compiled_pe, monkeypatch
):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    answers = iter(["n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    case, floss_raw, forced_verbose = build_case(compiled_pe, run_yara=False, run_capa=False)

    assert case.static.tools["floss"]["reason"] == "floss not requested (use --floss)"
    assert case.static.tools["diec"]["reason"] == "diec not requested (use --diec)"
