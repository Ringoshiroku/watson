import json
import shutil
import sys
from pathlib import Path

import pytest

from watson.cli import build_case, main
import watson.cli
import watson.tool_discovery
import watson.pe_metadata


def _isolate_rule_caches(monkeypatch, tmp_path):
    # real ~/.watson/rules/* may already be populated on this machine from
    # prior interactive fetches; point the caches at guaranteed-empty dirs so
    # tests that don't pass --rules-dir/--capa-rules-dir stay fast and
    # deterministic instead of silently running a real scan
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "unused-yara-cache")
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")
    monkeypatch.setattr("watson.cli.GORESYM_CACHE", tmp_path / "unused-goresym-cache")


def test_main_version_flag_prints_version_and_exits(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.strip().startswith("watson ")


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


def test_analyze_writes_case_for_elf_file(compiled_elf, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_elf), "--out", str(out_dir)])

    assert exit_code == 0

    captured = capsys.readouterr()
    assert "ELF Metadata" in captured.out
    assert compiled_elf.name in captured.out

    case_files = list(out_dir.glob("*.json"))
    assert len(case_files) == 1
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["elf_metadata"] is not None
    assert case_data["static"]["pe_metadata"] is None


def test_analyze_directory_handles_mixed_pe_and_elf_files(
    compiled_pe, compiled_elf, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    shutil.copy(compiled_elf, samples_dir / "two.elf")
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "one.exe:" in captured.err
    assert "two.elf:" in captured.err
    assert "analyzed: 2" in captured.out


def test_analyze_rejects_unrecognized_file_format(tmp_path, capsys):
    bad_file = tmp_path / "not_a_pe_or_elf.bin"
    bad_file.write_bytes(b"not a recognized binary at all")

    exit_code = main(["analyze", str(bad_file)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "not a recognized PE or ELF file" in captured.err


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

requires_stringsifter = pytest.mark.skipif(
    shutil.which("rank_strings") is None, reason="stringsifter not installed"
)


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
    # hh-mm-ss-DD-MM-YYYY-<sanitized name>-<md5>-<flags>.json, dots replaced
    # with dashes so it never reads like a double extension. Neither -y nor
    # -c is passed, but with no analysis-selection prompt in a non-interactive
    # session both default to attempted, hence the "-yc" flags suffix.
    assert name.count(".") == 1
    assert name.endswith(f"-{compiled_pe.stem}-{compiled_pe.suffix.lstrip('.')}-{md5}-yc.json")
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


def test_analyze_saves_output_files_with_capability_flags_suffix(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    # answer "y" to the analysis-selection prompt: only YARA selected
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    saved_files = list(out_dir.glob("*-y.json"))
    assert len(saved_files) == 1


def test_capability_flags_suffix_includes_u_when_unpack_selected():
    from watson.cli import _capability_flags_suffix

    suffix = _capability_flags_suffix(True, False, False, True, False, True, False, False)

    assert suffix == "ydu"


def test_capability_options_includes_unpack_letter():
    from watson.cli import CAPABILITY_OPTIONS

    keys = [key for key, _ in CAPABILITY_OPTIONS]

    assert keys == ["y", "c", "f", "d", "r", "u", "g", "p"]


def test_resolve_capability_selection_extracts_run_unpack_from_mega_prompt(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "u")

    result = watson.cli._resolve_capability_selection(
        rules_dir=None, capa_rules_dir=None, run_floss=None, run_die=None,
        run_yara=None, run_capa=None, run_rank=None, run_unpack=None, run_goresym=None,
        run_extract_pyinstaller=None, subject="test.exe",
    )

    *_, run_unpack, run_goresym, run_extract_pyinstaller, forced_verbose = result
    assert run_unpack is True


def test_analyze_selecting_unpack_via_mega_prompt_attempts_unpack(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "u")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "unpack not requested" not in captured.out


def test_analyze_with_explicit_unpack_flag_alone_never_shows_mega_prompt(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir), "--unpack"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "which analyses do you want to run?" not in captured.out


def test_resolve_upx_reports_unavailable_with_install_hint_when_missing(monkeypatch):
    from watson.cli import _resolve_upx

    original_which = shutil.which
    monkeypatch.setattr(
        "watson.tool_discovery.shutil.which",
        lambda name: None if name == "upx" else original_which(name),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Linux")

    status, path = _resolve_upx(offline=False)

    assert status["available"] is False
    assert "upx-ucl" in status["reason"]
    assert path is None


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
            "--rank-strings",
            "--unpack",
            "--goresym",
            "--extract-pyinstaller",
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


def test_setup_reports_summary_for_all_tools(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "unused-yara-cache")
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")

    exit_code = main(["setup"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Summary" in captured.out
    assert "python:" in captured.out
    assert "yara:" in captured.out
    assert "capa:" in captured.out
    assert "floss:" in captured.out
    assert "signify:" in captured.out
    assert "diec:" in captured.out
    assert "stringsifter:" in captured.out
    assert "watson analyze" in captured.out


def test_setup_reports_missing_stdlib_modules_with_apt_command_on_linux(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "unused-yara-cache")
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Linux")
    monkeypatch.setattr("watson.cli.tool_discovery.missing_stdlib_modules", lambda names: ["bz2", "readline"])
    monkeypatch.setattr("watson.cli._pyenv_version_from_executable", lambda: "3.11.15")

    exit_code = main(["setup"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "python: unavailable (missing stdlib module(s): bz2, readline" in captured.out
    assert (
        "fix: sudo apt install libbz2-dev libreadline-dev && "
        "pyenv uninstall 3.11.15 && pyenv install 3.11.15"
    ) in captured.out


def test_setup_omits_apt_command_for_missing_stdlib_modules_off_linux(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "unused-yara-cache")
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Darwin")
    monkeypatch.setattr("watson.cli.tool_discovery.missing_stdlib_modules", lambda names: ["bz2"])
    monkeypatch.setattr("watson.cli._pyenv_version_from_executable", lambda: None)

    exit_code = main(["setup"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "sudo apt install" not in captured.out
    assert "python: unavailable (missing stdlib module(s): bz2" in captured.out
    assert "rebuild this interpreter after installing the headers above" in captured.out


def test_pyenv_version_from_executable_extracts_version_segment(monkeypatch):
    from watson.cli import _pyenv_version_from_executable

    monkeypatch.setattr(
        "watson.cli.sys.executable", "/home/kali/.pyenv/versions/3.11.15/bin/python3"
    )

    assert _pyenv_version_from_executable() == "3.11.15"


def test_pyenv_version_from_executable_returns_none_for_non_pyenv_path(monkeypatch):
    from watson.cli import _pyenv_version_from_executable

    monkeypatch.setattr("watson.cli.sys.executable", "/usr/bin/python3")

    assert _pyenv_version_from_executable() is None


def test_setup_prints_interpreter_diagnostic_line(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("watson.cli.YARA_RULES_CACHE", tmp_path / "unused-yara-cache")
    monkeypatch.setattr("watson.cli.CAPA_RULES_CACHE", tmp_path / "unused-capa-cache")
    monkeypatch.setattr("watson.cli.CAPA_SIGS_REPO_CACHE", tmp_path / "unused-capa-sigs-cache")
    monkeypatch.setattr("watson.cli.DIE_CACHE", tmp_path / "unused-die-cache")

    exit_code = main(["setup"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert f"Running under: {sys.executable}" in captured.out
    assert "virtual environment:" in captured.out


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
        raise AssertionError(
            "should not prompt when run_yara/run_capa/run_floss/run_die/run_rank are all explicit"
        )

    monkeypatch.setattr("builtins.input", fail_if_called)

    case, floss_raw, forced_verbose, ranked_strings_full, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
        run_unpack=False,
        run_goresym=False,
        run_extract_pyinstaller=False,
    )

    assert case.static.tools["yara"] == {
        "available": False,
        "reason": "not requested (skipped at the analysis-selection prompt)",
    }
    assert case.static.tools["capa"] == {
        "available": False,
        "reason": "not requested (skipped at the analysis-selection prompt)",
    }
    assert case.static.tools["stringsifter"] == {
        "available": False,
        "reason": "stringsifter not requested (use --rank-strings)",
    }
    assert forced_verbose is False
    assert ranked_strings_full is None


def test_build_case_passes_is_unsigned_true_for_unsigned_pe(compiled_pe, monkeypatch):
    captured_kwargs = {}
    real_classify = watson.cli.classify

    def recording_classify(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_classify(*args, **kwargs)

    monkeypatch.setattr("watson.cli.classify", recording_classify)

    build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
    )

    assert captured_kwargs["is_unsigned"] is True


def test_build_case_passes_is_unsigned_false_for_elf(compiled_elf, monkeypatch):
    captured_kwargs = {}
    real_classify = watson.cli.classify

    def recording_classify(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_classify(*args, **kwargs)

    monkeypatch.setattr("watson.cli.classify", recording_classify)

    build_case(
        compiled_elf,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
    )

    assert captured_kwargs["is_unsigned"] is False


def test_build_case_passes_signature_invalid_false_when_signify_unavailable(compiled_pe, monkeypatch):
    monkeypatch.setattr(
        "watson.cli.find_module",
        lambda *a, **k: watson.tool_discovery.ToolStatus(
            name="signify", available=False, path=None, reason="signify not installed"
        ),
    )
    captured_kwargs = {}
    real_classify = watson.cli.classify

    def recording_classify(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_classify(*args, **kwargs)

    monkeypatch.setattr("watson.cli.classify", recording_classify)

    case, *_ = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert captured_kwargs["signature_invalid"] is False
    assert case.static.signature_verification is None
    assert case.static.tools["signify"]["available"] is False


def test_build_case_skips_verification_when_pe_unsigned(compiled_pe, monkeypatch):
    # compiled_pe is a freshly compiled, never-signed fixture, so
    # has_digital_signature is False and verify_signature must not be called
    # even if signify itself is available.
    def fail_if_called(*args, **kwargs):
        raise AssertionError("verify_signature should not be called for an unsigned PE")

    monkeypatch.setattr("watson.cli.verify_signature", fail_if_called)

    case, *_ = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert case.static.signature_verification is None


def test_build_case_records_authenticode_scan_error_as_unavailable(compiled_pe, monkeypatch):
    from watson.authenticode_scan import AuthenticodeScanError

    monkeypatch.setattr("watson.cli.find_module", lambda *a, **k: watson.tool_discovery.ToolStatus(
        name="signify", available=True, path="signify", reason=None
    ))
    monkeypatch.setattr("watson.pe_metadata.extract_pe_metadata", watson.pe_metadata.extract_pe_metadata)
    monkeypatch.setattr(
        watson.cli, "extract_pe_metadata",
        lambda path: {**watson.pe_metadata.extract_pe_metadata(path), "has_digital_signature": True},
    )

    def raise_scan_error(*args, **kwargs):
        raise AuthenticodeScanError("boom")

    monkeypatch.setattr("watson.cli.verify_signature", raise_scan_error)

    case, *_ = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert case.static.signature_verification is None
    assert case.static.tools["signify"]["available"] is False
    assert "signature verification failed" in case.static.tools["signify"]["reason"]


def test_build_case_records_signature_verification_on_success(compiled_pe, monkeypatch):
    monkeypatch.setattr("watson.cli.find_module", lambda *a, **k: watson.tool_discovery.ToolStatus(
        name="signify", available=True, path="signify", reason=None
    ))
    monkeypatch.setattr("watson.pe_metadata.extract_pe_metadata", watson.pe_metadata.extract_pe_metadata)
    monkeypatch.setattr(
        watson.cli, "extract_pe_metadata",
        lambda path: {**watson.pe_metadata.extract_pe_metadata(path), "has_digital_signature": True},
    )

    verify_result = {
        "status": "valid",
        "verification_result": "OK",
        "signer_subject": "CN=Example Signer",
        "signer_issuer": "CN=Example Root",
        "valid_from": "2026-01-01T00:00:00+00:00",
        "valid_to": "2027-01-01T00:00:00+00:00",
        "error": None,
    }
    monkeypatch.setattr("watson.cli.verify_signature", lambda *a, **k: verify_result)

    captured_kwargs = {}
    real_classify = watson.cli.classify

    def recording_classify(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_classify(*args, **kwargs)

    monkeypatch.setattr("watson.cli.classify", recording_classify)

    case, *_ = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert case.static.signature_verification.tool == "signify"
    assert case.static.signature_verification.status == "valid"
    assert case.static.signature_verification.verification_result == "OK"
    assert case.static.signature_verification.signer_subject == "CN=Example Signer"
    assert case.static.signature_verification.signer_issuer == "CN=Example Root"
    assert case.static.signature_verification.valid_from == "2026-01-01T00:00:00+00:00"
    assert case.static.signature_verification.valid_to == "2027-01-01T00:00:00+00:00"
    assert case.static.signature_verification.error is None
    assert captured_kwargs["signature_invalid"] is False
    assert captured_kwargs["signature_verification_result"] == "OK"


def test_build_case_records_signature_invalid_true_when_verification_fails(compiled_pe, monkeypatch):
    monkeypatch.setattr("watson.cli.find_module", lambda *a, **k: watson.tool_discovery.ToolStatus(
        name="signify", available=True, path="signify", reason=None
    ))
    monkeypatch.setattr("watson.pe_metadata.extract_pe_metadata", watson.pe_metadata.extract_pe_metadata)
    monkeypatch.setattr(
        watson.cli, "extract_pe_metadata",
        lambda path: {**watson.pe_metadata.extract_pe_metadata(path), "has_digital_signature": True},
    )

    verify_result = {
        "status": "invalid",
        "verification_result": "CERTIFICATE_ERROR",
        "signer_subject": "CN=Example Signer",
        "signer_issuer": "CN=Example Root",
        "valid_from": "2026-01-01T00:00:00+00:00",
        "valid_to": "2027-01-01T00:00:00+00:00",
        "error": "untrusted root",
    }
    monkeypatch.setattr("watson.cli.verify_signature", lambda *a, **k: verify_result)

    captured_kwargs = {}
    real_classify = watson.cli.classify

    def recording_classify(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_classify(*args, **kwargs)

    monkeypatch.setattr("watson.cli.classify", recording_classify)

    case, *_ = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert case.static.signature_verification.status == "invalid"
    assert case.static.signature_verification.verification_result == "CERTIFICATE_ERROR"
    assert captured_kwargs["signature_invalid"] is True
    assert captured_kwargs["signature_verification_result"] == "CERTIFICATE_ERROR"


def test_build_case_populates_pe_metadata_versioninfo_fields(masquerading_pe):
    case, *_ = build_case(
        masquerading_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert case.static.pe_metadata.company_name == "Watson Test Company"
    assert case.static.pe_metadata.original_filename == "original-fixture-name.exe"
    assert case.static.pe_metadata.requested_execution_level == "requireAdministrator"


def test_build_case_flags_filename_mismatch_for_masquerading_pe(masquerading_pe):
    case, *_ = build_case(
        masquerading_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    # masquerading_pe's OriginalFilename ("original-fixture-name.exe") never
    # matches its actual on-disk filename ("masquerading.exe", set by the
    # conftest.py fixture), so this must always be True here.
    assert case.static.masquerade_check.filename_mismatch is True
    assert case.static.masquerade_check.requested_execution_level == "requireAdministrator"


def test_build_case_flags_claimed_vendor_mismatch_when_unsigned_and_known_vendor_claimed(
    compiled_pe, monkeypatch
):
    monkeypatch.setattr(
        watson.cli, "extract_pe_metadata",
        lambda path: {**watson.pe_metadata.extract_pe_metadata(path), "company_name": "Microsoft Corporation"},
    )
    captured_kwargs = {}
    real_classify = watson.cli.classify

    def recording_classify(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_classify(*args, **kwargs)

    monkeypatch.setattr("watson.cli.classify", recording_classify)

    case, *_ = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert case.static.masquerade_check.claimed_vendor_mismatch is True
    assert case.static.masquerade_check.claimed_vendor == "Microsoft Corporation"
    assert captured_kwargs["claimed_vendor_mismatch"] is True
    assert captured_kwargs["claimed_vendor"] == "Microsoft Corporation"


def test_build_case_no_claimed_vendor_mismatch_when_signed_but_signify_unavailable(
    compiled_pe, monkeypatch
):
    # the sample DOES carry a signature, but signify isn't installed so its
    # identity can't be checked: this must never be reported as a mismatch,
    # only as "unknown". A false positive here would mean a validly-signed
    # Microsoft binary gets flagged purely because the verification tool
    # wasn't available.
    monkeypatch.setattr(
        "watson.cli.find_module",
        lambda *a, **k: watson.tool_discovery.ToolStatus(
            name="signify", available=False, path=None, reason="signify not installed"
        ),
    )
    monkeypatch.setattr(
        watson.cli, "extract_pe_metadata",
        lambda path: {
            **watson.pe_metadata.extract_pe_metadata(path),
            "has_digital_signature": True,
            "company_name": "Microsoft Corporation",
        },
    )

    case, *_ = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert case.static.signature_verification is None
    assert case.static.tools["signify"]["available"] is False
    assert case.static.masquerade_check.claimed_vendor_mismatch is False


def test_build_case_no_claimed_vendor_mismatch_for_elf(compiled_elf):
    case, *_ = build_case(
        compiled_elf, run_yara=False, run_capa=False, run_floss=False, run_die=False, run_rank=False
    )

    assert case.static.masquerade_check is None


def test_build_case_explicit_run_yara_run_capa_still_prompts_for_floss_die_and_rank_once_each(
    compiled_pe, monkeypatch
):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    answers = iter(["n", "n", "n", "n", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    case, floss_raw, forced_verbose, ranked_strings_full, _, _, _, _, _ = build_case(
        compiled_pe, run_yara=False, run_capa=False
    )

    assert case.static.tools["floss"]["reason"] == "floss not requested (use --floss)"
    assert case.static.tools["diec"]["reason"] == "diec not requested (use --diec)"
    assert case.static.tools["stringsifter"]["reason"] == "stringsifter not requested (use --rank-strings)"


def test_build_case_returns_flags_suffix_matching_selected_capabilities(compiled_pe):
    case, floss_raw, forced_verbose, ranked_strings_full, flags_suffix, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=True,
        run_capa=False,
        run_floss=True,
        run_die=False,
        run_rank=False,
    )

    assert flags_suffix == "yf"


def test_build_case_returns_empty_flags_suffix_when_nothing_selected(compiled_pe):
    case, floss_raw, forced_verbose, ranked_strings_full, flags_suffix, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
    )

    assert flags_suffix == ""


def test_build_case_includes_python_stdlib_check_in_tools_regardless_of_flags(compiled_pe):
    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
        run_unpack=False,
    )

    assert "python" in case.static.tools
    assert case.static.tools["python"]["available"] is True


def test_build_case_returns_nine_element_tuple_including_resolved_capabilities(compiled_pe):
    result = build_case(
        compiled_pe,
        run_yara=True,
        run_capa=False,
        run_floss=True,
        run_die=False,
        run_rank=False,
    )

    assert len(result) == 9
    resolved_capabilities = result[5]
    assert resolved_capabilities == (True, False, True, False, False, False)


def test_build_case_does_not_attempt_unpack_when_run_unpack_false(compiled_pe):
    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
        run_unpack=False,
    )

    assert case.static.unpacking is None


def test_build_case_does_not_attempt_unpack_when_die_not_run(compiled_pe, monkeypatch):
    monkeypatch.setattr("watson.cli._resolve_upx", lambda offline: ({"available": True, "reason": None}, "upx"))

    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
        run_unpack=True,
    )

    assert case.static.unpacking is None


def test_build_case_does_not_attempt_unpack_when_die_finds_no_upx(compiled_pe, monkeypatch):
    monkeypatch.setattr("watson.cli._resolve_upx", lambda offline: ({"available": True, "reason": None}, "upx"))
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr("watson.cli.die_scan_file", lambda *a, **k: [])

    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_unpack=True,
    )

    assert case.static.unpacking is None


def test_build_case_populates_unpacking_result_when_upx_detected_and_unpack_succeeds(compiled_pe, monkeypatch, tmp_path):
    monkeypatch.setattr("watson.cli._resolve_upx", lambda offline: ({"available": True, "reason": None}, "upx"))
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "UPX", "version": "4.2.4", "string": None}]}],
    )
    monkeypatch.setattr("watson.cli.upx_unpack.unpack_file", lambda file_path, output_path, **k: output_path.write_bytes(b"unpacked"))

    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_unpack=True,
    )

    assert case.static.unpacking is not None
    assert case.static.unpacking.tool == "upx"
    assert case.static.unpacking.success is True
    assert case.static.unpacking.output_path is not None
    assert Path(case.static.unpacking.output_path).exists()


def test_build_case_records_failure_reason_when_unpack_fails(compiled_pe, monkeypatch):
    from watson.upx_unpack import UpxUnpackError

    monkeypatch.setattr("watson.cli._resolve_upx", lambda offline: ({"available": True, "reason": None}, "upx"))
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "UPX", "version": None, "string": None}]}],
    )

    def failing_unpack(*a, **k):
        raise UpxUnpackError("upx exited with code 2")

    monkeypatch.setattr("watson.cli.upx_unpack.unpack_file", failing_unpack)

    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_unpack=True,
    )

    assert case.static.unpacking.success is False
    assert case.static.unpacking.reason == "upx exited with code 2"


def test_build_case_skips_pyinstaller_extraction_when_not_requested(compiled_pe):
    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
        run_extract_pyinstaller=False,
    )

    assert case.static.pyinstaller_extraction is None
    assert case.static.tools["pyinstxtractor"]["available"] is False
    assert "not requested" in case.static.tools["pyinstxtractor"]["reason"]


def test_build_case_does_not_attempt_extraction_when_die_not_run(compiled_pe):
    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
        run_extract_pyinstaller=True,
    )

    assert case.static.pyinstaller_extraction is None
    assert case.static.tools["pyinstxtractor"]["available"] is False
    assert "diec" in case.static.tools["pyinstxtractor"]["reason"]


def test_build_case_does_not_attempt_extraction_when_die_finds_no_pyinstaller(compiled_pe, monkeypatch):
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr("watson.cli.die_scan_file", lambda *a, **k: [])

    case, _, _, _, _, _, _, _, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_extract_pyinstaller=True,
    )

    assert case.static.pyinstaller_extraction is None


def test_build_case_populates_pyinstaller_extraction_when_detected_and_extraction_succeeds(compiled_pe, monkeypatch):
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_entries = [{"path": "main.pyc", "size": 10, "pyarmor_protected": False}]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_entries)

    case, _, _, _, _, _, _, pyinstaller_output_dir, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_extract_pyinstaller=True,
    )

    assert case.static.pyinstaller_extraction is not None
    assert case.static.pyinstaller_extraction.success is True
    assert case.static.pyinstaller_extraction.entries == fake_entries
    assert case.static.tools["pyinstxtractor"]["available"] is True
    assert pyinstaller_output_dir is not None


def test_build_case_records_extraction_failure_reason(compiled_pe, monkeypatch):
    from watson.pyinstaller_extract import PyInstallerExtractError

    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )

    def failing_extract(*a, **k):
        raise PyInstallerExtractError("boom")

    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", failing_extract)

    case, _, _, _, _, _, _, pyinstaller_output_dir, _ = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_extract_pyinstaller=True,
    )

    assert case.static.pyinstaller_extraction.success is False
    assert case.static.pyinstaller_extraction.reason == "boom"
    assert pyinstaller_output_dir is None


def test_build_case_skips_pyarmor_unpack_when_pyinstaller_extraction_not_attempted(compiled_pe):
    (
        case, _, _, _, _, _, _, _, pyarmor_output_dir,
    ) = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=False,
        run_rank=False,
        run_extract_pyinstaller=False,
    )

    assert case.static.pyarmor_unpacking is None
    assert pyarmor_output_dir is None


def test_build_case_skips_pyarmor_unpack_when_extraction_found_nothing_protected(compiled_pe, monkeypatch):
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_entries = [{"path": "python311.dll", "size": 20, "pyarmor_protected": False}]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_entries)

    (
        case, _, _, _, _, _, _, _, pyarmor_output_dir,
    ) = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_extract_pyinstaller=True,
    )

    assert case.static.pyarmor_unpacking is None
    assert "not attempted" in case.static.tools["pyarmor1shot"]["reason"]
    assert pyarmor_output_dir is None


def test_build_case_reports_pyarmor1shot_unavailable_reason_when_tool_missing(compiled_pe, monkeypatch):
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_entries = [{"path": "main.pyc", "size": 10, "pyarmor_protected": True}]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_entries)
    monkeypatch.setattr(
        "watson.cli._resolve_pyarmor1shot",
        lambda offline: ({"available": False, "reason": "pycryptodome python module not found"}, None),
    )

    (
        case, _, _, _, _, _, _, _, pyarmor_output_dir,
    ) = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_extract_pyinstaller=True,
    )

    assert case.static.pyarmor_unpacking is None
    assert case.static.tools["pyarmor1shot"] == {
        "available": False, "reason": "pycryptodome python module not found",
    }
    assert pyarmor_output_dir is None


def test_build_case_attempts_pyarmor_unpack_when_protected_entries_found(compiled_pe, monkeypatch):
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_extraction_entries = [
        {"path": "main.pyc", "size": 10, "pyarmor_protected": True},
        {"path": "python311.dll", "size": 20, "pyarmor_protected": False},
    ]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_extraction_entries)
    monkeypatch.setattr(
        "watson.cli._resolve_pyarmor1shot", lambda offline: ({"available": True, "reason": None}, "/opt/oneshot/shot.py")
    )
    fake_unpack_entries = [{"path": "main.pyc.1shot.py", "size": 128}]
    monkeypatch.setattr("watson.cli.pyarmor_unpack.unpack_dir", lambda *a, **k: fake_unpack_entries)

    (
        case, _, _, _, _, _, _, pyinstaller_output_dir, pyarmor_output_dir,
    ) = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_extract_pyinstaller=True,
    )

    assert case.static.pyarmor_unpacking is not None
    assert case.static.pyarmor_unpacking.success is True
    assert case.static.pyarmor_unpacking.entries == fake_unpack_entries
    assert case.static.tools["pyarmor1shot"]["available"] is True
    assert pyarmor_output_dir is not None


def test_build_case_records_pyarmor_unpack_failure_reason(compiled_pe, monkeypatch):
    from watson.pyarmor_unpack import PyArmorUnpackError

    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_extraction_entries = [{"path": "main.pyc", "size": 10, "pyarmor_protected": True}]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_extraction_entries)
    monkeypatch.setattr(
        "watson.cli._resolve_pyarmor1shot", lambda offline: ({"available": True, "reason": None}, "/opt/oneshot/shot.py")
    )

    def failing_unpack(*a, **k):
        raise PyArmorUnpackError("boom")

    monkeypatch.setattr("watson.cli.pyarmor_unpack.unpack_dir", failing_unpack)

    (
        case, _, _, _, _, _, _, _, pyarmor_output_dir,
    ) = build_case(
        compiled_pe,
        run_yara=False,
        run_capa=False,
        run_floss=False,
        run_die=True,
        run_rank=False,
        run_extract_pyinstaller=True,
    )

    assert case.static.pyarmor_unpacking.success is False
    assert case.static.pyarmor_unpacking.reason == "boom"
    assert pyarmor_output_dir is None


def test_analyze_unpacks_and_saves_a_second_case_for_a_upx_packed_sample(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.cli._resolve_upx", lambda offline: ({"available": True, "reason": None}, "upx"))
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "UPX", "version": None, "string": None}]}],
    )
    monkeypatch.setattr(
        "watson.cli.upx_unpack.unpack_file",
        lambda file_path, output_path, **k: output_path.write_bytes(file_path.read_bytes()),
    )

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--diec", "--unpack"]
    )

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    assert len(case_files) == 2
    unpacked_files = [f for f in case_files if "_unpacked" in f.name]
    assert len(unpacked_files) == 1
    captured = capsys.readouterr()
    assert "Unpacked binary analysis" in captured.out


def test_analyze_extracts_and_saves_manifest_when_pyinstaller_detected(compiled_pe, tmp_path, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_entries = [{"path": "main.pyc", "size": 10, "pyarmor_protected": True}]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_entries)

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--diec", "--extract-pyinstaller"]
    )

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    assert len(case_files) == 1
    data = json.loads(case_files[0].read_text())
    assert data["static"]["pyinstaller_extraction"]["success"] is True
    assert data["static"]["pyinstaller_extraction"]["entries"] == fake_entries
    assert data["static"]["pyinstaller_extraction"]["output_dir"].startswith(str(out_dir))
    assert Path(data["static"]["pyinstaller_extraction"]["output_dir"]).is_dir()


def test_analyze_pyinstaller_extraction_absent_when_die_finds_no_pyinstaller(compiled_pe, tmp_path, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr("watson.cli.die_scan_file", lambda *a, **k: [])

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--diec", "--extract-pyinstaller"]
    )

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    data = json.loads(case_files[0].read_text())
    assert data["static"]["pyinstaller_extraction"] is None


def test_analyze_unpacks_pyarmor_and_saves_manifest_when_protected_entries_found(compiled_pe, tmp_path, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_extraction_entries = [{"path": "main.pyc", "size": 10, "pyarmor_protected": True}]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_extraction_entries)
    monkeypatch.setattr(
        "watson.cli._resolve_pyarmor1shot", lambda offline: ({"available": True, "reason": None}, "/opt/oneshot/shot.py")
    )
    fake_unpack_entries = [{"path": "main.pyc.1shot.py", "size": 128}]
    monkeypatch.setattr("watson.cli.pyarmor_unpack.unpack_dir", lambda *a, **k: fake_unpack_entries)

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--diec", "--extract-pyinstaller"]
    )

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    assert len(case_files) == 1
    data = json.loads(case_files[0].read_text())
    assert data["static"]["pyarmor_unpacking"]["success"] is True
    assert data["static"]["pyarmor_unpacking"]["entries"] == fake_unpack_entries
    assert data["static"]["pyarmor_unpacking"]["output_dir"].startswith(str(out_dir))
    assert Path(data["static"]["pyarmor_unpacking"]["output_dir"]).is_dir()


def test_analyze_pyarmor_unpacking_absent_when_nothing_protected(compiled_pe, tmp_path, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_entries = [{"path": "python311.dll", "size": 20, "pyarmor_protected": False}]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_entries)

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--diec", "--extract-pyinstaller"]
    )

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    data = json.loads(case_files[0].read_text())
    assert data["static"]["pyarmor_unpacking"] is None


def test_analyze_directory_unpacks_pyarmor_and_saves_manifest_for_protected_entries(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    out_dir = tmp_path / "cases"
    monkeypatch.setattr(
        "watson.cli._resolve_pyinstxtractor", lambda offline: ({"available": True, "reason": None}, "pyinstxtractor-ng")
    )
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "PyInstaller", "version": None, "string": None}]}],
    )
    fake_extraction_entries = [{"path": "main.pyc", "size": 10, "pyarmor_protected": True}]
    monkeypatch.setattr("watson.cli.pyinstaller_extract.extract_file", lambda *a, **k: fake_extraction_entries)
    monkeypatch.setattr(
        "watson.cli._resolve_pyarmor1shot", lambda offline: ({"available": True, "reason": None}, "/opt/oneshot/shot.py")
    )
    fake_unpack_entries = [{"path": "main.pyc.1shot.py", "size": 128}]
    monkeypatch.setattr("watson.cli.pyarmor_unpack.unpack_dir", lambda *a, **k: fake_unpack_entries)

    exit_code = main(
        ["analyze", str(samples_dir), "--out", str(out_dir), "--diec", "--extract-pyinstaller"]
    )

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    assert len(case_files) == 1
    data = json.loads(case_files[0].read_text())
    assert data["static"]["pyarmor_unpacking"]["success"] is True
    pyarmor_dir = Path(data["static"]["pyarmor_unpacking"]["output_dir"])
    assert pyarmor_dir.is_dir()
    assert str(pyarmor_dir).startswith(str(out_dir))
    captured = capsys.readouterr()
    assert "[pyarmor unpacked]" in captured.err


def test_analyze_directory_unpacks_and_saves_second_cases_for_upx_packed_samples(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.cli._resolve_upx", lambda offline: ({"available": True, "reason": None}, "upx"))
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "UPX", "version": None, "string": None}]}],
    )
    monkeypatch.setattr(
        "watson.cli.upx_unpack.unpack_file",
        lambda file_path, output_path, **k: output_path.write_bytes(file_path.read_bytes()),
    )

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir), "--diec", "--unpack"])

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    assert len(case_files) == 2
    unpacked_files = [f for f in case_files if "_unpacked" in f.name]
    assert len(unpacked_files) == 1
    captured = capsys.readouterr()
    assert "unpacked: 1" in captured.out


def test_analyze_survives_unparseable_unpacked_output_and_still_saves_the_primary_case(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.cli._resolve_upx", lambda offline: ({"available": True, "reason": None}, "upx"))
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))
    monkeypatch.setattr(
        "watson.cli.die_scan_file",
        lambda *a, **k: [{"filetype": "PE64", "values": [{"type": "packer", "name": "UPX", "version": None, "string": None}]}],
    )
    monkeypatch.setattr(
        "watson.cli.upx_unpack.unpack_file",
        lambda file_path, output_path, **k: output_path.write_bytes(
            b"not a valid pe or elf, this will fail detect_format"
        ),
    )

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--diec", "--unpack"]
    )

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    assert len(case_files) == 1
    data = json.loads(case_files[0].read_text())
    assert "re-analysis failed" in data["static"]["unpacking"]["reason"]
    assert data["static"]["unpacking"]["success"] is True
    assert data["static"]["unpacking"]["unpacked_sha256"] is None
    captured = capsys.readouterr()
    assert "Unpacked binary analysis" not in captured.out
    assert "re-analysis failed" in captured.out


def test_analyze_directory_survives_unparseable_unpacked_output_and_analyzes_remaining_files(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    shutil.copy(compiled_pe, samples_dir / "two.exe")
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.cli._resolve_upx", lambda offline: ({"available": True, "reason": None}, "upx"))
    monkeypatch.setattr("watson.cli._resolve_die", lambda offline: ({"available": True, "reason": None}, "diec"))

    def fake_die_scan(file_path, *a, **k):
        if file_path.name == "one.exe":
            return [{"filetype": "PE64", "values": [{"type": "packer", "name": "UPX", "version": None, "string": None}]}]
        return []

    monkeypatch.setattr("watson.cli.die_scan_file", fake_die_scan)
    monkeypatch.setattr(
        "watson.cli.upx_unpack.unpack_file",
        lambda file_path, output_path, **k: output_path.write_bytes(
            b"not a valid pe or elf, this will fail detect_format"
        ),
    )

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir), "--diec", "--unpack"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "one.exe:" in captured.err
    assert "two.exe:" in captured.err
    assert "[unpacked, re-analysis failed]" in captured.err
    assert "Batch summary" in captured.out
    assert "analyzed: 2" in captured.out
    assert "unpacked: 1" in captured.out

    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    assert len(case_files) == 2
    unpacked_files = [f for f in case_files if "_unpacked" in f.name]
    assert len(unpacked_files) == 0
    summary_files = list(out_dir.glob("*-batch-summary.txt"))
    assert len(summary_files) == 1


def test_analyze_directory_recursively_finds_and_analyzes_files(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    (samples_dir / "nested").mkdir(parents=True)
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    shutil.copy(compiled_pe, samples_dir / "nested" / "two.exe")
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "one.exe:" in captured.err
    assert "two.exe:" in captured.err
    assert "Batch summary" in captured.out
    assert "analyzed: 2" in captured.out

    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith("_floss.json")]
    assert len(case_files) == 2


def test_analyze_directory_asks_analysis_selection_once_for_whole_batch(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    shutil.copy(compiled_pe, samples_dir / "two.exe")
    shutil.copy(compiled_pe, samples_dir / "three.exe")
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)

    call_count = {"n": 0}

    def counting_input(prompt=""):
        call_count["n"] += 1
        return "n"

    monkeypatch.setattr("builtins.input", counting_input)

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir)])

    assert exit_code == 0
    assert call_count["n"] == 1
    captured = capsys.readouterr()
    assert captured.out.count("which analyses do you want to run?") == 1


def test_analyze_directory_uses_same_flags_suffix_for_every_file_in_batch(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    shutil.copy(compiled_pe, samples_dir / "two.exe")
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    # answer "y" to the analysis-selection prompt: only YARA selected, for the whole batch
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir)])

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith("_floss.json")]
    assert len(case_files) == 2
    assert all(f.name.endswith("-y.json") for f in case_files)


def test_analyze_directory_asks_floss_and_die_confirmation_once_each(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    shutil.copy(compiled_pe, samples_dir / "two.exe")
    empty_rules_dir = tmp_path / "empty_rules"
    empty_rules_dir.mkdir()
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)

    call_count = {"n": 0}

    def counting_input(prompt=""):
        call_count["n"] += 1
        return "n"

    monkeypatch.setattr("builtins.input", counting_input)

    exit_code = main(
        ["analyze", str(samples_dir), "--out", str(out_dir), "--rules-dir", str(empty_rules_dir)]
    )

    assert exit_code == 0
    assert call_count["n"] == 6


def test_analyze_directory_skips_non_pe_files_and_continues(compiled_pe, tmp_path, capsys, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    (samples_dir / "readme.txt").write_bytes(b"not a pe file at all")
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "readme.txt: skipped (not a valid PE or ELF)" in captured.err
    assert "one.exe:" in captured.err
    assert "skipped (not a valid PE or ELF): 1" in captured.out
    assert "analyzed: 1" in captured.out

    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith("_floss.json")]
    assert len(case_files) == 1


def test_analyze_directory_records_unexpected_failure_and_continues(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "broken.exe")
    shutil.copy(compiled_pe, samples_dir / "ok.exe")
    out_dir = tmp_path / "cases"

    real_extract_pe_metadata = watson.cli.extract_pe_metadata

    def flaky_extract(file_path):
        if file_path.name == "broken.exe":
            raise RuntimeError("simulated tool crash")
        return real_extract_pe_metadata(file_path)

    monkeypatch.setattr("watson.cli.extract_pe_metadata", flaky_extract)

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "broken.exe: failed (simulated tool crash)" in captured.err
    assert "ok.exe:" in captured.err
    assert "failed: 1" in captured.out
    assert "analyzed: 1" in captured.out

    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith("_floss.json")]
    assert len(case_files) == 1


def test_analyze_directory_writes_batch_summary_file(compiled_pe, tmp_path, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    shutil.copy(compiled_pe, samples_dir / "one.exe")
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir)])

    assert exit_code == 0
    summary_files = list(out_dir.glob("*-batch-summary.txt"))
    assert len(summary_files) == 1
    content = summary_files[0].read_text()
    assert "Batch summary" in content
    assert "analyzed: 1" in content


def test_analyze_empty_directory_reports_zero_files(tmp_path, capsys):
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(samples_dir), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "scanned: 0 files" in captured.out


def test_analyze_rejects_missing_path_as_neither_file_nor_directory(tmp_path, capsys):
    missing = tmp_path / "does_not_exist"

    exit_code = main(["analyze", str(missing)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "is not a file or directory" in captured.err


def test_analyze_rank_strings_flag_without_floss_reports_floss_did_not_run(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir), "--rank-strings"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "stringsifter: unavailable (floss did not run" in captured.out

    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith("_floss.json")]
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["stringsifter"]["reason"] == (
        "floss did not run (string ranking needs FLOSS's output)"
    )
    assert not list(out_dir.glob("*_ranked_strings.json"))


def test_analyze_without_rank_strings_flag_reports_stringsifter_not_requested(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "stringsifter: unavailable" in captured.out

    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith("_floss.json")]
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["stringsifter"]["reason"] == (
        "stringsifter not requested (use --rank-strings)"
    )


@requires_floss
def test_analyze_selecting_floss_and_rank_together_lets_ranking_attempt_run(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--floss", "--rank-strings"]
    )

    assert exit_code == 0
    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith("_floss.json")]
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["stringsifter"]["reason"] != (
        "floss did not run (string ranking needs FLOSS's output)"
    )


@requires_floss
@requires_stringsifter
def test_analyze_with_floss_and_rank_strings_flags_writes_ranked_sidecar(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

    exit_code = main(
        ["analyze", str(compiled_pe), "--out", str(out_dir), "--floss", "--rank-strings"]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "stringsifter: available" in captured.out
    assert "Ranked Strings" in captured.out

    sidecars = list(out_dir.glob("*_ranked_strings.json"))
    assert len(sidecars) == 1

    case_files = [f for f in out_dir.glob("*.json") if not f.name.endswith(("_floss.json", "_ranked_strings.json"))]
    case_data = json.loads(case_files[0].read_text())
    assert len(case_data["static"]["ranked_strings"]) <= 20


def test_analyze_selecting_rank_without_floss_via_mega_prompt_reports_floss_did_not_run(
    compiled_pe, tmp_path, capsys, monkeypatch
):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "r")

    exit_code = main(["analyze", str(compiled_pe), "--out", str(out_dir)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "stringsifter: unavailable (floss did not run" in captured.out


def test_resolve_goresym_returns_available_when_on_path(monkeypatch):
    from watson.tool_discovery import ToolStatus

    monkeypatch.setattr(
        "watson.cli.find_binary",
        lambda name, pip_package=None, offline=False: ToolStatus(
            name=name, available=True, path="/usr/local/bin/GoReSym", reason=None
        ),
    )

    status, path = watson.cli._resolve_goresym(offline=True)

    assert status == {"available": True, "reason": None}
    assert path == "/usr/local/bin/GoReSym"


def test_resolve_goresym_falls_back_to_fetch_when_not_on_path(monkeypatch):
    from watson.tool_discovery import ToolStatus

    monkeypatch.setattr(
        "watson.cli.find_binary",
        lambda name, pip_package=None, offline=False: ToolStatus(
            name=name, available=False, path=None, reason="GoReSym not found"
        ),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Linux")

    calls = []

    def fake_fetch(name, binary_relpath, cache_dir, archive_url, offline=False):
        calls.append((name, binary_relpath, str(cache_dir), archive_url, offline))
        return ToolStatus(name=name, available=False, path=None, reason="download declined")

    monkeypatch.setattr("watson.cli.find_or_fetch_zip_binary", fake_fetch)

    status, path = watson.cli._resolve_goresym(offline=True)

    assert len(calls) == 1
    name, binary_relpath, cache_dir, archive_url, offline = calls[0]
    assert binary_relpath == "GoReSym"
    assert archive_url == (
        "https://github.com/mandiant/GoReSym/releases/download/v3.4/GoReSym-linux.zip"
    )
    assert offline is True
    assert status == {"available": False, "reason": "download declined"}
    assert path is None


def test_goresym_archive_url_is_none_on_macos(monkeypatch):
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Darwin")

    assert watson.cli._goresym_archive_url() is None


def test_resolve_goresym_falls_back_to_fetch_with_exe_relpath_on_windows(monkeypatch):
    from watson.tool_discovery import ToolStatus

    monkeypatch.setattr(
        "watson.cli.find_binary",
        lambda name, pip_package=None, offline=False: ToolStatus(
            name=name, available=False, path=None, reason="GoReSym not found"
        ),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Windows")

    calls = []

    def fake_fetch(name, binary_relpath, cache_dir, archive_url, offline=False):
        calls.append((name, binary_relpath, str(cache_dir), archive_url, offline))
        return ToolStatus(name=name, available=False, path=None, reason="download declined")

    monkeypatch.setattr("watson.cli.find_or_fetch_zip_binary", fake_fetch)

    status, path = watson.cli._resolve_goresym(offline=True)

    assert len(calls) == 1
    name, binary_relpath, cache_dir, archive_url, offline = calls[0]
    assert binary_relpath == "GoReSym.exe"
    assert archive_url == (
        "https://github.com/mandiant/GoReSym/releases/download/v3.4/GoReSym-windows.zip"
    )
    assert offline is True
    assert status == {"available": False, "reason": "download declined"}
    assert path is None


def test_resolve_pyarmor1shot_reports_unavailable_when_pycryptodome_missing(monkeypatch):
    from watson.tool_discovery import ToolStatus

    monkeypatch.setattr(
        "watson.cli.find_module",
        lambda name, module_name, pip_package=None, offline=False: ToolStatus(
            name=name, available=False, path=None, reason="Crypto python module not found"
        ),
    )
    calls = []
    monkeypatch.setattr(
        "watson.cli.find_or_fetch_zip_binary",
        lambda *a, **k: calls.append(1) or ToolStatus(name="x", available=True, path="x", reason=None),
    )

    status, shot_script = watson.cli._resolve_pyarmor1shot(offline=True)

    assert status == {"available": False, "reason": "Crypto python module not found"}
    assert shot_script is None
    assert calls == []


def test_resolve_pyarmor1shot_fetches_linux_bundle_and_derives_shot_script_path(monkeypatch, tmp_path):
    from watson.tool_discovery import ToolStatus

    monkeypatch.setattr(
        "watson.cli.find_module",
        lambda name, module_name, pip_package=None, offline=False: ToolStatus(
            name=name, available=True, path=module_name, reason=None
        ),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Linux")
    monkeypatch.setattr("watson.cli.platform.machine", lambda: "x86_64")

    calls = []
    resolved_binary = tmp_path / "oneshot" / "pyarmor-1shot"

    def fake_fetch(name, binary_relpath, cache_dir, archive_url, offline=False):
        calls.append((name, binary_relpath, str(cache_dir), archive_url, offline))
        return ToolStatus(name=name, available=True, path=str(resolved_binary), reason=None)

    monkeypatch.setattr("watson.cli.find_or_fetch_zip_binary", fake_fetch)

    status, shot_script = watson.cli._resolve_pyarmor1shot(offline=True)

    assert len(calls) == 1
    name, binary_relpath, cache_dir, archive_url, offline = calls[0]
    assert binary_relpath == "oneshot/pyarmor-1shot"
    assert archive_url == (
        "https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases/download/v0.4.0/"
        "pyarmor-1shot-v0.4.0-linux-x86_64.zip"
    )
    assert offline is True
    assert status == {"available": True, "reason": None}
    assert shot_script == str(resolved_binary.parent / "shot.py")


def test_resolve_pyarmor1shot_uses_exe_relpath_and_url_on_windows(monkeypatch):
    from watson.tool_discovery import ToolStatus

    monkeypatch.setattr(
        "watson.cli.find_module",
        lambda name, module_name, pip_package=None, offline=False: ToolStatus(
            name=name, available=True, path=module_name, reason=None
        ),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Windows")
    monkeypatch.setattr("watson.cli.platform.machine", lambda: "AMD64")

    calls = []

    def fake_fetch(name, binary_relpath, cache_dir, archive_url, offline=False):
        calls.append((binary_relpath, archive_url))
        return ToolStatus(name=name, available=False, path=None, reason="download declined")

    monkeypatch.setattr("watson.cli.find_or_fetch_zip_binary", fake_fetch)

    status, shot_script = watson.cli._resolve_pyarmor1shot(offline=True)

    binary_relpath, archive_url = calls[0]
    assert binary_relpath == "oneshot/pyarmor-1shot.exe"
    assert archive_url == (
        "https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases/download/v0.4.0/"
        "pyarmor-1shot-v0.4.0-windows-x86_64.zip"
    )
    assert status == {"available": False, "reason": "download declined"}
    assert shot_script is None


def test_resolve_pyarmor1shot_uses_darwin_arm64_url_on_macos(monkeypatch):
    from watson.tool_discovery import ToolStatus

    monkeypatch.setattr(
        "watson.cli.find_module",
        lambda name, module_name, pip_package=None, offline=False: ToolStatus(
            name=name, available=True, path=module_name, reason=None
        ),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Darwin")
    monkeypatch.setattr("watson.cli.platform.machine", lambda: "arm64")

    calls = []

    def fake_fetch(name, binary_relpath, cache_dir, archive_url, offline=False):
        calls.append((binary_relpath, archive_url))
        return ToolStatus(name=name, available=False, path=None, reason="download declined")

    monkeypatch.setattr("watson.cli.find_or_fetch_zip_binary", fake_fetch)

    watson.cli._resolve_pyarmor1shot(offline=True)

    binary_relpath, archive_url = calls[0]
    assert binary_relpath == "oneshot/pyarmor-1shot"
    assert archive_url == (
        "https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/releases/download/v0.4.0/"
        "pyarmor-1shot-v0.4.0-darwin-arm64.zip"
    )


def test_resolve_pyarmor1shot_reports_unavailable_on_unsupported_platform(monkeypatch):
    from watson.tool_discovery import ToolStatus

    monkeypatch.setattr(
        "watson.cli.find_module",
        lambda name, module_name, pip_package=None, offline=False: ToolStatus(
            name=name, available=True, path=module_name, reason=None
        ),
    )
    monkeypatch.setattr("watson.cli.platform.system", lambda: "Linux")
    monkeypatch.setattr("watson.cli.platform.machine", lambda: "aarch64")

    calls = []
    monkeypatch.setattr(
        "watson.cli.find_or_fetch_zip_binary",
        lambda *a, **k: calls.append(1) or ToolStatus(name="x", available=True, path="x", reason=None),
    )

    status, shot_script = watson.cli._resolve_pyarmor1shot(offline=True)

    assert calls == []
    assert status["available"] is False
    assert "releases" in status["reason"]
    assert shot_script is None


def test_capability_flags_suffix_includes_g_when_goresym_selected():
    suffix = watson.cli._capability_flags_suffix(
        attempt_yara=False, attempt_capa=False, run_floss=False,
        run_die=False, run_rank=False, run_unpack=False, run_goresym=True,
        run_extract_pyinstaller=False,
    )

    assert "g" in suffix


def test_resolve_capability_selection_returns_run_goresym_flag_unchanged_when_explicit(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: False)

    result = watson.cli._resolve_capability_selection(
        rules_dir=None, capa_rules_dir=None, run_floss=False, run_die=False,
        run_yara=False, run_capa=False, run_rank=False, run_unpack=False, run_goresym=True,
        run_extract_pyinstaller=False, subject="test.exe",
    )

    *_, run_goresym, run_extract_pyinstaller, forced_verbose = result
    assert run_goresym is True


def test_resolve_capability_selection_returns_run_unpack_flag_unchanged_when_explicit(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: False)

    result = watson.cli._resolve_capability_selection(
        rules_dir=None, capa_rules_dir=None, run_floss=False, run_die=False,
        run_yara=False, run_capa=False, run_rank=False, run_unpack=True, run_goresym=False,
        run_extract_pyinstaller=False, subject="test.exe",
    )

    *_, run_unpack, run_goresym, run_extract_pyinstaller, forced_verbose = result
    assert run_unpack is True


def test_build_case_runs_goresym_and_populates_go_build_info(compiled_pe, monkeypatch, tmp_path):
    _isolate_rule_caches(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "watson.cli._resolve_goresym",
        lambda offline: ({"available": True, "reason": None}, "GoReSym"),
    )
    monkeypatch.setattr(
        "watson.cli.goresym_scan.scan_file",
        lambda file_path, goresym_binary=None, timeout=60: {
            "BuildInfo": {
                "GoVersion": "go1.24.4",
                "Path": "watsontestbin",
                "Main": {"Path": "watsontestbin", "Version": "(devel)"},
                "Deps": [],
            },
            "UserFunctions": [{"PackageName": "main", "FullName": "main.main"}],
        },
    )

    result = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False,
        run_die=False, run_rank=False, run_goresym=True,
    )
    case = result[0]
    goresym_raw = result[6]

    assert case.static.tools["goresym"] == {"available": True, "reason": None}
    assert case.static.go_build_info["go_version"] == "go1.24.4"
    assert case.static.go_build_info["packages"] == {"main": ["main.main"]}
    assert goresym_raw is not None


def test_build_case_stripped_go_build_info_flows_into_classification(compiled_pe, monkeypatch, tmp_path):
    _isolate_rule_caches(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "watson.cli._resolve_goresym",
        lambda offline: ({"available": True, "reason": None}, "GoReSym"),
    )
    monkeypatch.setattr(
        "watson.cli.goresym_scan.scan_file",
        lambda file_path, goresym_binary=None, timeout=60: {
            "BuildInfo": {},
            "UserFunctions": [],
            "Version": "go1.24.4",
        },
    )

    result = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False,
        run_die=False, run_rank=False, run_goresym=True,
    )
    case = result[0]

    assert case.static.go_build_info["go_version"] == "go1.24.4"
    assert case.static.go_build_info["module_path"] is None
    assert (
        "Go binary detected (via pclntab) but no module path or function names were recovered, "
        "consistent with stripped symbols (e.g. -ldflags=\"-s -w\") or an obfuscator (e.g. Gobfuscator)"
        in case.static.classification["reasoning"]
    )


def test_build_case_reports_goresym_not_requested_by_default(compiled_pe, monkeypatch, tmp_path):
    _isolate_rule_caches(monkeypatch, tmp_path)

    result = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False,
        run_die=False, run_rank=False, run_goresym=False,
    )
    case = result[0]

    assert case.static.tools["goresym"] == {
        "available": False,
        "reason": "goresym not requested (use --goresym)",
    }
    assert case.static.go_build_info == {}


def test_build_case_marks_goresym_unavailable_on_scan_error(compiled_pe, monkeypatch, tmp_path):
    _isolate_rule_caches(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "watson.cli._resolve_goresym",
        lambda offline: ({"available": True, "reason": None}, "GoReSym"),
    )

    from watson.goresym_scan import GoReSymScanError

    def fake_scan(file_path, goresym_binary=None, timeout=60):
        raise GoReSymScanError("boom")

    monkeypatch.setattr("watson.cli.goresym_scan.scan_file", fake_scan)

    result = build_case(
        compiled_pe, run_yara=False, run_capa=False, run_floss=False,
        run_die=False, run_rank=False, run_goresym=True,
    )
    case = result[0]

    assert case.static.tools["goresym"]["available"] is False
    assert "goresym scan failed" in case.static.tools["goresym"]["reason"]
    assert case.static.go_build_info == {}


def test_analyze_without_goresym_flag_reports_not_requested(compiled_pe, tmp_path, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir)])

    assert exit_code == 0
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads(case_files[0].read_text())
    assert case_data["static"]["tools"]["goresym"]["reason"] == "goresym not requested (use --goresym)"
    assert case_data["static"]["go_build_info"] == {}


def test_analyze_goresym_flag_saves_sidecar_when_go_binary_detected(compiled_pe, tmp_path, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "watson.cli._resolve_goresym",
        lambda offline: ({"available": True, "reason": None}, "GoReSym"),
    )
    monkeypatch.setattr(
        "watson.cli.goresym_scan.scan_file",
        lambda file_path, goresym_binary=None, timeout=60: {
            "BuildInfo": {
                "GoVersion": "go1.24.4",
                "Path": "watsontestbin",
                "Main": {"Path": "watsontestbin", "Version": "(devel)"},
                "Deps": [],
            },
            "UserFunctions": [{"PackageName": "main", "FullName": "main.main"}],
        },
    )
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-g"])

    assert exit_code == 0
    sidecar_files = list(out_dir.glob("*_goresym.json"))
    assert len(sidecar_files) == 1
    sidecar_data = json.loads(sidecar_files[0].read_text())
    assert sidecar_data["BuildInfo"]["GoVersion"] == "go1.24.4"
    case_files = list(out_dir.glob("*.json"))
    case_data = json.loads([f for f in case_files if not f.name.endswith("_goresym.json")][0].read_text())
    assert case_data["static"]["go_build_info"]["go_version"] == "go1.24.4"


def test_analyze_goresym_does_not_save_sidecar_for_non_go_binary(compiled_pe, tmp_path, monkeypatch):
    _isolate_rule_caches(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "watson.cli._resolve_goresym",
        lambda offline: ({"available": True, "reason": None}, "GoReSym"),
    )
    monkeypatch.setattr(
        "watson.cli.goresym_scan.scan_file",
        lambda file_path, goresym_binary=None, timeout=60: {
            "error": "Failed to parse file: no valid pclntab found"
        },
    )
    out_dir = tmp_path / "cases"

    exit_code = main(["analyze", str(compiled_pe), "-o", str(out_dir), "-g"])

    assert exit_code == 0
    assert list(out_dir.glob("*_goresym.json")) == []
