import json

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
