import shutil
import subprocess
from pathlib import Path

import pytest

from watson.pyinstaller_extract import PyInstallerExtractError, extract_file

requires_pyinstxtractor = pytest.mark.skipif(
    shutil.which("pyinstxtractor-ng") is None, reason="pyinstxtractor-ng not installed"
)


def test_extract_file_raises_error_when_binary_missing(tmp_path):
    input_file = tmp_path / "in.exe"
    input_file.write_bytes(b"not a real pyinstaller exe")
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    with pytest.raises(PyInstallerExtractError):
        extract_file(input_file, output_dir, extractor_binary="definitely-not-a-real-tool-xyz")


def test_extract_file_raises_error_on_non_zero_exit(tmp_path, monkeypatch):
    input_file = tmp_path / "in.exe"
    input_file.write_bytes(b"not a real pyinstaller exe")
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="not a pyinstaller archive")

    monkeypatch.setattr("watson.pyinstaller_extract.subprocess.run", fake_run)

    with pytest.raises(PyInstallerExtractError, match="not a pyinstaller archive"):
        extract_file(input_file, output_dir)


def test_extract_file_raises_error_on_timeout(tmp_path, monkeypatch):
    input_file = tmp_path / "in.exe"
    input_file.write_bytes(b"not a real pyinstaller exe")
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="pyinstxtractor-ng", timeout=1)

    monkeypatch.setattr("watson.pyinstaller_extract.subprocess.run", fake_run)

    with pytest.raises(PyInstallerExtractError):
        extract_file(input_file, output_dir, timeout=1)


def test_extract_file_builds_manifest_from_extracted_tree(tmp_path, monkeypatch):
    input_file = tmp_path / "in.exe"
    input_file.write_bytes(b"not a real pyinstaller exe")
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_run(*args, **kwargs):
        extracted = Path(kwargs["cwd"]) / "in.exe_extracted"
        extracted.mkdir(parents=True)
        (extracted / "main.pyc").write_bytes(b"PY000000" + b"\x00" * 20)
        (extracted / "pyarmor_runtime.pyd").write_bytes(b"\x00" * 20)
        (extracted / "python311.dll").write_bytes(b"\x00" * 20)
        return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("watson.pyinstaller_extract.subprocess.run", fake_run)

    entries = extract_file(input_file, output_dir)

    by_path = {entry["path"]: entry for entry in entries}
    assert len(entries) == 3
    assert by_path["in.exe_extracted/main.pyc"]["pyarmor_protected"] is True
    assert by_path["in.exe_extracted/pyarmor_runtime.pyd"]["pyarmor_protected"] is True
    assert by_path["in.exe_extracted/python311.dll"]["pyarmor_protected"] is False
    assert by_path["in.exe_extracted/python311.dll"]["size"] == 20


@requires_pyinstxtractor
def test_extract_file_raises_error_for_a_non_pyinstaller_file(tmp_path):
    input_file = tmp_path / "plain.exe"
    input_file.write_bytes(b"MZ" + b"\x00" * 100)
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    with pytest.raises(PyInstallerExtractError):
        extract_file(input_file, output_dir)
