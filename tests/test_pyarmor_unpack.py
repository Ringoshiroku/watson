import subprocess
import sys
from pathlib import Path

import pytest

from watson.pyarmor_unpack import PyArmorUnpackError, unpack_dir


def test_unpack_dir_raises_error_on_non_zero_exit(tmp_path, monkeypatch):
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="unexpected crash")

    monkeypatch.setattr("watson.pyarmor_unpack.subprocess.run", fake_run)

    with pytest.raises(PyArmorUnpackError, match="unexpected crash"):
        unpack_dir(input_dir, output_dir, shot_script="/opt/oneshot/shot.py")


def test_unpack_dir_raises_error_on_timeout(tmp_path, monkeypatch):
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="shot.py", timeout=1)

    monkeypatch.setattr("watson.pyarmor_unpack.subprocess.run", fake_run)

    with pytest.raises(PyArmorUnpackError):
        unpack_dir(input_dir, output_dir, shot_script="/opt/oneshot/shot.py", timeout=1)


def test_unpack_dir_raises_error_on_oserror(tmp_path, monkeypatch):
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_run(*args, **kwargs):
        raise OSError("no such file or directory")

    monkeypatch.setattr("watson.pyarmor_unpack.subprocess.run", fake_run)

    with pytest.raises(PyArmorUnpackError):
        unpack_dir(input_dir, output_dir, shot_script="/nonexistent/shot.py")


def test_unpack_dir_raises_error_when_clean_exit_produces_no_output_files(tmp_path, monkeypatch):
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="no armored data found")

    monkeypatch.setattr("watson.pyarmor_unpack.subprocess.run", fake_run)

    with pytest.raises(PyArmorUnpackError, match="no armored data found"):
        unpack_dir(input_dir, output_dir, shot_script="/opt/oneshot/shot.py")


def test_unpack_dir_builds_manifest_from_generated_files(tmp_path, monkeypatch):
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    captured_cmd = []

    def fake_run(cmd, **kwargs):
        captured_cmd.extend(cmd)
        out = Path(cmd[-1])
        (out / "main.pyc.1shot.py").write_text("import os\n")
        (out / "main.pyc.1shot.seq").write_bytes(b"\x00" * 8)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("watson.pyarmor_unpack.subprocess.run", fake_run)

    entries = unpack_dir(input_dir, output_dir, shot_script="/opt/oneshot/shot.py")

    assert captured_cmd == [
        sys.executable, "/opt/oneshot/shot.py", str(input_dir), "--no-banner", "-o", str(output_dir),
    ]
    by_path = {entry["path"]: entry for entry in entries}
    assert len(entries) == 2
    assert by_path["main.pyc.1shot.py"]["size"] == len("import os\n")
    assert by_path["main.pyc.1shot.seq"]["size"] == 8
