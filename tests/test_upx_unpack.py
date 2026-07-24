import shutil
import subprocess
from pathlib import Path

import pytest

from watson.upx_unpack import UpxUnpackError, unpack_file

requires_upx = pytest.mark.skipif(shutil.which("upx") is None, reason="upx not installed")


@requires_upx
def test_unpack_file_decompresses_a_upx_packed_binary(compiled_pe, tmp_path):
    packed = tmp_path / "packed.exe"
    subprocess.run(["upx", "-q", "--best", "-o", str(packed), str(compiled_pe)], check=True)
    output = tmp_path / "unpacked.exe"

    unpack_file(packed, output)

    assert output.exists()
    assert output.stat().st_size == compiled_pe.stat().st_size


@requires_upx
def test_unpack_file_raises_upx_unpack_error_for_a_non_packed_file(compiled_pe, tmp_path):
    output = tmp_path / "unpacked.exe"

    with pytest.raises(UpxUnpackError):
        unpack_file(compiled_pe, output)


def test_unpack_file_raises_upx_unpack_error_when_binary_missing(tmp_path):
    input_file = tmp_path / "in.exe"
    input_file.write_bytes(b"not a real pe")
    output = tmp_path / "out.exe"

    with pytest.raises(UpxUnpackError):
        unpack_file(input_file, output, upx_binary="definitely-not-a-real-upx-binary-xyz")


def test_unpack_file_raises_upx_unpack_error_on_timeout(tmp_path, monkeypatch):
    input_file = tmp_path / "in.exe"
    input_file.write_bytes(b"not a real pe")
    output = tmp_path / "out.exe"

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="upx", timeout=1)

    monkeypatch.setattr("watson.upx_unpack.subprocess.run", fake_run)

    with pytest.raises(UpxUnpackError):
        unpack_file(input_file, output, timeout=1)
