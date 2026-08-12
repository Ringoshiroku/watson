import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURE_SOURCE = Path(__file__).parent / "fixtures" / "hello.c"
MINGW_COMPILER = "x86_64-w64-mingw32-gcc"


@pytest.fixture(scope="session")
def compiled_pe(tmp_path_factory) -> Path:
    if shutil.which(MINGW_COMPILER) is None:
        pytest.skip(f"{MINGW_COMPILER} not available")

    out_dir = tmp_path_factory.mktemp("pe_fixture")
    out_path = out_dir / "hello.exe"

    subprocess.run(
        [MINGW_COMPILER, str(FIXTURE_SOURCE), "-o", str(out_path)],
        check=True,
        capture_output=True,
    )

    return out_path


@pytest.fixture(scope="session")
def compiled_elf(tmp_path_factory) -> Path:
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")

    out_dir = tmp_path_factory.mktemp("elf_fixture")
    out_path = out_dir / "hello_elf"

    subprocess.run(
        ["gcc", str(FIXTURE_SOURCE), "-o", str(out_path)],
        check=True,
        capture_output=True,
    )

    return out_path


@pytest.fixture(scope="session")
def compiled_elf_static(tmp_path_factory) -> Path:
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")

    out_dir = tmp_path_factory.mktemp("elf_static_fixture")
    out_path = out_dir / "hello_elf_static"

    subprocess.run(
        ["gcc", "-static", str(FIXTURE_SOURCE), "-o", str(out_path)],
        check=True,
        capture_output=True,
    )

    return out_path


@pytest.fixture(scope="session")
def self_signed_pe(tmp_path_factory, compiled_pe) -> Path:
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    if shutil.which("osslsigncode") is None:
        pytest.skip("osslsigncode not available")

    out_dir = tmp_path_factory.mktemp("signed_pe_fixture")
    key_path = out_dir / "test.key"
    cert_path = out_dir / "test.crt"
    signed_path = out_dir / "hello_signed.exe"

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "365", "-nodes",
            "-subj", "/CN=Watson Test Signer/O=Watson Test Fixtures",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "osslsigncode", "sign",
            "-certs", str(cert_path), "-key", str(key_path),
            "-in", str(compiled_pe), "-out", str(signed_path),
        ],
        check=True,
        capture_output=True,
    )

    return signed_path


@pytest.fixture(scope="session")
def tampered_signed_pe(tmp_path_factory, self_signed_pe) -> Path:
    out_dir = tmp_path_factory.mktemp("tampered_pe_fixture")
    out_path = out_dir / "hello_tampered.exe"

    data = bytearray(self_signed_pe.read_bytes())
    # Flip a byte well inside the compiled code, ahead of the appended
    # Authenticode signature block, so the change lands in the signed
    # region and invalidates the digest rather than the signature bytes
    # themselves. If this offset lands outside the signed region for the
    # compiled fixture in practice, move it earlier (it must stay below
    # the PE's SizeOfHeaders + first section's raw data start).
    flip_offset = 512
    data[flip_offset] ^= 0xFF
    out_path.write_bytes(bytes(data))

    return out_path
