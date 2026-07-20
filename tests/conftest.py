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
