import contextlib
import io
import subprocess
import zipfile

from watson.tool_discovery import (
    check_stdlib_modules,
    confirm,
    find_binary,
    find_module,
    find_or_fetch_dir,
    find_or_fetch_zip_binary,
    select_options,
)


def test_find_binary_reports_available_when_on_path():
    status = find_binary("python3")

    assert status.available is True
    assert status.path is not None
    assert status.reason is None


def test_find_binary_reports_unavailable_with_reason_when_missing():
    status = find_binary("definitely-not-a-real-watson-tool-xyz")

    assert status.available is False
    assert status.path is None
    assert "not found on PATH" in status.reason


def test_find_binary_reports_pip_install_hint_when_missing_with_pip_package():
    status = find_binary("definitely-not-a-real-watson-tool-xyz", pip_package="some-package")

    assert status.available is False
    assert "pip install some-package" in status.reason


def test_find_binary_prints_venv_hint_when_pip_install_fails_externally_managed(monkeypatch, capsys):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    fake_result = subprocess.CompletedProcess(
        args=["pip", "install", "some-package"],
        returncode=1,
        stdout="error: externally-managed-environment\n",
    )
    monkeypatch.setattr("watson.tool_discovery.subprocess.run", lambda *a, **k: fake_result)

    status = find_binary("definitely-not-a-real-watson-tool-xyz", pip_package="some-package")

    assert status.available is False
    captured = capsys.readouterr()
    assert "PEP 668" in captured.out
    assert "python3 -m venv" in captured.out


def test_find_binary_prints_setuptools_hint_when_pip_install_fails_backend_unavailable(monkeypatch, capsys):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    fake_result = subprocess.CompletedProcess(
        args=["pip", "install", "some-package"],
        returncode=1,
        stdout="BackendUnavailable: Cannot import 'setuptools.build_meta'\n",
    )
    monkeypatch.setattr("watson.tool_discovery.subprocess.run", lambda *a, **k: fake_result)

    status = find_binary("definitely-not-a-real-watson-tool-xyz", pip_package="some-package")

    assert status.available is False
    captured = capsys.readouterr()
    assert "pip install --upgrade pip setuptools wheel" in captured.out


def test_find_binary_prints_no_hint_for_unrelated_pip_failure(monkeypatch, capsys):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    fake_result = subprocess.CompletedProcess(
        args=["pip", "install", "some-package"],
        returncode=1,
        stdout="ERROR: Could not find a version that satisfies the requirement some-package\n",
    )
    monkeypatch.setattr("watson.tool_discovery.subprocess.run", lambda *a, **k: fake_result)

    status = find_binary("definitely-not-a-real-watson-tool-xyz", pip_package="some-package")

    assert status.available is False
    captured = capsys.readouterr()
    assert "hint:" not in captured.out


def test_offer_pip_install_prints_captured_output_and_returns_true_on_success(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    fake_result = subprocess.CompletedProcess(
        args=["pip", "install", "some-package"],
        returncode=0,
        stdout="Successfully installed some-package-1.0\n",
    )
    monkeypatch.setattr("watson.tool_discovery.subprocess.run", lambda *a, **k: fake_result)

    from watson.tool_discovery import _offer_pip_install

    result = _offer_pip_install("some-tool", "some-package")

    assert result is True
    captured = capsys.readouterr()
    assert "Successfully installed some-package-1.0" in captured.out
    assert "hint:" not in captured.out


def test_check_stdlib_modules_reports_available_when_all_present():
    status = check_stdlib_modules(["os", "sys"])

    assert status.available is True
    assert status.reason is None


def test_check_stdlib_modules_reports_unavailable_with_missing_names_and_rebuild_hint():
    status = check_stdlib_modules(["os", "definitely_not_a_real_stdlib_module_xyz"])

    assert status.available is False
    assert "definitely_not_a_real_stdlib_module_xyz" in status.reason
    assert "rebuild" in status.reason.lower()


def test_find_binary_finds_tool_alongside_sys_executable_when_not_on_path(tmp_path, monkeypatch):
    venv_bin = tmp_path / "venv_bin"
    venv_bin.mkdir()
    fake_binary = venv_bin / "definitely-not-a-real-watson-tool-xyz"
    fake_binary.write_text("#!/bin/sh\necho hi\n")
    fake_binary.chmod(0o755)

    monkeypatch.setattr("watson.tool_discovery.sys.executable", str(venv_bin / "python"))
    monkeypatch.setattr("shutil.which", lambda name: None)

    status = find_binary("definitely-not-a-real-watson-tool-xyz")

    assert status.available is True
    assert status.path == str(fake_binary)


def test_find_binary_uses_override_path_when_given(tmp_path):
    fake_binary = tmp_path / "fake_tool"
    fake_binary.write_text("#!/bin/sh\necho hi\n")
    fake_binary.chmod(0o755)

    status = find_binary("fake_tool", override_path=str(fake_binary))

    assert status.available is True
    assert status.path == str(fake_binary)


def test_find_binary_reports_unavailable_when_override_path_missing(tmp_path):
    missing = tmp_path / "does_not_exist"

    status = find_binary("fake_tool", override_path=str(missing))

    assert status.available is False
    assert "does not exist" in status.reason


def test_find_module_reports_available_for_real_module():
    status = find_module("yara", "yara")

    assert status.available is True
    assert status.reason is None


def test_find_module_reports_unavailable_with_reason_when_missing():
    status = find_module("definitely-not-a-real-module", "definitely_not_a_real_module_xyz")

    assert status.available is False
    assert "not found" in status.reason


def test_find_module_reports_pip_install_hint_when_missing_with_pip_package():
    status = find_module(
        "definitely-not-a-real-module", "definitely_not_a_real_module_xyz", pip_package="some-package"
    )

    assert status.available is False
    assert "pip install some-package" in status.reason


def test_find_or_fetch_dir_uses_configured_path_when_given(tmp_path):
    configured = tmp_path / "my-rules"
    configured.mkdir()

    status = find_or_fetch_dir("yara rules", configured, cache_dir=tmp_path / "cache")

    assert status.available is True
    assert status.path == str(configured)
    assert status.reason is None


def test_find_or_fetch_dir_reports_unavailable_when_configured_path_missing(tmp_path):
    missing = tmp_path / "does-not-exist"

    status = find_or_fetch_dir("yara rules", missing, cache_dir=tmp_path / "cache")

    assert status.available is False
    assert "does not exist" in status.reason


def test_find_or_fetch_dir_uses_populated_cache_dir_without_prompting(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "a.yar").write_text("rule a { condition: true }")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when cache dir is already populated")

    monkeypatch.setattr("builtins.input", fail_if_called)

    status = find_or_fetch_dir(
        "yara rules", None, cache_dir=cache_dir, fetch_url="https://example.invalid/rules.git"
    )

    assert status.available is True
    assert status.path == str(cache_dir)


def test_find_or_fetch_dir_reports_fetch_hint_when_missing_and_not_interactive(tmp_path):
    status = find_or_fetch_dir(
        "yara rules", None, cache_dir=tmp_path / "cache", fetch_url="https://example.invalid/rules.git"
    )

    assert status.available is False
    assert "git clone" in status.reason


def test_find_or_fetch_dir_reports_manual_hint_when_missing_and_no_fetch_url(tmp_path):
    status = find_or_fetch_dir("capa signatures", None, cache_dir=tmp_path / "cache")

    assert status.available is False
    assert "provide a path manually" in status.reason


def test_find_or_fetch_dir_clones_when_confirmed_interactively(tmp_path, monkeypatch):
    origin = tmp_path / "origin"
    origin.mkdir()
    subprocess.run(["git", "init", "-q", str(origin)], check=True)
    (origin / "example.yar").write_text("rule example { condition: true }")
    subprocess.run(["git", "-C", str(origin), "add", "example.yar"], check=True)
    subprocess.run(
        [
            "git", "-C", str(origin),
            "-c", "user.email=test@test.com", "-c", "user.name=test",
            "commit", "-q", "-m", "init",
        ],
        check=True,
    )

    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    status = find_or_fetch_dir("yara rules", None, cache_dir=cache_dir, fetch_url=str(origin))

    assert status.available is True
    assert (cache_dir / "example.yar").is_file()


def test_find_or_fetch_dir_declines_when_user_says_no(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    status = find_or_fetch_dir(
        "yara rules", None, cache_dir=cache_dir, fetch_url="https://example.invalid/rules.git"
    )

    assert status.available is False
    assert not cache_dir.exists()


def test_find_or_fetch_dir_reports_unavailable_when_git_missing(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("shutil.which", lambda name: None)

    status = find_or_fetch_dir(
        "yara rules", None, cache_dir=cache_dir, fetch_url="https://example.invalid/rules.git"
    )

    assert status.available is False
    assert not cache_dir.exists()


def test_confirm_returns_false_when_not_interactive(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: False)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when not interactive")

    monkeypatch.setattr("builtins.input", fail_if_called)

    assert confirm("run floss?") is False


def test_confirm_returns_true_when_interactive_and_confirmed(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    assert confirm("run floss?") is True


def test_confirm_returns_false_when_interactive_and_declined(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    assert confirm("run floss?") is False


_OPTIONS = [("y", "yara scanning"), ("c", "capa detection"), ("f", "floss extraction")]


def test_select_options_returns_empty_selection_when_not_interactive(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: False)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when not interactive")

    monkeypatch.setattr("builtins.input", fail_if_called)

    result = select_options("pick some", _OPTIONS)

    assert result.keys == set()
    assert result.via_all_shorthand is False


def test_select_options_parses_multiple_letters(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yc")

    result = select_options("pick some", _OPTIONS)

    assert result.keys == {"y", "c"}
    assert result.via_all_shorthand is False


def test_select_options_all_key_selects_everything(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")

    result = select_options("pick some", _OPTIONS)

    assert result.keys == {"y", "c", "f"}
    assert result.via_all_shorthand is True


def test_select_options_typing_every_letter_individually_is_not_all_shorthand(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "ycf")

    result = select_options("pick some", _OPTIONS)

    assert result.keys == {"y", "c", "f"}
    assert result.via_all_shorthand is False


def test_select_options_blank_answer_selects_nothing(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "")

    result = select_options("pick some", _OPTIONS)

    assert result.keys == set()
    assert result.via_all_shorthand is False


def test_select_options_none_key_selects_nothing_even_if_mixed_in(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    result = select_options("pick some", _OPTIONS)

    assert result.keys == set()
    assert result.via_all_shorthand is False


def test_select_options_ignores_unknown_letters(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yz")

    result = select_options("pick some", _OPTIONS)

    assert result.keys == {"y"}
    assert result.via_all_shorthand is False


def _build_test_zip(binary_relpath: str, content: bytes = b"fake binary") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(binary_relpath, content)
    return buffer.getvalue()


def test_find_or_fetch_zip_binary_uses_populated_cache_without_prompting(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    (cache_dir / "tool").mkdir(parents=True)
    (cache_dir / "tool" / "bin.exe").write_text("already here")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not fetch when cache already has the binary")

    monkeypatch.setattr("watson.tool_discovery.urllib.request.urlopen", fail_if_called)

    status = find_or_fetch_zip_binary(
        "diec", "tool/bin.exe", cache_dir=cache_dir, archive_url="https://example.invalid/tool.zip"
    )

    assert status.available is True
    assert status.path == str(cache_dir / "tool" / "bin.exe")


def test_find_or_fetch_zip_binary_reports_unavailable_when_missing_and_not_interactive(tmp_path):
    status = find_or_fetch_zip_binary(
        "diec", "tool/bin.exe", cache_dir=tmp_path / "cache", archive_url="https://example.invalid/tool.zip"
    )

    assert status.available is False
    assert "not found locally" in status.reason


def test_find_or_fetch_zip_binary_reports_manual_hint_when_no_archive_url(tmp_path):
    status = find_or_fetch_zip_binary("diec", "tool/bin.exe", cache_dir=tmp_path / "cache", archive_url=None)

    assert status.available is False
    assert "install it manually" in status.reason


def test_find_or_fetch_zip_binary_downloads_and_extracts_when_confirmed(tmp_path, monkeypatch):
    zip_bytes = _build_test_zip("tool/bin.exe", b"fake binary contents")
    cache_dir = tmp_path / "cache"

    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    monkeypatch.setattr(
        "watson.tool_discovery.urllib.request.urlopen",
        lambda url, timeout=60: contextlib.closing(io.BytesIO(zip_bytes)),
    )

    status = find_or_fetch_zip_binary(
        "diec", "tool/bin.exe", cache_dir=cache_dir, archive_url="https://example.invalid/tool.zip"
    )

    assert status.available is True
    assert status.path == str(cache_dir / "tool" / "bin.exe")
    assert (cache_dir / "tool" / "bin.exe").read_bytes() == b"fake binary contents"


def test_find_or_fetch_zip_binary_declines_when_user_says_no(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not download when declined")

    monkeypatch.setattr("watson.tool_discovery.urllib.request.urlopen", fail_if_called)

    status = find_or_fetch_zip_binary(
        "diec", "tool/bin.exe", cache_dir=cache_dir, archive_url="https://example.invalid/tool.zip"
    )

    assert status.available is False
    assert not cache_dir.exists()


def test_find_or_fetch_zip_binary_handles_corrupt_zip_gracefully(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    monkeypatch.setattr(
        "watson.tool_discovery.urllib.request.urlopen",
        lambda url, timeout=60: contextlib.closing(io.BytesIO(b"not a real zip file")),
    )

    status = find_or_fetch_zip_binary(
        "diec", "tool/bin.exe", cache_dir=cache_dir, archive_url="https://example.invalid/tool.zip"
    )

    assert status.available is False
    assert status.reason is not None
