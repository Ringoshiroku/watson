import contextlib
import io
import subprocess
import zipfile

from watson.tool_discovery import (
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


def test_select_options_returns_empty_set_when_not_interactive(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: False)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when not interactive")

    monkeypatch.setattr("builtins.input", fail_if_called)

    assert select_options("pick some", _OPTIONS) == set()


def test_select_options_parses_multiple_letters(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yc")

    assert select_options("pick some", _OPTIONS) == {"y", "c"}


def test_select_options_all_key_selects_everything(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")

    assert select_options("pick some", _OPTIONS) == {"y", "c", "f"}


def test_select_options_blank_answer_selects_nothing(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "")

    assert select_options("pick some", _OPTIONS) == set()


def test_select_options_none_key_selects_nothing_even_if_mixed_in(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    assert select_options("pick some", _OPTIONS) == set()


def test_select_options_ignores_unknown_letters(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery.is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yz")

    assert select_options("pick some", _OPTIONS) == {"y"}


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
