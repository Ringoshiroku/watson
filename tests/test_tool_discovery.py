import subprocess

from watson.tool_discovery import confirm, find_binary, find_module, find_or_fetch_dir


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
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    status = find_or_fetch_dir("yara rules", None, cache_dir=cache_dir, fetch_url=str(origin))

    assert status.available is True
    assert (cache_dir / "example.yar").is_file()


def test_find_or_fetch_dir_declines_when_user_says_no(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    status = find_or_fetch_dir(
        "yara rules", None, cache_dir=cache_dir, fetch_url="https://example.invalid/rules.git"
    )

    assert status.available is False
    assert not cache_dir.exists()


def test_find_or_fetch_dir_reports_unavailable_when_git_missing(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)
    monkeypatch.setattr("shutil.which", lambda name: None)

    status = find_or_fetch_dir(
        "yara rules", None, cache_dir=cache_dir, fetch_url="https://example.invalid/rules.git"
    )

    assert status.available is False
    assert not cache_dir.exists()


def test_confirm_returns_false_when_not_interactive(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: False)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not prompt when not interactive")

    monkeypatch.setattr("builtins.input", fail_if_called)

    assert confirm("run floss?") is False


def test_confirm_returns_true_when_interactive_and_confirmed(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    assert confirm("run floss?") is True


def test_confirm_returns_false_when_interactive_and_declined(monkeypatch):
    monkeypatch.setattr("watson.tool_discovery._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    assert confirm("run floss?") is False
