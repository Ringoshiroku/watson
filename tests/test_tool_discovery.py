from watson.tool_discovery import find_binary, find_module


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
