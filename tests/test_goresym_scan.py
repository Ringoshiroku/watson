import json
import subprocess

import pytest

from watson.goresym_scan import (
    GoReSymScanError,
    extract_build_info,
    save_goresym_raw,
    scan_file,
)


def test_scan_file_returns_parsed_json(tmp_path, monkeypatch):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"not actually a pe, just a path to pass around")

    class FakeResult:
        returncode = 0
        stdout = '{"BuildInfo": {"GoVersion": "go1.24.4"}}'
        stderr = ""

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return FakeResult()

    monkeypatch.setattr("watson.goresym_scan.subprocess.run", fake_run)

    result = scan_file(target, goresym_binary="GoReSym")

    assert result == {"BuildInfo": {"GoVersion": "go1.24.4"}}
    assert calls == [["GoReSym", "-t", "-p", str(target)]]


def test_scan_file_returns_error_response_for_non_go_binary_without_raising(tmp_path, monkeypatch):
    # verified real GoReSym behavior against a non-Go binary: exit code 1,
    # clean JSON {"error": "..."} on stdout, nothing on stderr. This is a
    # normal outcome, not a tool failure.
    target = tmp_path / "sample.exe"
    target.write_bytes(b"not a go binary")

    class FakeResult:
        returncode = 1
        stdout = '{"error": "Failed to parse file: no valid pclntab found"}'
        stderr = ""

    monkeypatch.setattr("watson.goresym_scan.subprocess.run", lambda cmd, **kwargs: FakeResult())

    result = scan_file(target, goresym_binary="GoReSym")

    assert result == {"error": "Failed to parse file: no valid pclntab found"}


def test_scan_file_raises_on_invalid_json(tmp_path, monkeypatch):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"x")

    class FakeResult:
        returncode = 0
        stdout = "not json at all"
        stderr = ""

    monkeypatch.setattr("watson.goresym_scan.subprocess.run", lambda cmd, **kwargs: FakeResult())

    with pytest.raises(GoReSymScanError):
        scan_file(target, goresym_binary="GoReSym")


def test_scan_file_raises_on_timeout(tmp_path, monkeypatch):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"x")

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))

    monkeypatch.setattr("watson.goresym_scan.subprocess.run", fake_run)

    with pytest.raises(GoReSymScanError):
        scan_file(target, goresym_binary="GoReSym", timeout=5)


def test_scan_file_raises_on_missing_binary(tmp_path, monkeypatch):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"x")

    def fake_run(cmd, **kwargs):
        raise OSError("no such file or directory")

    monkeypatch.setattr("watson.goresym_scan.subprocess.run", fake_run)

    with pytest.raises(GoReSymScanError):
        scan_file(target, goresym_binary="/does/not/exist")


def test_extract_build_info_returns_none_for_error_response():
    raw = {"error": "Failed to parse file: no valid pclntab found"}

    assert extract_build_info(raw) is None


def test_extract_build_info_returns_none_when_buildinfo_missing():
    raw = {"BuildInfo": {}, "UserFunctions": []}

    assert extract_build_info(raw) is None


def test_extract_build_info_recovers_from_pclntab_when_buildinfo_stripped():
    # real scenario verified live: buildinfo section wiped (a common, trivial
    # evasion technique), so BuildInfo has no GoVersion, but GoReSym still
    # recovers a top-level Version and real UserFunctions via pclntab parsing
    raw = {
        "BuildInfo": {},
        "Version": "go1.24.4",
        "UserFunctions": [
            {"PackageName": "main", "FullName": "main.main"},
        ],
    }

    result = extract_build_info(raw)

    assert result is not None
    assert result["go_version"] == "go1.24.4"
    assert result["packages"] == {"main": ["main.main"]}


def test_extract_build_info_builds_expected_shape():
    # based on real GoReSym output captured this session (a binary with a
    # local-module dependency wired via a go.mod replace directive)
    raw = {
        "BuildInfo": {
            "GoVersion": "go1.24.4",
            "Path": "watsontestbin",
            "Main": {"Path": "watsontestbin", "Version": "(devel)"},
            "Deps": [
                {"Path": "github.com/example/examplelib", "Version": "v0.0.0"},
            ],
        },
        "UserFunctions": [],
    }

    result = extract_build_info(raw)

    assert result == {
        "go_version": "go1.24.4",
        "module_path": "watsontestbin",
        "module_version": "(devel)",
        "dependencies": [{"path": "github.com/example/examplelib", "version": "v0.0.0"}],
        "packages": {},
    }


def test_extract_build_info_filters_packages_to_own_module_and_declared_deps():
    # real false-inclusion class found live this session: GoReSym's own
    # std/user split let internal runtime packages leak into UserFunctions
    # on newer Go versions
    raw = {
        "BuildInfo": {
            "GoVersion": "go1.24.4",
            "Path": "watsontestbin",
            "Main": {"Path": "watsontestbin", "Version": "(devel)"},
            "Deps": [{"Path": "github.com/example/examplelib", "Version": "v0.0.0"}],
        },
        "UserFunctions": [
            {"PackageName": "main", "FullName": "main.main"},
            {
                "PackageName": "github.com/example/examplelib",
                "FullName": "github.com/example/examplelib.Shout",
            },
            {
                "PackageName": "internal/runtime/maps",
                "FullName": "internal/runtime/maps.NewMap",
            },
            {"PackageName": "runtime", "FullName": "runtime.newobject"},
        ],
    }

    result = extract_build_info(raw)

    assert result["packages"] == {
        "main": ["main.main"],
        "github.com/example/examplelib": ["github.com/example/examplelib.Shout"],
    }


def test_extract_build_info_dedupes_and_sorts_function_names_per_package():
    raw = {
        "BuildInfo": {
            "GoVersion": "go1.24.4",
            "Path": "watsontestbin",
            "Main": {"Path": "watsontestbin", "Version": "(devel)"},
            "Deps": [],
        },
        "UserFunctions": [
            {"PackageName": "main", "FullName": "main.zebra"},
            {"PackageName": "main", "FullName": "main.apple"},
            {"PackageName": "main", "FullName": "main.zebra"},
        ],
    }

    result = extract_build_info(raw)

    assert result["packages"] == {"main": ["main.apple", "main.zebra"]}


def test_save_goresym_raw_writes_json_file(tmp_path):
    raw = {"BuildInfo": {"GoVersion": "go1.24.4"}}

    out_path = save_goresym_raw(raw, tmp_path, "12-00-00-01-01-2026-sample-exe-deadbeef")

    assert out_path == tmp_path / "12-00-00-01-01-2026-sample-exe-deadbeef_goresym.json"
    assert json.loads(out_path.read_text()) == raw
