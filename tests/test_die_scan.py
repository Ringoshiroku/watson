import shutil
from pathlib import Path

import pytest

from watson import die_scan
from watson.die_scan import DieScanError, scan_file

requires_diec = pytest.mark.skipif(shutil.which("diec") is None, reason="diec not installed")


@requires_diec
def test_scan_file_returns_detections_for_compiled_pe(compiled_pe):
    detections = scan_file(compiled_pe)

    assert isinstance(detections, list)
    assert len(detections) >= 1
    assert "filetype" in detections[0]
    assert "values" in detections[0]


@requires_diec
def test_scan_file_raises_die_scan_error_for_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.exe"

    with pytest.raises(DieScanError):
        scan_file(missing)


def test_parse_json_returns_dict_on_valid_json():
    assert die_scan._parse_json('{"detects": []}') == {"detects": []}


def test_parse_json_raises_die_scan_error_on_top_level_array():
    with pytest.raises(DieScanError):
        die_scan._parse_json("[1, 2, 3]")


def test_parse_json_recovers_from_leaked_prefix_text():
    assert die_scan._parse_json('some heuristic scan text\n{"detects": []}') == {"detects": []}


def test_parse_json_raises_die_scan_error_on_completely_invalid_output():
    with pytest.raises(DieScanError):
        die_scan._parse_json("not json at all, no braces here")


def test_reshape_detects_skips_non_dict_entries():
    data = {
        "detects": [
            "not a dict",
            {
                "filetype": "PE64",
                "values": [
                    "not a dict",
                    {"type": "Packer", "name": "UPX", "version": "3.96", "string": None},
                ],
            },
        ]
    }

    assert die_scan._reshape_detects(data) == [
        {"filetype": "PE64", "values": [{"type": "Packer", "name": "UPX", "version": "3.96", "string": None}]}
    ]


def test_reshape_detects_handles_missing_keys_gracefully():
    data = {"detects": [{"values": [{}]}]}

    assert die_scan._reshape_detects(data) == [
        {"filetype": None, "values": [{"type": None, "name": None, "version": None, "string": None}]}
    ]


def test_scan_file_raises_die_scan_error_for_unusable_binary_path(tmp_path):
    fake_file = tmp_path / "sample.bin"
    fake_file.write_bytes(b"not a real PE")
    missing_binary = tmp_path / "does-not-exist-diec"

    with pytest.raises(DieScanError):
        scan_file(fake_file, diec_binary=str(missing_binary))
