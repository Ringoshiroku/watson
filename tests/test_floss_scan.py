import json
import shutil
from pathlib import Path

import pytest

from watson.floss_scan import FlossScanError, flatten_strings, save_raw_output, scan_file

requires_floss = pytest.mark.skipif(shutil.which("floss") is None, reason="floss not installed")


@requires_floss
def test_scan_file_returns_raw_strings_for_compiled_pe(compiled_pe):
    raw = scan_file(compiled_pe)

    assert "strings" in raw
    static_strings = [entry["string"] for entry in raw["strings"]["static_strings"]]
    assert "hello from watson test fixture" in static_strings


@requires_floss
def test_scan_file_raises_floss_scan_error_for_non_pe_file(tmp_path):
    bad_file = tmp_path / "not_a_pe.bin"
    bad_file.write_bytes(b"not a pe file at all")

    with pytest.raises(FlossScanError):
        scan_file(bad_file)


def test_flatten_strings_tags_each_entry_with_its_source():
    raw = {
        "strings": {
            "static_strings": [{"string": "static one", "encoding": "ASCII", "offset": 0}],
            "stack_strings": [{"string": "stack one"}],
            "tight_strings": [{"string": "tight one"}],
            "decoded_strings": [{"string": "decoded one"}],
        }
    }

    flattened = flatten_strings(raw)

    assert flattened == [
        {"string": "static one", "source": "static_strings"},
        {"string": "stack one", "source": "stack_strings"},
        {"string": "tight one", "source": "tight_strings"},
        {"string": "decoded one", "source": "decoded_strings"},
    ]


def test_save_raw_output_writes_json_file(tmp_path):
    raw = {"strings": {"static_strings": []}}

    out_path = save_raw_output(raw, tmp_path, "a" * 64)

    assert out_path == tmp_path / (("a" * 64) + "_floss.json")
    assert json.loads(out_path.read_text()) == raw
