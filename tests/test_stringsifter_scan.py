import json

import pytest

from watson.stringsifter_scan import (
    StringSifterError,
    _parse_ranked_output,
    _prepare_input,
    rank_strings,
    save_ranked_strings,
)


def test_prepare_input_joins_strings_and_maps_source():
    strings = [
        {"string": "http://evil.example/payload", "source": "decoded_strings"},
        {"string": "GetProcAddress", "source": "static_strings"},
    ]

    stdin_text, source_by_text = _prepare_input(strings)

    assert stdin_text == "http://evil.example/payload\nGetProcAddress"
    assert source_by_text == {
        "http://evil.example/payload": "decoded_strings",
        "GetProcAddress": "static_strings",
    }


def test_prepare_input_excludes_strings_containing_newlines():
    strings = [
        {"string": "line one\nline two", "source": "decoded_strings"},
        {"string": "clean string", "source": "static_strings"},
    ]

    stdin_text, source_by_text = _prepare_input(strings)

    assert stdin_text == "clean string"
    assert "line one\nline two" not in stdin_text
    # still recorded in the source map even though excluded from ranking
    assert source_by_text["line one\nline two"] == "decoded_strings"


def test_prepare_input_last_write_wins_for_duplicate_text():
    strings = [
        {"string": "dup", "source": "static_strings"},
        {"string": "dup", "source": "stack_strings"},
    ]

    _, source_by_text = _prepare_input(strings)

    assert source_by_text["dup"] == "stack_strings"


def test_parse_ranked_output_sorts_by_score_descending():
    stdout = "10.00,low\n99.50,high\n50.25,mid\n"
    source_by_text = {"low": "static_strings", "high": "decoded_strings", "mid": "stack_strings"}

    ranked = _parse_ranked_output(stdout, source_by_text)

    assert [entry["string"] for entry in ranked] == ["high", "mid", "low"]
    assert ranked[0] == {"string": "high", "source": "decoded_strings", "score": 99.50}


def test_parse_ranked_output_handles_string_containing_a_comma():
    stdout = "12.34,a, b, c\n"
    source_by_text = {"a, b, c": "static_strings"}

    ranked = _parse_ranked_output(stdout, source_by_text)

    assert ranked == [{"string": "a, b, c", "source": "static_strings", "score": 12.34}]


def test_parse_ranked_output_skips_malformed_lines():
    stdout = "not a score line\n42.00,fine\n"
    source_by_text = {"fine": "static_strings"}

    ranked = _parse_ranked_output(stdout, source_by_text)

    assert ranked == [{"string": "fine", "source": "static_strings", "score": 42.00}]


def test_parse_ranked_output_uses_unknown_source_for_unmapped_text():
    stdout = "5.00,mystery\n"

    ranked = _parse_ranked_output(stdout, {})

    assert ranked == [{"string": "mystery", "source": "unknown", "score": 5.00}]


def test_rank_strings_returns_empty_list_for_empty_input():
    ranked = rank_strings([], binary="does-not-matter-not-invoked")

    assert ranked == []


def test_rank_strings_raises_string_sifter_error_for_unusable_binary(tmp_path):
    missing_binary = tmp_path / "does-not-exist-rank-strings"

    with pytest.raises(StringSifterError):
        rank_strings([{"string": "sample", "source": "static_strings"}], binary=str(missing_binary))


def test_save_ranked_strings_writes_json_file(tmp_path):
    ranked = [{"string": "http://evil.example", "source": "decoded_strings", "score": 88.5}]

    out_path = save_ranked_strings(ranked, tmp_path, "12-00-00-01-01-2026-sample-exe-deadbeef")

    assert out_path == tmp_path / "12-00-00-01-01-2026-sample-exe-deadbeef_ranked_strings.json"
    assert json.loads(out_path.read_text()) == ranked
