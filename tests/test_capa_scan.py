import shutil
from pathlib import Path

import pytest

from watson.capa_scan import CapaScanError, _extract_evidence, scan_file

RULES_DIR = Path(__file__).parent / "fixtures" / "capa_rules"

requires_capa = pytest.mark.skipif(shutil.which("capa") is None, reason="capa not installed")


@requires_capa
def test_scan_file_finds_match_in_compiled_pe(compiled_pe):
    matches = scan_file(compiled_pe, RULES_DIR)

    assert len(matches) == 1
    assert matches[0]["rule"] == "watson test fixture string"
    assert matches[0]["namespace"] == "watson/test"
    assert matches[0]["attack"] == []
    assert matches[0]["mbc"] == []
    assert matches[0]["evidence"] == [
        {
            "feature": "string",
            "value": "hello from watson test fixture",
            "addresses": [{"type": "file", "value": 30208}],
            "more_addresses": 0,
        }
    ]


@requires_capa
def test_scan_file_raises_capa_scan_error_for_empty_rules_dir(tmp_path, compiled_pe):
    empty_rules_dir = tmp_path / "empty_rules"
    empty_rules_dir.mkdir()

    with pytest.raises(CapaScanError):
        scan_file(compiled_pe, empty_rules_dir)


@requires_capa
def test_scan_file_raises_capa_scan_error_for_malformed_rule(tmp_path, compiled_pe):
    bad_rules_dir = tmp_path / "bad_rules"
    bad_rules_dir.mkdir()
    (bad_rules_dir / "bad.yml").write_text(
        "rule:\n  meta:\n    name: broken rule\n  features:\n    - not_a_real_feature_type: nonsense\n"
    )

    with pytest.raises(CapaScanError):
        scan_file(compiled_pe, bad_rules_dir)


def test_extract_evidence_keeps_only_successful_leaves():
    matches = [
        [
            {"type": "no address"},
            {
                "success": True,
                "node": {"type": "statement", "statement": {"type": "or"}},
                "children": [
                    {
                        "success": False,
                        "node": {"type": "feature", "feature": {"type": "os", "os": "linux"}},
                        "children": [],
                        "locations": [],
                    },
                    {
                        "success": True,
                        "node": {"type": "feature", "feature": {"type": "api", "api": "Sleep"}},
                        "children": [],
                        "locations": [{"type": "absolute", "value": 5368713662}],
                    },
                ],
            },
        ]
    ]

    evidence = _extract_evidence(matches)

    assert evidence == [
        {
            "feature": "api",
            "value": "Sleep",
            "addresses": [{"type": "absolute", "value": 5368713662}],
            "more_addresses": 0,
        }
    ]


def test_extract_evidence_handles_a_single_feature_leaf_as_the_whole_tree():
    matches = [
        [
            {"type": "no address"},
            {
                "success": True,
                "node": {
                    "type": "feature",
                    "feature": {"type": "string", "string": "hello from watson test fixture"},
                },
                "children": [],
                "locations": [{"type": "file", "value": 30208}],
            },
        ]
    ]

    evidence = _extract_evidence(matches)

    assert evidence == [
        {
            "feature": "string",
            "value": "hello from watson test fixture",
            "addresses": [{"type": "file", "value": 30208}],
            "more_addresses": 0,
        }
    ]


def test_extract_evidence_caps_addresses_per_feature_at_five():
    locations = [{"type": "absolute", "value": i} for i in range(7)]
    matches = [
        [
            {"type": "no address"},
            {
                "success": True,
                "node": {"type": "feature", "feature": {"type": "api", "api": "Sleep"}},
                "children": [],
                "locations": locations,
            },
        ]
    ]

    evidence = _extract_evidence(matches)

    assert evidence[0]["addresses"] == [{"type": "absolute", "value": i} for i in range(5)]
    assert evidence[0]["more_addresses"] == 2


def test_extract_evidence_caps_total_entries_per_rule_at_five():
    def leaf(n):
        return [
            {"type": "no address"},
            {
                "success": True,
                "node": {"type": "feature", "feature": {"type": "number", "number": n}},
                "children": [],
                "locations": [],
            },
        ]

    matches = [leaf(n) for n in range(7)]

    evidence = _extract_evidence(matches)

    assert len(evidence) == 5


def test_extract_evidence_is_defensive_against_malformed_tree_shapes():
    matches = [
        "not a list",
        [1, 2, 3],
        [{"type": "no address"}, "not a dict"],
        [
            {"type": "no address"},
            {"success": True, "node": "not a dict", "children": [], "locations": []},
        ],
        [
            {"type": "no address"},
            {
                "success": True,
                "node": {"type": "feature", "feature": "not a dict"},
                "children": [],
                "locations": [],
            },
        ],
        [
            {"type": "no address"},
            {
                "success": True,
                "node": {"type": "statement", "statement": {"type": "and"}},
                "children": "not a list",
                "locations": [],
            },
        ],
    ]

    evidence = _extract_evidence(matches)

    assert evidence == []
