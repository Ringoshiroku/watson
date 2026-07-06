import shutil
from pathlib import Path

import pytest

from watson.capa_scan import CapaScanError, scan_file

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
