import shutil
from pathlib import Path

import pytest

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
