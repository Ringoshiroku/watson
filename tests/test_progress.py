import re
import time

import pytest

from watson import progress


def test_stage_non_tty_prints_start_and_done_lines(capsys, monkeypatch):
    monkeypatch.setattr(progress.sys.stdout, "isatty", lambda: False)

    with progress.stage("test stage"):
        pass

    captured = capsys.readouterr()
    assert "running test stage...\n" in captured.out
    assert re.search(r"done: test stage \(\d+\.\d+s\)", captured.out)


def test_stage_non_tty_has_no_carriage_return_redraw(capsys, monkeypatch):
    monkeypatch.setattr(progress.sys.stdout, "isatty", lambda: False)

    with progress.stage("test stage"):
        pass

    captured = capsys.readouterr()
    assert "\r" not in captured.out


def test_stage_propagates_exception_and_skips_done_line(capsys, monkeypatch):
    monkeypatch.setattr(progress.sys.stdout, "isatty", lambda: False)

    with pytest.raises(ValueError, match="boom"):
        with progress.stage("test stage"):
            raise ValueError("boom")

    captured = capsys.readouterr()
    assert "running test stage...\n" in captured.out
    assert "done:" not in captured.out


def test_stage_tty_live_updates_and_prints_done_line(capsys, monkeypatch):
    monkeypatch.setattr(progress.sys.stdout, "isatty", lambda: True)

    with progress.stage("test stage", poll_interval=0.01):
        time.sleep(0.05)

    captured = capsys.readouterr()
    assert "\r" in captured.out
    assert re.search(r"done: test stage \(\d+\.\d+s\)", captured.out)
