from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager


@contextmanager
def stage(label: str, poll_interval: float = 0.2):
    live = sys.stdout.isatty()
    start = time.monotonic()
    print(f"running {label}...", end="\n" if not live else "", flush=True)

    stop_event = threading.Event()
    thread = None

    def _redraw() -> None:
        while not stop_event.wait(poll_interval):
            elapsed = time.monotonic() - start
            print(f"\rrunning {label}... {elapsed:.0f}s", end="", flush=True)

    if live:
        thread = threading.Thread(target=_redraw, daemon=True)
        thread.start()

    try:
        yield
    except BaseException:
        stop_event.set()
        if thread is not None:
            thread.join()
            print("\r" + " " * (len(label) + 24) + "\r", end="", flush=True)
        raise

    stop_event.set()
    if thread is not None:
        thread.join()

    elapsed = time.monotonic() - start
    prefix = "\r" if live else ""
    print(f"{prefix}done: {label} ({elapsed:.1f}s)" + " " * 10)
