from __future__ import annotations

import re

# Checked in this order; the first pattern that matches wins (a string is
# tagged with one reason, even if it could technically match more than one).
_PATTERNS = (
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("url", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://\S+")),
    ("registry_key", re.compile(r"\bHKEY_[A-Z_]+\\\S*")),
    ("windows_path", re.compile(r"\b[A-Za-z]:\\\S+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)


def find_interesting_strings(strings: list) -> list:
    interesting = []
    for entry in strings:
        text = entry["string"]
        for reason, pattern in _PATTERNS:
            if pattern.search(text):
                interesting.append({"string": text, "source": entry["source"], "reason": reason})
                break
    return interesting
