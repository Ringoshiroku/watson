from __future__ import annotations

import ipaddress
import re

# Interesting strings are short, standalone tokens (an IP, a path, a URL).
# Longer strings are usually boilerplate (CLI usage help, license text) that
# happens to contain a matching substring, not a useful IOC on its own.
_MAX_INTERESTING_LENGTH = 200

# A run of 4+ dot-separated numeric groups. Only checked as a candidate IP
# when the *whole* run is exactly 4 groups; a longer run (an X.509/ASN.1 OID
# like "1.3.6.1.5.5.7.3.1") contains a matching 4-group substring under a
# naive check but isn't an IP, and .NET assembly version strings like
# "1.0.0.0" are structurally indistinguishable from a real IP by this check
# alone (a known residual false-positive, not fixable by regex/octet
# validation).
_DOTTED_RUN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3,}\b")

# Standard ASN.1/X.509 OID arcs common enough in any crypto-touching binary
# (X.500 attribute types, X.509v3 extensions, PKIX, RSA/PKCS, NIST/OIW
# algorithm identifiers, Microsoft's enterprise arc) to be worth excluding by
# name; some of these arcs happen to be exactly 4 segments with in-range
# values, so they pass the ip check above with no other way to tell them
# apart. Not an exhaustive OID registry, just the prefixes actually observed
# causing noise.
_KNOWN_OID_PREFIXES = (
    "2.5.4.",
    "2.5.29.",
    "1.2.840.113549.",
    "1.2.840.10040.",
    "1.2.840.10045.",
    "1.3.6.1.5.5.7.",
    "1.3.14.3.2.",
    "2.16.840.1.101.3.4.",
    "1.3.6.1.4.1.311.",
)

# Checked in this order after the ip check; the first pattern that matches
# wins (a string is tagged with one reason, even if it could technically
# match more than one).
_PATTERNS = (
    ("url", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://\S+")),
    ("registry_key", re.compile(r"\bHKEY_[A-Z_]+\\\S*")),
    ("windows_path", re.compile(r"\b[A-Za-z]:\\\S+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)


def _looks_like_ip(text: str) -> bool:
    for match in _DOTTED_RUN.finditer(text):
        candidate = match.group()
        segments = candidate.split(".")
        if len(segments) != 4:
            continue
        if candidate.startswith(_KNOWN_OID_PREFIXES):
            continue
        try:
            ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        return True
    return False


def find_interesting_strings(strings: list) -> list:
    interesting = []
    for entry in strings:
        text = entry["string"]
        if len(text) > _MAX_INTERESTING_LENGTH:
            continue
        if _looks_like_ip(text):
            interesting.append({"string": text, "source": entry["source"], "reason": "ip"})
            continue
        for reason, pattern in _PATTERNS:
            if pattern.search(text):
                interesting.append({"string": text, "source": entry["source"], "reason": reason})
                break
    return interesting
