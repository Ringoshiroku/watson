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

_PATTERNS = (
    ("url", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://\S+")),
    ("registry_key", re.compile(r"\bHKEY_[A-Z_]+\\\S*")),
    ("windows_path", re.compile(r"\b[A-Za-z]:\\\S+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("user_agent", re.compile(r"\b[A-Za-z][A-Za-z0-9_.-]*/[0-9][\w.]*\s*\([^()]*\)")),
)

# label.label...tld shaped. On its own this is far too broad, it matches
# .NET/Java namespace strings (System.Windows.Forms) and filenames
# (readme.txt) just as readily as real domains; the TLD-membership check in
# _find_matches is what actually distinguishes a domain from either of
# those, since "Forms"/"txt" aren't in _KNOWN_TLDS.
_DOMAIN_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_DOMAIN_CANDIDATE = re.compile(rf"\b(?:{_DOMAIN_LABEL}\.)+[a-zA-Z]{{2,24}}\b")

# A pragmatic floor, not an IANA-complete registry, same spirit as
# _KNOWN_OID_PREFIXES above: common gTLDs plus ccTLDs actually seen in
# malware infrastructure and legitimate traffic.
_KNOWN_TLDS = frozenset({
    "com", "net", "org", "info", "biz", "name", "pro", "mobi",
    "io", "co", "me", "tv", "cc", "ws", "app", "dev", "cloud",
    "online", "site", "xyz", "top", "club", "live", "link", "click",
    "work", "icu", "buzz", "monster", "fun", "space", "store", "tech",
    "shop", "vip", "win", "bid", "loan", "download", "stream",
    "gq", "ga", "cf", "ml", "tk",
    "gov", "edu", "mil", "int",
    "us", "uk", "ca", "au", "de", "fr", "jp", "cn", "ru", "in",
    "br", "it", "es", "nl", "se", "no", "dk", "fi", "pl", "tr",
    "ir", "kr", "mx", "za", "ch", "at", "be", "pt", "gr", "cz",
    "hu", "ro", "bg", "ua", "by", "kz", "su", "tw", "hk", "sg",
    "my", "id", "vn", "th", "ph", "nz", "ie", "is", "lu", "li",
    "sk", "si", "hr", "rs", "lt", "lv", "ee", "md", "ge", "am",
    "az", "uz", "pk", "bd", "lk", "np", "kh", "la", "mm", "mn",
    "ae", "sa", "il", "eg", "ng", "ke", "gh", "tz", "ug", "ma",
    "dz", "tn", "ly", "sc", "mu", "cy", "mt", "al", "mk", "ba",
})

# Safety valve: a pathological blob (e.g. an embedded resource with many
# digit-dot runs) shouldn't be able to produce an unbounded number of
# entries from one source string.
_MAX_MATCHES_PER_STRING = 20


def _find_matches(text: str) -> list:
    spans = []  # (start, end, reason, value), in the order patterns are checked

    def _overlaps(start, end):
        return any(not (end <= s or start >= e) for s, e, _, _ in spans)

    for candidate_match in _DOTTED_RUN.finditer(text):
        candidate = candidate_match.group()
        segments = candidate.split(".")
        if len(segments) != 4:
            continue
        if candidate.startswith(_KNOWN_OID_PREFIXES):
            continue
        try:
            ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        spans.append((candidate_match.start(), candidate_match.end(), "ip", candidate))

    for reason, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            if _overlaps(match.start(), match.end()):
                continue
            spans.append((match.start(), match.end(), reason, match.group()))

    for match in _DOMAIN_CANDIDATE.finditer(text):
        tld = match.group().rsplit(".", 1)[-1].lower()
        if tld not in _KNOWN_TLDS:
            continue
        if _overlaps(match.start(), match.end()):
            continue
        spans.append((match.start(), match.end(), "domain", match.group()))

    spans.sort(key=lambda item: item[0])
    return [(reason, value) for _, _, reason, value in spans[:_MAX_MATCHES_PER_STRING]]


def find_interesting_strings(strings: list) -> list:
    interesting = []
    for entry in strings:
        text = entry["string"]
        source = entry["source"]
        matches = _find_matches(text)
        if len(text) <= _MAX_INTERESTING_LENGTH:
            seen_reasons = set()
            for reason, _ in matches:
                if reason in seen_reasons:
                    continue
                seen_reasons.add(reason)
                interesting.append({"string": text, "source": source, "reason": reason})
        else:
            seen_values = set()
            for reason, value in matches:
                key = (reason, value)
                if key in seen_values:
                    continue
                seen_values.add(key)
                interesting.append({"string": value, "source": source, "reason": reason})
    return interesting
