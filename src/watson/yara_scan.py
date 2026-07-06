from __future__ import annotations

from pathlib import Path


class YaraScanError(Exception):
    """Raised when a YARA rule file fails to compile or a scan fails."""


def scan_file(file_path: Path, rules_dir: Path) -> list:
    import yara

    rule_files = sorted(Path(rules_dir).glob("*.yar"))
    if not rule_files:
        return []

    filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
    try:
        compiled = yara.compile(filepaths=filepaths)
        matches = compiled.match(str(file_path))
    except yara.Error as exc:
        raise YaraScanError(str(exc)) from exc

    return [
        {
            "rule": match.rule,
            "tags": list(match.tags),
            "matches": [
                {
                    "identifier": string_match.identifier,
                    "offset": instance.offset,
                    "matched_data": instance.matched_data.decode("utf-8", errors="replace"),
                }
                for string_match in match.strings
                for instance in string_match.instances
            ],
        }
        for match in matches
    ]
