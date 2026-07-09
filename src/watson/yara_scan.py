from __future__ import annotations

from pathlib import Path


class YaraScanError(Exception):
    """Raised when a YARA rule file fails to compile or a scan fails."""


def scan_file(file_path: Path, rules_dir: Path) -> list:
    import yara

    rule_files = sorted(
        set(Path(rules_dir).rglob("*.yar")) | set(Path(rules_dir).rglob("*.yara"))
    )
    if not rule_files:
        return []

    filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
    try:
        rulesets = [yara.compile(filepaths=filepaths)]
    except yara.Error:
        # One or more individual rule files are broken (common in large community
        # rule repos); fall back to compiling each file on its own and skip only
        # the ones that fail, rather than losing every rule in the directory.
        # This does mean cross-file `include` references won't resolve in the
        # fallback path, only the all-good batch compile above preserves those.
        rulesets = []
        errors = []
        for rule_file in rule_files:
            try:
                rulesets.append(yara.compile(filepath=str(rule_file)))
            except yara.Error as exc:
                errors.append(f"{rule_file}: {exc}")
        if not rulesets:
            raise YaraScanError("; ".join(errors))

    try:
        matches = [match for ruleset in rulesets for match in ruleset.match(str(file_path))]
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
