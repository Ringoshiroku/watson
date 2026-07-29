from __future__ import annotations

from pathlib import Path


class YaraScanError(Exception):
    """Raised when a YARA rule file fails to compile or a scan fails."""


# Community rules (e.g. utils/domain.yar's `/([\w\.-]+)/`) are often loose
# enough to match single characters or the empty string all over a binary;
# without these bounds a single such rule can produce millions of instances.
_MIN_MATCH_LENGTH = 4
_MAX_INSTANCES_PER_IDENTIFIER = 20


def scan_file(file_path: Path, rules_dir: Path) -> list:
    import yara

    rule_files = sorted(
        set(Path(rules_dir).rglob("*.yar")) | set(Path(rules_dir).rglob("*.yara"))
    )
    if not rule_files:
        return []

    filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
    try:
        ruleset = yara.compile(filepaths=filepaths)
    except yara.Error:
        # One or more individual rule files are broken (common in large community
        # rule repos). Test-compile each file on its own to find which ones are
        # broken, then do a single batch recompile of just the good files.
        # Keeping each file as its own separate compiled Rules object (the
        # previous approach here) multiplies libyara's per-object overhead by
        # the file count: on the default community ruleset (500+ files) that
        # reached multiple gigabytes of memory and could get the process
        # OOM-killed, versus tens of megabytes for one batch compile of the
        # same rules.
        good_files = []
        errors = []
        for rule_file in rule_files:
            try:
                yara.compile(filepath=str(rule_file))
                good_files.append(rule_file)
            except yara.Error as exc:
                errors.append(f"{rule_file}: {exc}")
        if not good_files:
            raise YaraScanError("; ".join(errors))
        good_filepaths = {f"rule_{i}": str(f) for i, f in enumerate(good_files)}
        try:
            ruleset = yara.compile(filepaths=good_filepaths)
        except yara.Error as exc:
            raise YaraScanError(str(exc)) from exc

    try:
        matches = ruleset.match(str(file_path))
    except yara.Error as exc:
        raise YaraScanError(str(exc)) from exc

    results = []
    for match in matches:
        if match.meta.get("hide"):
            continue

        by_identifier = {}
        for string_match in match.strings:
            for instance in string_match.instances:
                matched_data = instance.matched_data.decode("utf-8", errors="replace")
                if len(matched_data) < _MIN_MATCH_LENGTH:
                    continue
                by_identifier.setdefault(string_match.identifier, []).append(
                    {
                        "identifier": string_match.identifier,
                        "offset": instance.offset,
                        "matched_data": matched_data,
                    }
                )

        flattened = []
        for identifier, instances in by_identifier.items():
            kept = instances[:_MAX_INSTANCES_PER_IDENTIFIER]
            flattened.extend(kept)
            suppressed = len(instances) - len(kept)
            if suppressed > 0:
                flattened.append(
                    {
                        "identifier": identifier,
                        "offset": None,
                        "matched_data": f"...{suppressed} more instance(s) suppressed",
                    }
                )

        if not flattened:
            continue

        results.append({"rule": match.rule, "tags": list(match.tags), "matches": flattened})

    return results
