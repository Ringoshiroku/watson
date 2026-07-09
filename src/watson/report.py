from __future__ import annotations

from watson.case import Case


def build_json_report(case: Case) -> dict:
    report = case.to_dict()
    report["summary"] = _build_summary(case)
    return report


def _format_mapping_entry(entry) -> str:
    if isinstance(entry, str):
        return entry
    parts = entry.get("parts") or []
    label = "::".join(parts) if parts else entry.get("name", str(entry))
    entry_id = entry.get("id")
    return f"{label} [{entry_id}]" if entry_id else label


def _attack_tactic(entry) -> str:
    if isinstance(entry, str):
        return entry.split("::", 1)[0] if "::" in entry else "Ungrouped"
    parts = entry.get("parts") or []
    return entry.get("tactic") or (parts[0] if parts else "Ungrouped")


def _capability_tactics(capability: dict) -> list:
    attack = capability.get("attack") or []
    if not attack:
        return ["Ungrouped"]
    tactics = []
    for entry in attack:
        tactic = _attack_tactic(entry)
        if tactic not in tactics:
            tactics.append(tactic)
    return tactics


def _group_capabilities_by_tactic(capabilities: list) -> dict:
    grouped: dict = {}
    for capability in capabilities:
        for tactic in _capability_tactics(capability):
            grouped.setdefault(tactic, []).append(capability)
    return grouped


def _group_strings_by_reason(findings: list) -> dict:
    grouped: dict = {}
    for finding in findings:
        grouped.setdefault(finding["reason"], []).append(finding)
    return grouped


def _build_summary(case: Case) -> dict:
    yara_rules = [match["rule"] for match in case.static.yara_matches]

    tactic_counts: dict = {}
    for capability in case.static.capabilities:
        for tactic in _capability_tactics(capability):
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    reason_counts: dict = {}
    for finding in case.static.interesting_strings:
        reason = finding["reason"]
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    return {
        "yara_matches": {"count": len(yara_rules), "rules": yara_rules},
        "capabilities": {"count": len(case.static.capabilities), "tactics": tactic_counts},
        "interesting_strings": {
            "count": len(case.static.interesting_strings),
            "by_reason": reason_counts,
        },
    }


def _render_summary_lines(summary: dict) -> list:
    lines = ["Summary", "-" * 7]
    yara = summary["yara_matches"]
    capabilities = summary["capabilities"]
    strings = summary["interesting_strings"]

    lines.append(f"YARA: {yara['count']} rule(s) matched")
    lines.append(
        f"Capabilities: {capabilities['count']} finding(s) across "
        f"{len(capabilities['tactics'])} ATT&CK tactic(s)"
    )
    reason_summary = ", ".join(
        f"{reason}: {count}" for reason, count in sorted(strings["by_reason"].items())
    )
    reason_suffix = f" ({reason_summary})" if reason_summary else ""
    lines.append(f"Strings: {strings['count']} flagged{reason_suffix}")

    if yara["rules"]:
        lines.append(f"  YARA rules: {', '.join(yara['rules'])}")
    tactics_only = sorted(t for t in capabilities["tactics"] if t != "Ungrouped")
    if tactics_only:
        lines.append(f"  ATT&CK tactics: {', '.join(tactics_only)}")

    return lines


def build_text_report(case: Case, verbose: bool = False) -> str:
    lines = []
    lines.append("=" * 30)
    lines.append("Watson Static Analysis Report")
    lines.append("=" * 30)
    lines.append("")
    lines.append("Sample")
    lines.append("-" * 6)
    lines.append(case.identity.file_name)
    lines.append("")
    lines.append("Hashes")
    lines.append("-" * 6)
    lines.append(f"MD5:     {case.identity.md5}")
    lines.append(f"SHA1:    {case.identity.sha1}")
    lines.append(f"SHA256:  {case.identity.sha256}")
    lines.append(f"Imphash: {case.identity.imphash or 'N/A'}")
    lines.append("")
    lines.append("PE Metadata")
    lines.append("-" * 11)
    pe = case.static.pe_metadata
    machine = f"{pe.machine} ({pe.machine_name})" if pe.machine_name else pe.machine
    lines.append(f"Machine: {machine}")
    lines.append(f"Compile Timestamp: {pe.compile_timestamp or 'N/A'}")
    lines.append(f"Digital Signature Present: {pe.has_digital_signature}")
    lines.append(f"Likely Packed: {pe.likely_packed}")
    lines.append("")
    lines.append("Sections")
    lines.append("-" * 8)
    for section in pe.sections:
        lines.append(
            f"  {section['name']:<10} virtual_size={section['virtual_size']:<8} "
            f"raw_size={section['raw_size']:<8} entropy={section['entropy']}"
        )
    lines.append("")
    lines.append("Imports")
    lines.append("-" * 7)
    for dll, functions in pe.imports.items():
        lines.append(f"  {dll} ({len(functions)} functions)")

    lines.append("")
    lines.extend(_render_summary_lines(_build_summary(case)))

    lines.append("")
    lines.append("Tools")
    lines.append("-" * 5)
    for tool_name, status in case.static.tools.items():
        state = "available" if status.get("available") else "unavailable"
        line = f"  {tool_name}: {state}"
        reason = status.get("reason")
        if reason:
            line += f" ({reason})"
        lines.append(line)

    lines.append("")
    lines.append("YARA Matches")
    lines.append("-" * 12)
    if case.static.yara_matches:
        for match in case.static.yara_matches:
            tags = f" [{', '.join(match['tags'])}]" if match.get("tags") else ""
            lines.append(f"  {match['rule']}{tags}")
            if verbose:
                for string_match in match.get("matches", []):
                    lines.append(
                        f"    {string_match['identifier']} @ {hex(string_match['offset'])}: "
                        f"{string_match['matched_data']!r}"
                    )
    else:
        lines.append("  none")

    lines.append("")
    lines.append("Capabilities")
    lines.append("-" * 12)
    if case.static.capabilities:
        grouped = _group_capabilities_by_tactic(case.static.capabilities)
        for tactic in sorted(grouped, key=lambda t: (t == "Ungrouped", t)):
            lines.append(tactic)
            for capability in grouped[tactic]:
                lines.append(f"  {capability['rule']}")
                for attack in capability.get("attack") or []:
                    lines.append(f"    ATT&CK: {_format_mapping_entry(attack)}")
                for mbc in capability.get("mbc") or []:
                    lines.append(f"    MBC: {_format_mapping_entry(mbc)}")
    else:
        lines.append("  none")

    lines.append("")
    lines.append("Interesting Strings")
    lines.append("-" * 19)
    if case.static.interesting_strings:
        grouped = _group_strings_by_reason(case.static.interesting_strings)
        for reason in sorted(grouped):
            lines.append(reason)
            for finding in grouped[reason]:
                lines.append(f"  {finding['string']} ({finding['source']})")
    else:
        lines.append("  none")

    return "\n".join(lines)
