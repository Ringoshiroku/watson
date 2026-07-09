from __future__ import annotations

from watson.case import Case


def build_json_report(case: Case) -> dict:
    return case.to_dict()


def _format_mapping_entry(entry) -> str:
    if isinstance(entry, str):
        return entry
    parts = entry.get("parts") or []
    label = "::".join(parts) if parts else entry.get("name", str(entry))
    entry_id = entry.get("id")
    return f"{label} [{entry_id}]" if entry_id else label


def build_text_report(case: Case) -> str:
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
        for capability in case.static.capabilities:
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
        for finding in case.static.interesting_strings:
            lines.append(f"  [{finding['reason']}] {finding['string']} ({finding['source']})")
    else:
        lines.append("  none")

    return "\n".join(lines)
