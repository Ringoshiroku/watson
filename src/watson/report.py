from __future__ import annotations

from watson.case import Case


def build_json_report(case: Case) -> dict:
    report = case.to_dict()
    report["summary"] = _build_summary(case)
    report["overview"] = _build_overview(case.static.capabilities)
    return report


def _render_classification_lines(classification: dict | None) -> list:
    lines = ["Classification", "-" * 14]
    if classification is None:
        lines.append("  not computed")
        return lines
    detection = classification.get("detection")
    if detection:
        lines.append(f"Detection: {detection}")
    lines.append(f"Verdict: {classification['verdict']}")
    lines.append(f"Risk: {classification['risk']}")
    lines.append("Reasoning:")
    for reason in classification["reasoning"]:
        lines.append(f"  - {reason}")
    return lines


def _render_die_lines(die_detections: list) -> list:
    lines = ["Detect It Easy", "-" * 14]
    if not die_detections:
        lines.append("  none")
        return lines
    for detect in die_detections:
        filetype = detect.get("filetype") or "unknown"
        lines.append(f"  File Type: {filetype}")
        for value in detect.get("values") or []:
            label = value.get("type") or "Detection"
            name = value.get("name") or ""
            version = value.get("version")
            detail = f"{name} ({version})" if version else name
            lines.append(f"    {label}: {detail}")
    return lines


def _render_pe_metadata_lines(pe, signature_verification=None, masquerade_check=None) -> list:
    lines = ["PE Metadata", "-" * 11]
    machine = f"{pe.machine} ({pe.machine_name})" if pe.machine_name else pe.machine
    lines.append(f"Machine: {machine}")
    lines.append(f"Compile Timestamp: {pe.compile_timestamp or 'N/A'}")
    lines.append(f"Digital Signature Present: {pe.has_digital_signature}")
    if signature_verification is not None:
        lines.append(f"Signature Verification: {signature_verification.verification_result}")
        lines.append(f"Signer Subject: {signature_verification.signer_subject or 'N/A'}")
        lines.append(f"Signer Issuer: {signature_verification.signer_issuer or 'N/A'}")
        lines.append(f"Signature Valid From: {signature_verification.valid_from or 'N/A'}")
        lines.append(f"Signature Valid To: {signature_verification.valid_to or 'N/A'}")
    if pe.company_name or pe.product_name or pe.original_filename or pe.internal_name or pe.file_description:
        lines.append(f"Claimed Company Name: {pe.company_name or 'N/A'}")
        lines.append(f"Claimed Product Name: {pe.product_name or 'N/A'}")
        lines.append(f"Claimed Original Filename: {pe.original_filename or 'N/A'}")
        lines.append(f"Claimed Internal Name: {pe.internal_name or 'N/A'}")
        lines.append(f"Claimed File Description: {pe.file_description or 'N/A'}")
    if pe.requested_execution_level:
        lines.append(f"Requested Execution Level: {pe.requested_execution_level}")
    if masquerade_check is not None and (
        masquerade_check.filename_mismatch or masquerade_check.claimed_vendor_mismatch
    ):
        lines.append(f"Filename Mismatch: {masquerade_check.filename_mismatch}")
        vendor_suffix = f" (claims {masquerade_check.claimed_vendor})" if masquerade_check.claimed_vendor else ""
        lines.append(f"Claimed Vendor Mismatch: {masquerade_check.claimed_vendor_mismatch}{vendor_suffix}")
    lines.append(f"Likely Packed: {pe.likely_packed}")
    return lines


def _render_elf_metadata_lines(elf) -> list:
    lines = ["ELF Metadata", "-" * 12]
    machine = f"{elf.machine} ({elf.machine_name})" if elf.machine_name else elf.machine
    lines.append(f"Machine: {machine}")
    lines.append(f"Entry Point: {elf.entry_point}")
    lines.append(f"Interpreter: {elf.interpreter or 'N/A (statically linked)'}")
    lines.append(f"PIE: {elf.is_pie}")
    lines.append(f"Stripped: {elf.is_stripped}")
    lines.append(f"Digital Signature Present: {elf.has_digital_signature}")
    lines.append(f"Likely Packed: {elf.likely_packed}")
    return lines


def _render_sections_lines(sections: list) -> list:
    lines = ["Sections", "-" * 8]
    for section in sections:
        lines.append(
            f"  {section['name']:<10} virtual_size={section['virtual_size']:<8} "
            f"raw_size={section['raw_size']:<8} entropy={section['entropy']}"
        )
    return lines


def _render_imports_lines(imports: dict) -> list:
    lines = ["Imports", "-" * 7]
    for dll, functions in imports.items():
        lines.append(f"  {dll} ({len(functions)} functions)")
    return lines


def _render_needed_libraries_lines(needed_libraries: list) -> list:
    lines = ["Needed Libraries", "-" * 16]
    if not needed_libraries:
        lines.append("  none (statically linked)")
        return lines
    for library in needed_libraries:
        lines.append(f"  {library}")
    return lines


def _render_dynamic_symbols_lines(dynamic_symbols: list) -> list:
    lines = ["Dynamic Symbols", "-" * 15]
    if not dynamic_symbols:
        lines.append("  none")
        return lines
    for symbol in dynamic_symbols:
        lines.append(f"  {symbol}")
    return lines


def _format_mapping_entry(entry) -> str:
    if isinstance(entry, str):
        return entry
    parts = entry.get("parts") or []
    label = "::".join(parts) if parts else entry.get("name", str(entry))
    entry_id = entry.get("id")
    return f"{label} [{entry_id}]" if entry_id else label


def _format_capa_evidence_line(evidence: dict) -> str:
    feature = evidence.get("feature") or "feature"
    value = evidence.get("value")
    addresses = evidence.get("addresses") or []
    more = evidence.get("more_addresses", 0)
    if not addresses:
        return f"    {feature}: {value}"
    addr_text = ", ".join(hex(a) for a in addresses)
    if more:
        addr_text += f" (+{more} more)"
    return f"    {feature}: {value} @ {addr_text}"


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


def _build_overview(capabilities: list) -> dict:
    grouped = _group_capabilities_by_tactic(capabilities)
    return {
        tactic: [capability["rule"] for capability in grouped[tactic]]
        for tactic in sorted(grouped, key=lambda t: (t == "Ungrouped", t))
    }


def _render_overview_lines(capabilities: list) -> list:
    lines = ["Overview", "-" * 8]
    if not capabilities:
        lines.append("  none")
        return lines
    for tactic, rules in _build_overview(capabilities).items():
        lines.append(f"{tactic}:")
        for rule in rules:
            lines.append(f"  - {rule}")
    return lines


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


# FLOSS extracts a Go binary's packed string-literal data (no null
# separators between literals) as one long "string"; the full text is kept
# in the underlying data (the JSON report and the standalone
# *_ranked_strings.json file), this only bounds what the plain-text report
# prints so a single entry can't turn into a multi-KB unreadable line.
_MAX_RANKED_STRING_DISPLAY_LENGTH = 300


def _render_ranked_strings_lines(ranked_strings: list) -> list:
    lines = ["Ranked Strings", "-" * 14]
    if not ranked_strings:
        lines.append("  none")
        return lines
    for entry in ranked_strings:
        text = entry["string"]
        if len(text) > _MAX_RANKED_STRING_DISPLAY_LENGTH:
            omitted = len(text) - _MAX_RANKED_STRING_DISPLAY_LENGTH
            text = f"{text[:_MAX_RANKED_STRING_DISPLAY_LENGTH]}... (+{omitted} more chars)"
        lines.append(f"  {entry['score']:.2f}  {text} ({entry['source']})")
    return lines


_MAX_PYINSTALLER_EXTRACTION_ENTRIES_DISPLAY = 50


def _render_pyinstaller_extraction_lines(extraction) -> list:
    lines = ["PyInstaller Extraction", "-" * 22]
    lines.append(f"  tool: {extraction.tool}")
    lines.append(f"  result: {'succeeded' if extraction.success else 'failed'}")
    if extraction.reason:
        lines.append(f"  reason: {extraction.reason}")
    if extraction.output_dir:
        lines.append(f"  output: {extraction.output_dir}")
    if extraction.entries:
        lines.append(f"  entries: {len(extraction.entries)}")
        shown = extraction.entries[:_MAX_PYINSTALLER_EXTRACTION_ENTRIES_DISPLAY]
        for entry in shown:
            marker = " [pyarmor-protected]" if entry.get("pyarmor_protected") else ""
            lines.append(f"    {entry['path']} ({entry['size']} bytes){marker}")
        remainder = len(extraction.entries) - len(shown)
        if remainder > 0:
            lines.append(f"    ... (+{remainder} more)")
    return lines


_MAX_PYARMOR_UNPACKING_ENTRIES_DISPLAY = 50


def _render_pyarmor_unpacking_lines(unpacking) -> list:
    lines = ["PyArmor Unpack", "-" * 14]
    lines.append(f"  tool: {unpacking.tool}")
    lines.append(f"  result: {'succeeded' if unpacking.success else 'failed'}")
    if unpacking.reason:
        lines.append(f"  reason: {unpacking.reason}")
    if unpacking.output_dir:
        lines.append(f"  output: {unpacking.output_dir}")
    if unpacking.entries:
        lines.append(f"  entries: {len(unpacking.entries)}")
        shown = unpacking.entries[:_MAX_PYARMOR_UNPACKING_ENTRIES_DISPLAY]
        for entry in shown:
            lines.append(f"    {entry['path']} ({entry['size']} bytes)")
        remainder = len(unpacking.entries) - len(shown)
        if remainder > 0:
            lines.append(f"    ... (+{remainder} more)")
    return lines


# a large Go binary can recover hundreds of function names per package; the
# full list is kept in the underlying data (the JSON report and the
# standalone *_goresym.json sidecar), this only bounds what the plain-text
# report prints per package so it can't turn into a multi-thousand-line dump.
_MAX_FUNCTIONS_PER_PACKAGE_DISPLAY = 20


def _render_go_build_info_lines(go_build_info: dict) -> list:
    lines = ["Go Build Info", "-" * 13]
    if not go_build_info:
        lines.append("  none")
        return lines

    lines.append(f"Go Version: {go_build_info.get('go_version') or 'N/A'}")
    module_path = go_build_info.get("module_path") or "N/A"
    module_version = go_build_info.get("module_version") or "N/A"
    lines.append(f"Module: {module_path} ({module_version})")

    lines.append("Dependencies:")
    dependencies = go_build_info.get("dependencies") or []
    if dependencies:
        for dep in dependencies:
            lines.append(f"  {dep['path']}@{dep['version']}")
    else:
        lines.append("  none")

    lines.append("Packages:")
    packages = go_build_info.get("packages") or {}
    if packages:
        for package_name in sorted(packages):
            lines.append(f"  {package_name}")
            funcs = packages[package_name]
            for func in funcs[:_MAX_FUNCTIONS_PER_PACKAGE_DISPLAY]:
                lines.append(f"    {func}")
            omitted = len(funcs) - _MAX_FUNCTIONS_PER_PACKAGE_DISPLAY
            if omitted > 0:
                lines.append(f"    ... +{omitted} more")
    else:
        lines.append("  none")

    return lines


def build_text_report(case: Case, verbose: bool = False) -> str:
    lines = []
    lines.append("=" * 30)
    lines.append("Watson Static Analysis Report")
    lines.append("=" * 30)
    lines.append("")
    lines.extend(_render_classification_lines(case.static.classification))
    lines.append("")
    lines.extend(_render_overview_lines(case.static.capabilities))
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
    pe = case.static.pe_metadata
    elf = case.static.elf_metadata
    if pe is not None:
        lines.extend(
            _render_pe_metadata_lines(pe, case.static.signature_verification, case.static.masquerade_check)
        )
        lines.append("")
        lines.extend(_render_die_lines(case.static.die_detections))
        lines.append("")
        lines.extend(_render_sections_lines(pe.sections))
        lines.append("")
        lines.extend(_render_imports_lines(pe.imports))
    else:
        lines.extend(_render_elf_metadata_lines(elf))
        lines.append("")
        lines.extend(_render_die_lines(case.static.die_detections))
        lines.append("")
        lines.extend(_render_sections_lines(elf.sections))
        lines.append("")
        lines.extend(_render_needed_libraries_lines(elf.needed_libraries))
        lines.append("")
        lines.extend(_render_dynamic_symbols_lines(elf.dynamic_symbols))

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

    if case.static.unpacking is not None:
        lines.append("")
        lines.append("Unpacking")
        lines.append("-" * 9)
        u = case.static.unpacking
        lines.append(f"  tool: {u.tool}")
        lines.append(f"  result: {'succeeded' if u.success else 'failed'}")
        if u.reason:
            lines.append(f"  reason: {u.reason}")
        if u.output_path:
            lines.append(f"  output: {u.output_path}")
        if u.unpacked_sha256:
            lines.append(f"  unpacked sha256: {u.unpacked_sha256}")

    if case.static.pyinstaller_extraction is not None:
        lines.append("")
        lines.extend(_render_pyinstaller_extraction_lines(case.static.pyinstaller_extraction))

    if case.static.pyarmor_unpacking is not None:
        lines.append("")
        lines.extend(_render_pyarmor_unpacking_lines(case.static.pyarmor_unpacking))

    lines.append("")
    lines.append("YARA Matches")
    lines.append("-" * 12)
    if case.static.yara_matches:
        for match in case.static.yara_matches:
            tags = f" [{', '.join(match['tags'])}]" if match.get("tags") else ""
            lines.append(f"  {match['rule']}{tags}")
            if verbose:
                for string_match in match.get("matches", []):
                    offset = string_match["offset"]
                    if offset is None:
                        # the "+N more instance(s) suppressed" marker yara_scan.py
                        # appends when a rule's matches are capped, not a real match
                        lines.append(f"    {string_match['identifier']}: {string_match['matched_data']}")
                    else:
                        lines.append(
                            f"    {string_match['identifier']} @ {hex(offset)}: "
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
                if verbose:
                    for evidence in capability.get("evidence") or []:
                        lines.append(_format_capa_evidence_line(evidence))
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

    lines.append("")
    lines.extend(_render_ranked_strings_lines(case.static.ranked_strings))

    lines.append("")
    lines.extend(_render_go_build_info_lines(case.static.go_build_info))

    return "\n".join(lines)
