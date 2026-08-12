from __future__ import annotations

import re
from typing import Optional

_RANSOMWARE_KEYWORDS = ("ransom",)
_WORM_KEYWORDS = ("worm",)
_INFOSTEALER_KEYWORDS = ("steal", "keylog")
_BACKDOOR_KEYWORDS = ("backdoor",)
_BACKDOOR_WHOLE_WORD_KEYWORDS = ("rat",)
_DOWNLOADER_KEYWORDS = ("download", "dropper")
_ADWARE_KEYWORDS = ("adware", "pua", "unwanted")

_YARA_KEYWORDS_BY_VERDICT = {
    "ransomware": (_RANSOMWARE_KEYWORDS, ()),
    "worm": (_WORM_KEYWORDS, ()),
    "infostealer": (_INFOSTEALER_KEYWORDS, ()),
    "backdoor": (_BACKDOOR_KEYWORDS, _BACKDOOR_WHOLE_WORD_KEYWORDS),
    "downloader": (_DOWNLOADER_KEYWORDS, ()),
    "adware": (_ADWARE_KEYWORDS, ()),
}


def _yara_hit_for_verdict(verdict: str, yara_matches: list):
    substrings, whole_words = _YARA_KEYWORDS_BY_VERDICT.get(verdict, ((), ()))
    return _yara_keyword_hit(yara_matches, substrings=substrings, whole_words=whole_words)


_RISK_BY_VERDICT = {
    "ransomware": "high",
    "worm": "high",
    "infostealer": "high",
    "backdoor": "high",
    "downloader": "medium",
    "trojan": "medium",
    "adware": "low",
    "unclassified": "low",
}
_RISK_ORDER = ["low", "medium", "high"]

_TOOL_LABELS = {"yara": "YARA", "capa": "capa"}
_TOOL_EVIDENCE_NOUN = {"yara": "rule", "capa": "capability"}

_WIN64_MACHINE_CODES = (0x8664, 0xAA64)

_VERDICT_SIGNAL = {
    "ransomware": "CryptoImpact",
    "worm": "LateralMovement",
    "infostealer": "CredentialAccess",
    "adware": "PUA",
    "trojan": "Generic",
}


def _attack_tactic(entry) -> str:
    if isinstance(entry, str):
        return entry.split("::", 1)[0] if "::" in entry else ""
    parts = entry.get("parts") or []
    return entry.get("tactic") or (parts[0] if parts else "")


def _mbc_objective(entry) -> str:
    if isinstance(entry, str):
        return entry.split("::", 1)[0] if "::" in entry else ""
    parts = entry.get("parts") or []
    return entry.get("objective") or (parts[0] if parts else "")


def _attack_tactics(capabilities: list) -> dict:
    tactics: dict = {}
    for capability in capabilities:
        for entry in capability.get("attack") or []:
            tactic = _attack_tactic(entry)
            if tactic:
                names = tactics.setdefault(tactic, [])
                if capability["rule"] not in names:
                    names.append(capability["rule"])
    return tactics


def _mbc_objectives(capabilities: list) -> dict:
    objectives: dict = {}
    for capability in capabilities:
        for entry in capability.get("mbc") or []:
            objective = _mbc_objective(entry)
            if objective:
                names = objectives.setdefault(objective, [])
                if capability["rule"] not in names:
                    names.append(capability["rule"])
    return objectives


def _yara_keyword_hit(yara_matches: list, substrings: tuple = (), whole_words: tuple = ()):
    for match in yara_matches:
        text = f"{match.get('rule', '')} {' '.join(match.get('tags') or [])}".lower()
        for keyword in substrings:
            if keyword in text:
                return match
        for keyword in whole_words:
            if re.search(rf"\b{keyword}\b", text):
                return match
    return None


def _verdict(yara_matches: list, capabilities: list) -> str:
    tactics = _attack_tactics(capabilities)
    objectives = _mbc_objectives(capabilities)

    if (
        ("Impact" in objectives and "Cryptography" in objectives)
        or ("Impact" in tactics and "Cryptography" in objectives)
        or _yara_keyword_hit(yara_matches, substrings=_RANSOMWARE_KEYWORDS)
    ):
        return "ransomware"

    if "Lateral Movement" in tactics or _yara_keyword_hit(yara_matches, substrings=_WORM_KEYWORDS):
        return "worm"

    if "Credential Access" in tactics or _yara_keyword_hit(yara_matches, substrings=_INFOSTEALER_KEYWORDS):
        return "infostealer"

    if (
        "Command and Control" in tactics and ("Discovery" in tactics or "Execution" in tactics)
    ) or _yara_keyword_hit(
        yara_matches, substrings=_BACKDOOR_KEYWORDS, whole_words=_BACKDOOR_WHOLE_WORD_KEYWORDS
    ):
        return "backdoor"

    if _yara_keyword_hit(yara_matches, substrings=_DOWNLOADER_KEYWORDS) or "Command and Control" in tactics:
        return "downloader"

    if _yara_keyword_hit(yara_matches, substrings=_ADWARE_KEYWORDS):
        return "adware"

    if yara_matches or capabilities:
        return "trojan"

    return "unclassified"


def _risk(
    verdict: str, likely_packed: bool, die_packer_names: list, is_unsigned: bool = False, signature_invalid: bool = False, claimed_vendor_mismatch: bool = False
) -> str:
    tier = _RISK_BY_VERDICT[verdict]
    bumps = 0
    if likely_packed or die_packer_names:
        bumps += 1
    if (is_unsigned or signature_invalid or claimed_vendor_mismatch) and verdict != "unclassified":
        bumps += 1
    if bumps:
        index = min(_RISK_ORDER.index(tier) + bumps, len(_RISK_ORDER) - 1)
        tier = _RISK_ORDER[index]
    return tier


def _tool_reasoning_line(tool_name: str, tools: dict) -> str:
    label = _TOOL_LABELS[tool_name]
    status = tools.get(tool_name, {})
    if status.get("available"):
        return f"{label} ran and found no {_TOOL_EVIDENCE_NOUN[tool_name]} matches"
    reason = status.get("reason") or "not run"
    return f"{label} was not run ({reason})"


def _format_rule_names(names: list) -> str:
    shown = names[:3]
    text = ", ".join(f"'{name}'" for name in shown)
    remainder = len(names) - len(shown)
    if remainder > 0:
        text += f" (+{remainder} more)"
    return text


def _merge_rule_names(*name_lists: list) -> list:
    merged: list = []
    for names in name_lists:
        for name in names:
            if name not in merged:
                merged.append(name)
    return merged


def _capa_reasoning_line(rule_names: list, behavior_desc: str) -> str:
    return f"capa rule(s) {_format_rule_names(rule_names)} fired {behavior_desc}"


def _yara_reasoning_line(yara_hit: dict) -> str:
    tags = ", ".join(yara_hit.get("tags") or [])
    tag_suffix = f" (tags: {tags})" if tags else ""
    return f"YARA rule '{yara_hit['rule']}' matched{tag_suffix}"


def _packed_reasoning_line(likely_packed: bool, die_packer_names: list) -> str:
    if likely_packed and die_packer_names:
        return (
            "risk raised one tier because the sample is likely packed (high section entropy) "
            f"and Detect It Easy identified a known packer/protector: {_format_rule_names(die_packer_names)}"
        )
    if die_packer_names:
        return (
            "risk raised one tier because Detect It Easy identified a known packer/protector: "
            f"{_format_rule_names(die_packer_names)}"
        )
    return "risk raised one tier because the sample is likely packed"


def _is_go_build_info_stripped(go_build_info: dict) -> bool:
    return bool(go_build_info.get("go_version")) and not go_build_info.get("module_path")


def _go_build_info_stripped_line() -> str:
    return (
        "Go binary detected (via pclntab) but no module path or dependency "
        "metadata was recovered, consistent with build info stripped or "
        "removed (e.g. by an obfuscator such as Gobfuscator)"
    )


def _reasoning(
    verdict: str,
    yara_matches: list,
    capabilities: list,
    likely_packed: bool,
    tools: dict,
    die_packer_names: list,
    is_unsigned: bool = False,
    signature_invalid: bool = False,
    signature_verification_result: str = "",
    claimed_vendor_mismatch: bool = False,
    claimed_vendor: str = "",
    go_build_info: dict = None,
) -> list:
    reasoning = []
    go_build_info = go_build_info or {}

    if verdict == "unclassified":
        reasoning.append(_tool_reasoning_line("yara", tools))
        reasoning.append(_tool_reasoning_line("capa", tools))
        if likely_packed or die_packer_names:
            reasoning.append(_packed_reasoning_line(likely_packed, die_packer_names))
        if _is_go_build_info_stripped(go_build_info):
            reasoning.append(_go_build_info_stripped_line())
        return reasoning

    if verdict == "trojan":
        reasoning.append(
            f"capa/YARA found {len(yara_matches) + len(capabilities)} capability finding(s) "
            "but none matched a more specific category"
        )
    else:
        tactics = _attack_tactics(capabilities)
        objectives = _mbc_objectives(capabilities)
        if verdict == "ransomware":
            if "Cryptography" in objectives and "Impact" in objectives:
                rules = _merge_rule_names(objectives["Cryptography"], objectives["Impact"])
                reasoning.append(
                    _capa_reasoning_line(
                        rules, "both MBC Cryptography and MBC Impact behavior, consistent with ransomware"
                    )
                )
            elif "Impact" in tactics and "Cryptography" in objectives:
                rules = _merge_rule_names(tactics["Impact"], objectives["Cryptography"])
                reasoning.append(
                    _capa_reasoning_line(
                        rules, "ATT&CK Impact and MBC Cryptography behavior, consistent with ransomware"
                    )
                )
            yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
            if yara_hit:
                reasoning.append(_yara_reasoning_line(yara_hit))
        elif verdict == "worm":
            if "Lateral Movement" in tactics:
                reasoning.append(
                    _capa_reasoning_line(
                        tactics["Lateral Movement"], "ATT&CK Lateral Movement behavior, consistent with a worm"
                    )
                )
            yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
            if yara_hit:
                reasoning.append(_yara_reasoning_line(yara_hit))
        elif verdict == "infostealer":
            if "Credential Access" in tactics:
                reasoning.append(
                    _capa_reasoning_line(
                        tactics["Credential Access"],
                        "ATT&CK Credential Access behavior, consistent with an infostealer",
                    )
                )
            yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
            if yara_hit:
                reasoning.append(_yara_reasoning_line(yara_hit))
        elif verdict == "backdoor":
            if "Command and Control" in tactics and ("Discovery" in tactics or "Execution" in tactics):
                rules = _merge_rule_names(
                    tactics["Command and Control"],
                    tactics.get("Discovery") or tactics.get("Execution") or [],
                )
                reasoning.append(
                    _capa_reasoning_line(
                        rules,
                        "ATT&CK Command and Control behavior alongside Discovery/Execution, "
                        "consistent with a backdoor",
                    )
                )
            yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
            if yara_hit:
                reasoning.append(_yara_reasoning_line(yara_hit))
        elif verdict == "downloader":
            yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
            if yara_hit:
                reasoning.append(_yara_reasoning_line(yara_hit))
            if "Command and Control" in tactics:
                reasoning.append(
                    _capa_reasoning_line(
                        tactics["Command and Control"],
                        "ATT&CK Command and Control behavior, consistent with a downloader",
                    )
                )
        elif verdict == "adware":
            yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
            if yara_hit:
                reasoning.append(_yara_reasoning_line(yara_hit))

    reasoning.append(
        "see Capabilities/YARA Matches below for full evidence detail (run with -v for match locations)"
    )

    if likely_packed or die_packer_names:
        reasoning.append(_packed_reasoning_line(likely_packed, die_packer_names))
    if _is_go_build_info_stripped(go_build_info):
        reasoning.append(_go_build_info_stripped_line())

    if claimed_vendor_mismatch:
        reasoning.append(
            "risk raised one tier because the sample's VERSIONINFO claims to be "
            f"published by {claimed_vendor} but that isn't corroborated by its signature"
        )
    elif is_unsigned:
        reasoning.append("risk raised one tier because the sample is unsigned")
    elif signature_invalid:
        reasoning.append(
            "risk raised one tier because the sample's digital signature failed "
            f"verification ({signature_verification_result})"
        )

    return reasoning


def _platform(machine: str, file_format: str = "pe") -> str:
    if file_format == "elf":
        return "Linux"
    try:
        code = int(machine, 16)
    except (TypeError, ValueError):
        return "Win32"
    return "Win64" if code in _WIN64_MACHINE_CODES else "Win32"


def _detection_source(yara_hit, capa_rules: list) -> str:
    has_capa = bool(capa_rules)
    has_yara = yara_hit is not None
    if has_capa and has_yara:
        return "capa+yara"
    if has_yara:
        return "yara"
    return "capa"


def _detection(
    verdict: str, yara_matches: list, capabilities: list, machine: str, file_format: str = "pe"
) -> Optional[str]:
    if verdict == "unclassified":
        return None

    tactics = _attack_tactics(capabilities)
    objectives = _mbc_objectives(capabilities)

    if verdict == "ransomware":
        capa_rules = objectives.get("Cryptography", []) or tactics.get("Impact", [])
        yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
        signal = _VERDICT_SIGNAL["ransomware"]
    elif verdict == "worm":
        capa_rules = tactics.get("Lateral Movement", [])
        yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
        signal = _VERDICT_SIGNAL["worm"]
    elif verdict == "infostealer":
        capa_rules = tactics.get("Credential Access", [])
        yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
        signal = _VERDICT_SIGNAL["infostealer"]
    elif verdict == "backdoor":
        capa_rules = tactics.get("Command and Control", [])
        yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
        signal = "C2Discovery" if "Discovery" in tactics else "C2Execution"
    elif verdict == "downloader":
        yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
        capa_rules = tactics.get("Command and Control", [])
        signal = "C2" if "Command and Control" in tactics else "DropperKeyword"
    elif verdict == "adware":
        capa_rules = []
        yara_hit = _yara_hit_for_verdict(verdict, yara_matches)
        signal = _VERDICT_SIGNAL["adware"]
    else:  # trojan: the catch-all, cite everything that's present
        capa_rules = [capability["rule"] for capability in capabilities]
        yara_hit = yara_matches[0] if yara_matches else None
        signal = _VERDICT_SIGNAL["trojan"]

    source = _detection_source(yara_hit, capa_rules)
    return f"{verdict.capitalize()}:{_platform(machine, file_format)}/{signal}.{source}"


def classify(
    yara_matches: list,
    capabilities: list,
    likely_packed: bool,
    tools: dict,
    machine: str = "",
    file_format: str = "pe",
    is_unsigned: bool = False,
    die_packer_names: list = None,
    signature_invalid: bool = False,
    signature_verification_result: str = "",
    claimed_vendor_mismatch: bool = False,
    claimed_vendor: str = "",
    go_build_info: dict = None,
) -> dict:
    die_packer_names = die_packer_names or []
    verdict = _verdict(yara_matches, capabilities)
    risk = _risk(verdict, likely_packed, die_packer_names, is_unsigned, signature_invalid, claimed_vendor_mismatch)
    reasoning = _reasoning(
        verdict,
        yara_matches,
        capabilities,
        likely_packed,
        tools,
        die_packer_names,
        is_unsigned,
        signature_invalid,
        signature_verification_result,
        claimed_vendor_mismatch,
        claimed_vendor,
        go_build_info,
    )
    detection = _detection(verdict, yara_matches, capabilities, machine, file_format)
    return {"verdict": verdict, "risk": risk, "reasoning": reasoning, "detection": detection}
