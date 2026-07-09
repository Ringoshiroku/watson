from __future__ import annotations

import re

_RANSOMWARE_KEYWORDS = ("ransom",)
_WORM_KEYWORDS = ("worm",)
_INFOSTEALER_KEYWORDS = ("steal", "keylog")
_BACKDOOR_KEYWORDS = ("backdoor",)
_BACKDOOR_WHOLE_WORD_KEYWORDS = ("rat",)
_DOWNLOADER_KEYWORDS = ("download", "dropper")
_ADWARE_KEYWORDS = ("adware", "pua", "unwanted")

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


def _attack_tactics(capabilities: list) -> set:
    tactics = set()
    for capability in capabilities:
        for entry in capability.get("attack") or []:
            tactic = _attack_tactic(entry)
            if tactic:
                tactics.add(tactic)
    return tactics


def _mbc_objectives(capabilities: list) -> set:
    objectives = set()
    for capability in capabilities:
        for entry in capability.get("mbc") or []:
            objective = _mbc_objective(entry)
            if objective:
                objectives.add(objective)
    return objectives


def _yara_keyword_hit(yara_matches: list, substrings: tuple = (), whole_words: tuple = ()) -> bool:
    for match in yara_matches:
        text = f"{match.get('rule', '')} {' '.join(match.get('tags') or [])}".lower()
        for keyword in substrings:
            if keyword in text:
                return True
        for keyword in whole_words:
            if re.search(rf"\b{keyword}\b", text):
                return True
    return False


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


def _risk(verdict: str, likely_packed: bool) -> str:
    tier = _RISK_BY_VERDICT[verdict]
    if likely_packed:
        index = min(_RISK_ORDER.index(tier) + 1, len(_RISK_ORDER) - 1)
        tier = _RISK_ORDER[index]
    return tier


def _tool_reasoning_line(tool_name: str, tools: dict) -> str:
    label = _TOOL_LABELS[tool_name]
    status = tools.get(tool_name, {})
    if status.get("available"):
        return f"{label} ran and found no {_TOOL_EVIDENCE_NOUN[tool_name]} matches"
    reason = status.get("reason") or "not run"
    return f"{label} was not run ({reason})"


def _reasoning(
    verdict: str, yara_matches: list, capabilities: list, likely_packed: bool, tools: dict
) -> list:
    reasoning = []

    if verdict == "unclassified":
        reasoning.append(_tool_reasoning_line("yara", tools))
        reasoning.append(_tool_reasoning_line("capa", tools))
    elif verdict == "trojan":
        reasoning.append(
            f"capa/YARA found {len(yara_matches) + len(capabilities)} capability finding(s) "
            "but none matched a more specific category"
        )
    else:
        tactics = _attack_tactics(capabilities)
        objectives = _mbc_objectives(capabilities)
        if verdict == "ransomware":
            if "Cryptography" in objectives and "Impact" in objectives:
                reasoning.append(
                    "capa detected Cryptography and Impact behavior (MBC), consistent with ransomware"
                )
            if _yara_keyword_hit(yara_matches, substrings=_RANSOMWARE_KEYWORDS):
                reasoning.append("a YARA rule matched with a ransomware-related tag or name")
        elif verdict == "worm":
            if "Lateral Movement" in tactics:
                reasoning.append("capa detected Lateral Movement behavior (ATT&CK), consistent with a worm")
            if _yara_keyword_hit(yara_matches, substrings=_WORM_KEYWORDS):
                reasoning.append("a YARA rule matched with a worm-related tag or name")
        elif verdict == "infostealer":
            if "Credential Access" in tactics:
                reasoning.append(
                    "capa detected Credential Access behavior (ATT&CK), consistent with an infostealer"
                )
            if _yara_keyword_hit(yara_matches, substrings=_INFOSTEALER_KEYWORDS):
                reasoning.append("a YARA rule matched with an infostealer-related tag or name")
        elif verdict == "backdoor":
            if "Command and Control" in tactics:
                reasoning.append(
                    "capa detected Command and Control behavior alongside Discovery/Execution "
                    "(ATT&CK), consistent with a backdoor"
                )
            if _yara_keyword_hit(
                yara_matches, substrings=_BACKDOOR_KEYWORDS, whole_words=_BACKDOOR_WHOLE_WORD_KEYWORDS
            ):
                reasoning.append("a YARA rule matched with a backdoor/RAT-related tag or name")
        elif verdict == "downloader":
            if _yara_keyword_hit(yara_matches, substrings=_DOWNLOADER_KEYWORDS):
                reasoning.append("a YARA rule matched with a downloader/dropper-related tag or name")
            if "Command and Control" in tactics:
                reasoning.append("capa detected Command and Control behavior (ATT&CK)")
        elif verdict == "adware":
            reasoning.append("a YARA rule matched with an adware/PUA-related tag or name")

    if likely_packed:
        reasoning.append("risk raised one tier because the sample is likely packed")

    return reasoning


def classify(yara_matches: list, capabilities: list, likely_packed: bool, tools: dict) -> dict:
    verdict = _verdict(yara_matches, capabilities)
    risk = _risk(verdict, likely_packed)
    reasoning = _reasoning(verdict, yara_matches, capabilities, likely_packed, tools)
    return {"verdict": verdict, "risk": risk, "reasoning": reasoning}
