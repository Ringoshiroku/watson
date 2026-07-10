import pytest

from watson.classification import classify


def test_classify_detects_ransomware_via_mbc_cryptography_and_impact():
    capabilities = [
        {
            "rule": "encrypt files",
            "namespace": "data-manipulation/encryption",
            "attack": [],
            "mbc": [
                {"parts": ["Cryptography", "Encrypt Data"], "objective": "Cryptography", "id": "C0027"},
                {"parts": ["Impact", "Data Encrypted"], "objective": "Impact", "id": "F0002"},
            ],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "ransomware"


def test_classify_detects_ransomware_via_yara_keyword():
    yara_matches = [{"rule": "generic_ransomware_dropper", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["verdict"] == "ransomware"


def test_classify_detects_worm_via_attack_tactic():
    capabilities = [
        {
            "rule": "copy to removable drive",
            "namespace": "host-interaction/file-system",
            "attack": ["Lateral Movement::Replication Through Removable Media [T1091]"],
            "mbc": [],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "worm"


def test_classify_detects_worm_via_yara_keyword():
    yara_matches = [{"rule": "win32_worm_generic", "tags": ["Worm"], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["verdict"] == "worm"


def test_classify_detects_infostealer_via_attack_tactic():
    capabilities = [
        {
            "rule": "harvest browser credentials",
            "namespace": "collection/browser",
            "attack": ["Credential Access::Credentials from Password Stores [T1555]"],
            "mbc": [],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "infostealer"


def test_classify_detects_infostealer_via_yara_keyword():
    yara_matches = [{"rule": "generic_stealer_variant", "tags": ["Stealer"], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["verdict"] == "infostealer"


def test_classify_detects_backdoor_via_attack_tactic_combination():
    capabilities = [
        {
            "rule": "remote command execution",
            "namespace": "communication/socket",
            "attack": [
                "Command and Control::Non-Standard Port [T1571]",
                "Execution::Command and Scripting Interpreter [T1059]",
            ],
            "mbc": [],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "backdoor"


def test_classify_detects_backdoor_via_yara_backdoor_keyword():
    yara_matches = [{"rule": "generic_backdoor_implant", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["verdict"] == "backdoor"


def test_classify_detects_backdoor_via_yara_rat_tag_word_boundary():
    yara_matches = [{"rule": "generic_implant", "tags": ["RAT"], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["verdict"] == "backdoor"


def test_classify_rat_keyword_does_not_false_positive_inside_unrelated_word():
    yara_matches = [{"rule": "narrative_generator_tool", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["verdict"] == "trojan"


def test_classify_detects_downloader_via_yara_keyword():
    yara_matches = [{"rule": "generic_downloader", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["verdict"] == "downloader"


def test_classify_detects_downloader_via_lone_command_and_control_tactic():
    capabilities = [
        {
            "rule": "http c2 beacon",
            "namespace": "communication/http",
            "attack": ["Command and Control::Web Protocols [T1071.001]"],
            "mbc": [],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "downloader"


def test_classify_detects_adware_via_yara_keyword():
    yara_matches = [{"rule": "generic_adware_installer", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["verdict"] == "adware"


def test_classify_falls_back_to_trojan_when_evidence_exists_but_unspecific():
    capabilities = [
        {
            "rule": "read file",
            "namespace": "host-interaction/file-system/read",
            "attack": ["Execution::Command and Scripting Interpreter [T1059]"],
            "mbc": [],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "trojan"


def test_classify_detects_ransomware_via_mixed_attack_tactic_and_mbc_objective():
    capabilities = [
        {
            "rule": "destroy volume shadow copies",
            "namespace": "impact/data-destruction",
            "attack": [
                {"parts": ["Impact", "Inhibit System Recovery"], "tactic": "Impact", "id": "T1490"},
            ],
            "mbc": [
                {"parts": ["Cryptography", "Encrypt Data"], "objective": "Cryptography", "id": "C0027"},
            ],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "ransomware"
    assert result["reasoning"] == [
        "capa rule(s) 'destroy volume shadow copies' fired ATT&CK Impact and MBC Cryptography "
        "behavior, consistent with ransomware",
        "see Capabilities/YARA Matches below for full evidence detail (run with -v for match locations)",
    ]


def test_classify_detects_worm_via_dict_form_attack_entry():
    capabilities = [
        {
            "rule": "copy to removable drive",
            "namespace": "host-interaction/file-system",
            "attack": [
                {
                    "parts": ["Lateral Movement", "Replication Through Removable Media"],
                    "tactic": "Lateral Movement",
                    "id": "T1091",
                },
            ],
            "mbc": [],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "worm"


def test_classify_priority_order_ransomware_wins_over_worm_when_both_signals_present():
    capabilities = [
        {
            "rule": "encrypt and spread",
            "namespace": "impact/data-destruction",
            "attack": ["Lateral Movement::Replication Through Removable Media [T1091]"],
            "mbc": [
                {"parts": ["Cryptography", "Encrypt Data"], "objective": "Cryptography", "id": "C0027"},
                {"parts": ["Impact", "Data Encrypted"], "objective": "Impact", "id": "F0002"},
            ],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == "ransomware"


def test_classify_unclassified_when_no_evidence_at_all():
    tools = {
        "yara": {"available": True, "reason": None},
        "capa": {"available": True, "reason": None},
    }

    result = classify(yara_matches=[], capabilities=[], likely_packed=False, tools=tools)

    assert result["verdict"] == "unclassified"


def test_classify_risk_tier_high_for_ransomware():
    yara_matches = [{"rule": "generic_ransomware_dropper", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["risk"] == "high"


def test_classify_risk_tier_medium_for_downloader():
    yara_matches = [{"rule": "generic_downloader", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["risk"] == "medium"


def test_classify_risk_tier_low_for_adware():
    yara_matches = [{"rule": "generic_adware_installer", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert result["risk"] == "low"


def test_classify_risk_tier_low_for_unclassified():
    tools = {"yara": {"available": True, "reason": None}, "capa": {"available": True, "reason": None}}

    result = classify(yara_matches=[], capabilities=[], likely_packed=False, tools=tools)

    assert result["risk"] == "low"


def test_classify_packed_sample_bumps_risk_tier_up_one_step():
    yara_matches = [{"rule": "generic_adware_installer", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=True, tools={})

    assert result["risk"] == "medium"


def test_classify_packed_sample_at_high_risk_stays_high():
    yara_matches = [{"rule": "generic_ransomware_dropper", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=True, tools={})

    assert result["risk"] == "high"


def test_classify_packing_bump_adds_reasoning_line():
    yara_matches = [{"rule": "generic_adware_installer", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=True, tools={})

    assert "risk raised one tier because the sample is likely packed" in result["reasoning"]


def test_classify_unclassified_reasoning_when_both_tools_ran_and_found_nothing():
    tools = {
        "yara": {"available": True, "reason": None},
        "capa": {"available": True, "reason": None},
    }

    result = classify(yara_matches=[], capabilities=[], likely_packed=False, tools=tools)

    assert result["reasoning"] == [
        "YARA ran and found no rule matches",
        "capa ran and found no capability matches",
    ]


def test_classify_unclassified_reasoning_when_yara_not_run_capa_ran_empty():
    tools = {
        "yara": {"available": False, "reason": "not requested (skipped at the analysis-selection prompt)"},
        "capa": {"available": True, "reason": None},
    }

    result = classify(yara_matches=[], capabilities=[], likely_packed=False, tools=tools)

    assert result["reasoning"] == [
        "YARA was not run (not requested (skipped at the analysis-selection prompt))",
        "capa ran and found no capability matches",
    ]


def test_classify_unclassified_reasoning_when_yara_ran_empty_capa_not_run():
    tools = {
        "yara": {"available": True, "reason": None},
        "capa": {"available": False, "reason": "not requested (skipped at the analysis-selection prompt)"},
    }

    result = classify(yara_matches=[], capabilities=[], likely_packed=False, tools=tools)

    assert result["reasoning"] == [
        "YARA ran and found no rule matches",
        "capa was not run (not requested (skipped at the analysis-selection prompt))",
    ]


def test_classify_unclassified_reasoning_when_neither_tool_ran():
    tools = {
        "yara": {"available": False, "reason": "not requested (skipped at the analysis-selection prompt)"},
        "capa": {"available": False, "reason": "not requested (skipped at the analysis-selection prompt)"},
    }

    result = classify(yara_matches=[], capabilities=[], likely_packed=False, tools=tools)

    assert result["reasoning"] == [
        "YARA was not run (not requested (skipped at the analysis-selection prompt))",
        "capa was not run (not requested (skipped at the analysis-selection prompt))",
    ]


@pytest.mark.parametrize(
    "verdict,yara_matches,capabilities",
    [
        (
            "ransomware",
            [{"rule": "generic_ransomware_dropper", "tags": [], "matches": []}],
            [],
        ),
        (
            "worm",
            [{"rule": "win32_worm_generic", "tags": ["Worm"], "matches": []}],
            [],
        ),
        (
            "infostealer",
            [{"rule": "generic_stealer_variant", "tags": ["Stealer"], "matches": []}],
            [],
        ),
        (
            "backdoor",
            [{"rule": "generic_backdoor_implant", "tags": [], "matches": []}],
            [],
        ),
        (
            "downloader",
            [{"rule": "generic_downloader", "tags": [], "matches": []}],
            [],
        ),
        (
            "adware",
            [{"rule": "generic_adware_installer", "tags": [], "matches": []}],
            [],
        ),
        (
            "trojan",
            [],
            [
                {
                    "rule": "read file",
                    "namespace": "host-interaction/file-system/read",
                    "attack": ["Execution::Command and Scripting Interpreter [T1059]"],
                    "mbc": [],
                }
            ],
        ),
    ],
)
def test_classify_every_non_unclassified_verdict_has_nonempty_reasoning(verdict, yara_matches, capabilities):
    result = classify(yara_matches=yara_matches, capabilities=capabilities, likely_packed=False, tools={})

    assert result["verdict"] == verdict
    assert result["reasoning"] != []


def test_classify_detection_string_for_ransomware_win64_capa_only():
    capabilities = [
        {
            "rule": "encrypt files",
            "namespace": "data-manipulation/encryption",
            "attack": [],
            "mbc": [
                {"parts": ["Cryptography", "Encrypt Data"], "objective": "Cryptography", "id": "C0027"},
                {"parts": ["Impact", "Data Encrypted"], "objective": "Impact", "id": "F0002"},
            ],
        }
    ]

    result = classify(
        yara_matches=[], capabilities=capabilities, likely_packed=False, tools={}, machine="0x8664"
    )

    assert result["detection"] == "Ransomware:Win64/CryptoImpact.capa"


def test_classify_detection_string_uses_win32_for_x86_machine():
    yara_matches = [{"rule": "generic_ransomware_dropper", "tags": [], "matches": []}]

    result = classify(
        yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={}, machine="0x14c"
    )

    assert result["detection"] == "Ransomware:Win32/CryptoImpact.yara"


def test_classify_detection_string_reports_capa_plus_yara_when_both_contribute():
    capabilities = [
        {
            "rule": "encrypt files",
            "namespace": "data-manipulation/encryption",
            "attack": [],
            "mbc": [
                {"parts": ["Cryptography", "Encrypt Data"], "objective": "Cryptography", "id": "C0027"},
            ],
        }
    ]
    yara_matches = [{"rule": "generic_ransomware_dropper", "tags": [], "matches": []}]

    result = classify(
        yara_matches=yara_matches,
        capabilities=capabilities,
        likely_packed=False,
        tools={},
        machine="0x8664",
    )

    assert result["detection"] == "Ransomware:Win64/CryptoImpact.capa+yara"


def test_classify_detection_is_none_when_unclassified():
    tools = {
        "yara": {"available": True, "reason": None},
        "capa": {"available": True, "reason": None},
    }

    result = classify(yara_matches=[], capabilities=[], likely_packed=False, tools=tools)

    assert result["detection"] is None


def test_classify_detection_string_for_backdoor_prefers_discovery_signal():
    capabilities = [
        {
            "rule": "remote command execution",
            "namespace": "communication/socket",
            "attack": [
                "Command and Control::Non-Standard Port [T1571]",
                "Discovery::Query System Information [T1082]",
            ],
            "mbc": [],
        }
    ]

    result = classify(
        yara_matches=[], capabilities=capabilities, likely_packed=False, tools={}, machine="0x8664"
    )

    assert result["detection"] == "Backdoor:Win64/C2Discovery.capa"


def test_classify_reasoning_names_the_capa_rule_that_fired():
    capabilities = [
        {
            "rule": "harvest browser credentials",
            "namespace": "collection/browser",
            "attack": ["Credential Access::Credentials from Password Stores [T1555]"],
            "mbc": [],
        }
    ]

    result = classify(yara_matches=[], capabilities=capabilities, likely_packed=False, tools={})

    assert any("harvest browser credentials" in line for line in result["reasoning"])


def test_classify_reasoning_names_the_yara_rule_that_fired():
    yara_matches = [{"rule": "win32_worm_generic", "tags": ["Worm"], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert "YARA rule 'win32_worm_generic' matched (tags: Worm)" in result["reasoning"]


def test_classify_appends_navigation_hint_for_non_unclassified_verdict():
    yara_matches = [{"rule": "generic_downloader", "tags": [], "matches": []}]

    result = classify(yara_matches=yara_matches, capabilities=[], likely_packed=False, tools={})

    assert (
        "see Capabilities/YARA Matches below for full evidence detail (run with -v for match locations)"
        in result["reasoning"]
    )


def test_classify_no_navigation_hint_for_unclassified_verdict():
    tools = {
        "yara": {"available": True, "reason": None},
        "capa": {"available": True, "reason": None},
    }

    result = classify(yara_matches=[], capabilities=[], likely_packed=False, tools=tools)

    assert not any("see Capabilities/YARA Matches" in line for line in result["reasoning"])
