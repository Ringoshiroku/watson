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
