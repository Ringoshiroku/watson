from watson.masquerade_scan import check_masquerade


def test_check_masquerade_flags_filename_mismatch():
    result = check_masquerade(
        actual_filename="evil.exe",
        version_info={"original_filename": "legit.exe", "company_name": None},
        signer_subject=None,
    )

    assert result["filename_mismatch"] is True


def test_check_masquerade_no_mismatch_when_filename_matches():
    result = check_masquerade(
        actual_filename="legit.exe",
        version_info={"original_filename": "legit.exe", "company_name": None},
        signer_subject=None,
    )

    assert result["filename_mismatch"] is False


def test_check_masquerade_filename_match_is_case_insensitive():
    result = check_masquerade(
        actual_filename="LEGIT.EXE",
        version_info={"original_filename": "legit.exe", "company_name": None},
        signer_subject=None,
    )

    assert result["filename_mismatch"] is False


def test_check_masquerade_falls_back_to_internal_name_when_original_absent():
    result = check_masquerade(
        actual_filename="evil.exe",
        version_info={"original_filename": None, "internal_name": "legit", "company_name": None},
        signer_subject=None,
    )

    assert result["filename_mismatch"] is True


def test_check_masquerade_no_mismatch_when_no_filename_fields_present():
    result = check_masquerade(
        actual_filename="evil.exe",
        version_info={"original_filename": None, "internal_name": None, "company_name": None},
        signer_subject=None,
    )

    assert result["filename_mismatch"] is False


def test_check_masquerade_flags_known_vendor_with_no_signature():
    result = check_masquerade(
        actual_filename="evil.exe",
        version_info={"company_name": "Microsoft Corporation"},
        signer_subject=None,
    )

    assert result["claimed_vendor_mismatch"] is True
    assert result["claimed_vendor"] == "Microsoft Corporation"


def test_check_masquerade_no_mismatch_when_signer_corroborates_claimed_vendor():
    result = check_masquerade(
        actual_filename="evil.exe",
        version_info={"company_name": "Microsoft Corporation"},
        signer_subject="CN=Microsoft Corporation, O=Microsoft Corporation",
    )

    assert result["claimed_vendor_mismatch"] is False


def test_check_masquerade_flags_known_vendor_when_signer_does_not_corroborate():
    result = check_masquerade(
        actual_filename="evil.exe",
        version_info={"company_name": "Microsoft Corporation"},
        signer_subject="CN=Some Other Signer",
    )

    assert result["claimed_vendor_mismatch"] is True


def test_check_masquerade_no_mismatch_for_unrecognized_vendor_name():
    result = check_masquerade(
        actual_filename="evil.exe",
        version_info={"company_name": "Totally Legit Software Co"},
        signer_subject=None,
    )

    assert result["claimed_vendor_mismatch"] is False
    assert result["claimed_vendor"] is None
