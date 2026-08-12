from __future__ import annotations

from typing import Optional

_KNOWN_VENDORS = (
    "Microsoft Corporation",
    "Google LLC",
    "Adobe",
    "Mozilla Corporation",
    "Apple Inc.",
    "Oracle",
    "Intel Corporation",
    "NVIDIA Corporation",
    "VMware, Inc.",
)


def _claimed_vendor(company_name: Optional[str]) -> Optional[str]:
    if not company_name:
        return None
    lowered = company_name.lower()
    for vendor in _KNOWN_VENDORS:
        if vendor.lower() in lowered:
            return vendor
    return None


def check_masquerade(actual_filename: str, version_info: dict, signer_subject: Optional[str]) -> dict:
    original = version_info.get("original_filename") or version_info.get("internal_name")
    filename_mismatch = bool(original) and original.lower() != actual_filename.lower()

    claimed_vendor = _claimed_vendor(version_info.get("company_name"))
    claimed_vendor_mismatch = claimed_vendor is not None and (
        signer_subject is None or claimed_vendor.lower() not in signer_subject.lower()
    )

    return {
        "filename_mismatch": filename_mismatch,
        "claimed_vendor_mismatch": claimed_vendor_mismatch,
        "claimed_vendor": claimed_vendor,
    }
