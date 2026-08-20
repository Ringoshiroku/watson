from __future__ import annotations

from pathlib import Path


class AuthenticodeScanError(Exception):
    """Raised when a file can't be opened or parsed for Authenticode verification."""


def _signer_details(authenticode_file) -> dict:
    for signature in authenticode_file.signatures:
        signer_info = getattr(signature, "signer_info", None)
        certificates = getattr(signature, "certificates", None)
        if signer_info is None or certificates is None:
            continue
        matches = list(
            certificates.find_certificates(
                issuer=signer_info.issuer, serial_number=signer_info.serial_number
            )
        )
        if not matches:
            continue
        cert = matches[0]
        return {
            "signer_subject": str(cert.subject),
            "signer_issuer": str(cert.issuer),
            "valid_from": cert.valid_from.isoformat(),
            "valid_to": cert.valid_to.isoformat(),
        }
    return {"signer_subject": None, "signer_issuer": None, "valid_from": None, "valid_to": None}


def verify_signature(file_path: Path) -> dict:
    try:
        from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult
        from signify.exceptions import ParseError
    except Exception as import_exc:
        raise AuthenticodeScanError(f"signify is unusable: {import_exc}") from import_exc

    try:
        with open(file_path, "rb") as stream:
            authenticode_file = AuthenticodeFile.from_stream(stream)
            result, exc = authenticode_file.explain_verify()
            details = _signer_details(authenticode_file)
    except OSError as os_exc:
        raise AuthenticodeScanError(f"could not open {file_path}: {os_exc}") from os_exc
    except ParseError as parse_exc:
        raise AuthenticodeScanError(f"could not parse signature in {file_path}: {parse_exc}") from parse_exc
    except Exception as exc:
        raise AuthenticodeScanError(f"could not verify signature in {file_path}: {exc}") from exc

    status = "valid" if result == AuthenticodeVerificationResult.OK else "invalid"
    return {
        "status": status,
        "verification_result": result.name,
        "error": str(exc) if exc else None,
        **details,
    }
