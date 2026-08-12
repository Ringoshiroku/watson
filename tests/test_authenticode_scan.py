import datetime

import pytest
from signify.authenticode import AuthenticodeVerificationResult

from watson.authenticode_scan import AuthenticodeScanError, verify_signature


def test_verify_signature_raises_for_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.exe"

    with pytest.raises(AuthenticodeScanError):
        verify_signature(missing)


class _FakeCertificate:
    subject = "CN=Watson Test Signer, O=Watson Test Fixtures"
    issuer = "CN=Watson Test Root"
    valid_from = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    valid_to = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)


class _FakeCertificates:
    def find_certificates(self, issuer=None, serial_number=None):
        return [_FakeCertificate()]


class _FakeSignerInfo:
    issuer = "CN=Watson Test Root"
    serial_number = 1


class _FakeSignature:
    signer_info = _FakeSignerInfo()
    certificates = _FakeCertificates()


class _FakeAuthenticodeFile:
    signatures = [_FakeSignature()]

    def explain_verify(self):
        return AuthenticodeVerificationResult.OK, None

    @classmethod
    def from_stream(cls, stream):
        return cls()


def test_verify_signature_valid_returns_signer_details(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "signify.authenticode.AuthenticodeFile", _FakeAuthenticodeFile
    )
    fake_file = tmp_path / "fake.exe"
    fake_file.write_bytes(b"not a real PE, the parser is mocked")

    result = verify_signature(fake_file)

    assert result["status"] == "valid"
    assert result["verification_result"] == "OK"
    assert result["error"] is None
    assert result["signer_subject"] == "CN=Watson Test Signer, O=Watson Test Fixtures"
    assert result["signer_issuer"] == "CN=Watson Test Root"
    assert result["valid_from"] == "2026-01-01T00:00:00+00:00"
    assert result["valid_to"] == "2027-01-01T00:00:00+00:00"


class _FakeAuthenticodeFileInvalid(_FakeAuthenticodeFile):
    def explain_verify(self):
        return AuthenticodeVerificationResult.CERTIFICATE_ERROR, Exception("untrusted root")


def test_verify_signature_invalid_reports_status_and_error(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "signify.authenticode.AuthenticodeFile", _FakeAuthenticodeFileInvalid
    )
    fake_file = tmp_path / "fake.exe"
    fake_file.write_bytes(b"not a real PE, the parser is mocked")

    result = verify_signature(fake_file)

    assert result["status"] == "invalid"
    assert result["verification_result"] == "CERTIFICATE_ERROR"
    assert result["error"] == "untrusted root"


def test_verify_signature_self_signed_pe_is_invalid(self_signed_pe):
    result = verify_signature(self_signed_pe)

    assert result["status"] == "invalid"
    assert result["verification_result"] != "OK"
    assert result["signer_subject"] is not None
    assert "Watson Test Signer" in result["signer_subject"]


def test_verify_signature_tampered_pe_is_invalid(tampered_signed_pe):
    result = verify_signature(tampered_signed_pe)

    assert result["status"] == "invalid"
    assert result["verification_result"] != "OK"


class _FakeCertificateMalformed:
    @property
    def subject(self):
        raise ValueError("malformed ASN.1 distinguished name")

    issuer = "CN=Watson Test Root"
    valid_from = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    valid_to = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)


class _FakeCertificatesMalformed:
    def find_certificates(self, issuer=None, serial_number=None):
        return [_FakeCertificateMalformed()]


class _FakeSignatureMalformed:
    signer_info = _FakeSignerInfo()
    certificates = _FakeCertificatesMalformed()


class _FakeAuthenticodeFileMalformedCert(_FakeAuthenticodeFile):
    signatures = [_FakeSignatureMalformed()]


def test_verify_signature_wraps_malformed_certificate_error(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "signify.authenticode.AuthenticodeFile", _FakeAuthenticodeFileMalformedCert
    )
    fake_file = tmp_path / "fake.exe"
    fake_file.write_bytes(b"not a real PE, the parser is mocked")

    with pytest.raises(AuthenticodeScanError):
        verify_signature(fake_file)
