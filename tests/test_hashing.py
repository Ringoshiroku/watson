import hashlib

from watson.hashing import compute_hashes


def test_compute_hashes_matches_hashlib(tmp_path):
    file_path = tmp_path / "sample.bin"
    payload = b"watson test payload"
    file_path.write_bytes(payload)

    result = compute_hashes(file_path)

    assert result["md5"] == hashlib.md5(payload).hexdigest()
    assert result["sha1"] == hashlib.sha1(payload).hexdigest()
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
