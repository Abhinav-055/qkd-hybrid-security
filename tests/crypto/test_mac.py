"""Crypto layer: HMAC-SHA3-256 KATs and constant-time verification.

`ref_hmac` below is HMAC written out from RFC 2104 (ipad/opad, 136-byte
SHA3-256 block) without using `hmac`, so agreement with `crypto.mac` is a
genuinely independent check rather than the same library twice. It is first
validated against the published RFC 4231 SHA-256 vectors.
"""
from __future__ import annotations

import hashlib

import pytest

from crypto import mac

SHA3_256_BLOCK_SIZE = 136


def ref_hmac(hash_ctor, block_size: int, key: bytes, message: bytes) -> bytes:
    """HMAC from first principles (RFC 2104), no `hmac` module involved."""
    if len(key) > block_size:
        key = hash_ctor(key).digest()
    key = key.ljust(block_size, b"\x00")
    inner = bytes(b ^ 0x36 for b in key)
    outer = bytes(b ^ 0x5C for b in key)
    return hash_ctor(outer + hash_ctor(inner + message).digest()).digest()


def test_reference_hmac_matches_rfc4231_sha256_vectors():
    """Validate the from-scratch HMAC against published vectors first."""
    # RFC 4231 test case 1
    assert ref_hmac(hashlib.sha256, 64, b"\x0b" * 20, b"Hi There").hex() == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
    # RFC 4231 test case 2
    assert ref_hmac(hashlib.sha256, 64, b"Jefe", b"what do ya want for nothing?").hex() == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


@pytest.mark.parametrize(
    "key,message",
    [
        (b"\x0b" * 20, b"Hi There"),
        (b"Jefe", b"what do ya want for nothing?"),
        (b"\xaa" * 200, b"key longer than the SHA3-256 block"),
        (b"k", b""),
        (b"\x01" * 32, bytes(range(256)) * 4),
    ],
)
def test_module_matches_independent_hmac(key, message):
    assert mac.compute_mac(key, message) == ref_hmac(
        hashlib.sha3_256, SHA3_256_BLOCK_SIZE, key, message
    )


# "hi_there" uses the RFC 4231 test-case-1 inputs under SHA3-256; the tag is
# cross-checked by `test_module_matches_independent_hmac` above.
FROZEN_TAGS = {
    "hi_there": "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
    "transcript": "497f16f594543aea3d25ba0ff776223c9215c69760d25e76b759fa719110a77b",
}


def test_frozen_tags():
    """Pinned tags, so the transcript MAC cannot change unnoticed."""
    assert mac.compute_mac(b"\x0b" * 20, b"Hi There").hex() == FROZEN_TAGS["hi_there"]
    assert mac.compute_mac(b"k" * 32, b"M1|M2|M3|M4").hex() == FROZEN_TAGS["transcript"]


def test_tag_is_32_bytes():
    assert len(mac.compute_mac(b"key", b"msg")) == mac.MAC_LENGTH == 32


def test_verify_accepts_a_correct_tag():
    key, transcript = b"k" * 32, b"the whole transcript"
    assert mac.verify_mac(key, transcript, mac.compute_mac(key, transcript)) is True


def test_verify_rejects_a_wrong_key():
    transcript = b"the whole transcript"
    tag = mac.compute_mac(b"k" * 32, transcript)
    assert mac.verify_mac(b"j" * 32, transcript, tag) is False


def test_verify_rejects_a_tampered_transcript():
    key = b"k" * 32
    tag = mac.compute_mac(key, b"the whole transcript")
    assert mac.verify_mac(key, b"the whole transcripT", tag) is False


@pytest.mark.parametrize("tag", [b"", b"\x00" * 31, b"\x00" * 33])
def test_verify_rejects_a_wrong_length_tag(tag):
    assert mac.verify_mac(b"k" * 32, b"msg", tag) is False


def test_empty_key_is_rejected():
    with pytest.raises(ValueError):
        mac.compute_mac(b"", b"msg")


def test_verify_uses_constant_time_comparison():
    """Guard against a refactor back to `==` on the tag."""
    import inspect

    source = inspect.getsource(mac.verify_mac)
    assert "compare_digest" in source
