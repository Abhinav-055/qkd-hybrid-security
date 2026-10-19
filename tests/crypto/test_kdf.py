"""Crypto layer: HKDF-SHA3-256 correctness, KATs, and label separation.

There are no *published* HKDF-SHA3-256 test vectors, so correctness is
pinned three ways:

1. `test_rfc5869_*` -- an independent generic HKDF written from RFC 5869 in
   this file reproduces the RFC's published SHA-256 vectors. That validates
   the extract-then-expand construction itself.
2. `test_module_matches_*` -- the module (SHA3-256) agrees with that
   independent implementation, and with `cryptography`'s HKDF when
   installed.
3. `test_frozen_vectors` -- hardcoded digests, so a future refactor that
   changes derived keys fails loudly.
"""
from __future__ import annotations

import hashlib
import hmac

import pytest

from crypto import kdf


# -- independent reference implementation (RFC 5869, hash-agnostic) ----------


def ref_hkdf(hash_ctor, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    hash_len = hash_ctor().digest_size
    prk = hmac.new(salt or bytes(hash_len), ikm, hash_ctor).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hash_ctor).digest()
        okm += block
        counter += 1
    return okm[:length]


# -- RFC 5869 published vectors (SHA-256) ------------------------------------

RFC5869_CASES = [
    # (ikm, salt, info, length, expected okm) -- A.1, A.2, A.3
    (
        bytes.fromhex("0b" * 22),
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    ),
    (
        bytes.fromhex("".join(f"{i:02x}" for i in range(0x50))),
        bytes.fromhex("".join(f"{i:02x}" for i in range(0x60, 0xB0))),
        bytes.fromhex("".join(f"{i:02x}" for i in range(0xB0, 0x100))),
        82,
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb4"
        "1c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ),
    (
        bytes.fromhex("0b" * 22),
        b"",
        b"",
        42,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    ),
]


@pytest.mark.parametrize("ikm,salt,info,length,expected", RFC5869_CASES)
def test_rfc5869_vectors_validate_the_construction(ikm, salt, info, length, expected):
    okm = ref_hkdf(hashlib.sha256, ikm, salt, info, length)
    assert okm.hex() == expected


# -- the module agrees with independent implementations ----------------------


@pytest.mark.parametrize("length", [1, 16, 32, 42, 64, 255 * 32])
def test_module_matches_independent_reference(length):
    ikm, salt, info = b"input key material", b"salty", b"qkd-hake v1 | test"
    assert kdf.hkdf_sha3_256(ikm, salt, info, length) == ref_hkdf(
        hashlib.sha3_256, ikm, salt, info, length
    )


def test_module_matches_cryptography_hkdf():
    """Cross-check against a third-party HKDF, when `cryptography` is present."""
    hazmat = pytest.importorskip("cryptography.hazmat.primitives.kdf.hkdf")
    hashes = pytest.importorskip("cryptography.hazmat.primitives.hashes")

    ikm, salt, info = b"ss_lt||ss_eph||qkd", b"transcript-hash", b"qkd-hake v1 | session-key"
    expected = hazmat.HKDF(
        algorithm=hashes.SHA3_256(), length=48, salt=salt, info=info
    ).derive(ikm)
    assert kdf.hkdf_sha3_256(ikm, salt, info, 48) == expected


def test_empty_salt_is_zero_filled_per_rfc5869():
    ikm, info = b"ikm", b"info"
    assert kdf.hkdf_sha3_256(ikm, b"", info, 32) == kdf.hkdf_sha3_256(
        ikm, bytes(32), info, 32
    )


@pytest.mark.parametrize("length", [0, -1, 255 * 32 + 1])
def test_invalid_output_lengths_rejected(length):
    with pytest.raises(ValueError):
        kdf.hkdf_sha3_256(b"ikm", b"salt", b"info", length)


# -- frozen regression vectors ------------------------------------------------

FROZEN = {
    "hkdf": "f427696ea93329741b61ad598fcf66b6ddf278fd210da080301c91ed4efe71ac",
    "session": "a6a80992ca5f5ccc48eaa8b607e03952e9e84198884c96038333f1a7dc4ffc03",
    "confirm_initiator": "6926a6ccd14f85e48eb5be064577f3c28ffc7526cdd916b37eaea0d7bd349374",
    "confirm_responder": "7398d0ba211dfb84dc032830de167ce8046a6eb9fae5064bcf5e34b9cb0c67c8",
}


def test_frozen_vectors():
    """Pinned outputs, so a refactor cannot silently change derived keys."""
    ikm = bytes(range(32)) + bytes(range(32, 64))
    th = bytes.fromhex("aa" * 32)

    assert kdf.hkdf_sha3_256(ikm, b"salt", b"info", 32).hex() == FROZEN["hkdf"]
    assert kdf.derive_session_key(ikm, th).hex() == FROZEN["session"]
    assert kdf.derive_confirmation_key(ikm, th, "initiator").hex() == FROZEN["confirm_initiator"]
    assert kdf.derive_confirmation_key(ikm, th, "responder").hex() == FROZEN["confirm_responder"]


# -- label separation ---------------------------------------------------------


def test_labels_are_structured_and_versioned():
    th = bytes.fromhex("bb" * 32)
    assert kdf.label(kdf.PURPOSE_SESSION_KEY, th) == (
        b"qkd-hake v1 | session-key | " + b"bb" * 32
    )
    assert kdf.role_label(kdf.PURPOSE_CONFIRMATION_KEY, b"initiator", th) == (
        b"qkd-hake v1 | confirmation-key | initiator | " + b"bb" * 32
    )


def test_changing_the_label_changes_the_key():
    ikm, salt = b"same ikm", b"same salt"
    a = kdf.hkdf_sha3_256(ikm, salt, b"qkd-hake v1 | session-key", 32)
    b = kdf.hkdf_sha3_256(ikm, salt, b"qkd-hake v1 | session-keys", 32)
    assert a != b


def test_session_and_confirmation_keys_are_independent():
    ikm, th = b"ikm", bytes.fromhex("cc" * 32)
    session = kdf.derive_session_key(ikm, th)
    initiator = kdf.derive_confirmation_key(ikm, th, "initiator")
    responder = kdf.derive_confirmation_key(ikm, th, "responder")
    assert len({session, initiator, responder}) == 3


def test_role_must_be_a_known_role():
    with pytest.raises(ValueError):
        kdf.derive_confirmation_key(b"ikm", bytes(32), "eavesdropper")


def test_transcript_hash_is_order_and_content_sensitive():
    assert kdf.transcript_hash(b"a", b"b") == kdf.transcript_hash(b"ab")
    assert kdf.transcript_hash(b"a", b"b") != kdf.transcript_hash(b"b", b"a")
    assert len(kdf.transcript_hash(b"x")) == 32


def test_dropping_the_qkd_contribution_changes_the_session_key():
    """The core of the study: an absent QKD key yields a different session key."""
    th = kdf.transcript_hash(b"transcript")
    ss_lt, ss_eph, qkd = b"L" * 32, b"E" * 32, b"Q" * 32
    hybrid = kdf.derive_session_key(ss_lt + ss_eph + qkd, th)
    computational_only = kdf.derive_session_key(ss_lt + ss_eph + b"", th)
    assert hybrid != computational_only
