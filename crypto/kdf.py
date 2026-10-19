"""HKDF-SHA3-256 with explicit, structured labels.

Every label in the protocol is built here and nowhere else (DECISIONS.md
D11), so there are no magic constants scattered across the codebase. The
shape is:

    b"qkd-hake v1 | <purpose> | <hex transcript hash>"

Domain separation matters for the research question: the session key and the
two confirmation keys come from the same IKM, so a label collision would
make key confirmation meaningless.
"""
from __future__ import annotations

import hashlib
import hmac

HASH = hashlib.sha3_256
HASH_LENGTH = 32

#: Protocol/version tag that prefixes every label.
PROTOCOL_LABEL = b"qkd-hake v1"

PURPOSE_SESSION_KEY = b"session-key"
PURPOSE_CONFIRMATION_KEY = b"confirmation-key"

DEFAULT_KEY_LENGTH = 32


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 extract step with SHA3-256."""
    if not salt:
        salt = b"\x00" * HASH_LENGTH
    return hmac.new(salt, ikm, HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 expand step with SHA3-256."""
    if length <= 0:
        raise ValueError("length must be positive")
    max_length = 255 * HASH_LENGTH
    if length > max_length:
        raise ValueError(f"length {length} exceeds HKDF maximum {max_length}")

    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), HASH).digest()
        okm.extend(block)
        counter += 1
    return bytes(okm[:length])


def hkdf_sha3_256(ikm: bytes, salt: bytes, info: bytes, length: int = DEFAULT_KEY_LENGTH) -> bytes:
    """Full HKDF-SHA3-256 (extract-then-expand)."""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def label(purpose: bytes, transcript_hash: bytes) -> bytes:
    """Build the structured `info` label for one purpose and one transcript."""
    return b" | ".join((PROTOCOL_LABEL, purpose, transcript_hash.hex().encode("ascii")))


def role_label(purpose: bytes, role: bytes, transcript_hash: bytes) -> bytes:
    """Role-separated label, so the two confirmation keys can never collide."""
    return b" | ".join(
        (PROTOCOL_LABEL, purpose, role, transcript_hash.hex().encode("ascii"))
    )


def derive_session_key(
    ikm: bytes, transcript_hash: bytes, length: int = DEFAULT_KEY_LENGTH
) -> bytes:
    """The HAKE session key.

    `ikm` is ``ss_longterm || ss_ephemeral || qkd_key``, where the QKD
    contribution is ``b""`` when no QKD key was available. That empty
    contribution is precisely what turns a hybrid session into a
    computationally-only-secure one.
    """
    return hkdf_sha3_256(
        ikm=ikm,
        salt=transcript_hash,
        info=label(PURPOSE_SESSION_KEY, transcript_hash),
        length=length,
    )


def derive_confirmation_key(
    ikm: bytes, transcript_hash: bytes, role: str, length: int = DEFAULT_KEY_LENGTH
) -> bytes:
    """The key that MACs the transcript, one per role ("initiator"/"responder")."""
    if role not in ("initiator", "responder"):
        raise ValueError(f"role must be 'initiator' or 'responder', got {role!r}")
    return hkdf_sha3_256(
        ikm=ikm,
        salt=transcript_hash,
        info=role_label(PURPOSE_CONFIRMATION_KEY, role.encode("ascii"), transcript_hash),
        length=length,
    )


def transcript_hash(*chunks: bytes) -> bytes:
    """SHA3-256 over the concatenation of the given transcript chunks."""
    digest = HASH()
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()
