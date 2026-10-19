"""HMAC-SHA3-256 transcript confirmation MAC.

The MAC covers the full handshake transcript -- M1..M4 with each message's
own MAC field removed (DECISIONS.md D2/D3). Verification is constant-time.
"""
from __future__ import annotations

import hashlib
import hmac

HASH = hashlib.sha3_256
MAC_LENGTH = 32


def compute_mac(key: bytes, transcript: bytes) -> bytes:
    """HMAC-SHA3-256 tag over the transcript."""
    if not key:
        raise ValueError("MAC key must not be empty")
    return hmac.new(key, transcript, HASH).digest()


def verify_mac(key: bytes, transcript: bytes, tag: bytes) -> bool:
    """Constant-time verification. Returns False rather than raising."""
    if len(tag) != MAC_LENGTH:
        return False
    return hmac.compare_digest(compute_mac(key, transcript), tag)
