"""Crypto layer: KEM roles, HKDF-SHA3-256, transcript MAC.

Nothing in this package knows the QKD server exists. QKD key material
arrives here as plain bytes, handed in by the protocol layer.
"""

from .kdf import (
    derive_confirmation_key,
    derive_session_key,
    hkdf_sha3_256,
    transcript_hash,
)
from .kem import (
    DEFAULT_KEM,
    SUPPORTED_KEMS,
    EphemeralKEM,
    KEM,
    KEMError,
    KeyPair,
    LongTermKEM,
    UnsupportedKEM,
    available_kems,
    kem_sizes,
)
from .mac import MAC_LENGTH, compute_mac, verify_mac

__all__ = [
    "DEFAULT_KEM",
    "SUPPORTED_KEMS",
    "MAC_LENGTH",
    "EphemeralKEM",
    "KEM",
    "KEMError",
    "KeyPair",
    "LongTermKEM",
    "UnsupportedKEM",
    "available_kems",
    "compute_mac",
    "derive_confirmation_key",
    "derive_session_key",
    "hkdf_sha3_256",
    "kem_sizes",
    "transcript_hash",
    "verify_mac",
]
