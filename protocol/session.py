"""Session/result types and the ciphersuite string shared by both roles.

The distinction that carries the whole study is between `Session` and
`HandshakeResult` (DECISIONS.md D5):

* `Session` always records the **truth** about what was negotiated. The
  experiments read it -- it is the measurement oracle.
* `HandshakeResult` is what the **application** sees. Under
  `REFERENCE_SILENT` its `downgraded` field is `None`: a caller has no way
  to tell a hybrid session from a PQC-only one. That is the phenomenon.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from crypto.kem import DEFAULT_KEM
from qkd_client import QKDClient, QKDMode

from .messages import FLAG_DOWNGRADED, FLAG_HYBRID


class SecurityMode(Enum):
    #: QKD key material contributed to the session key.
    HYBRID = "hybrid"
    #: Session key rests on the KEMs alone.
    COMPUTATIONAL_ONLY = "computational_only"


class SecurityDowngradeWarning(UserWarning):
    """Emitted under EXPLICIT_DOWNGRADE when a handshake lost its QKD input."""


class ProtocolError(RuntimeError):
    """A peer sent something unusable: bad suite, wrong session id, bad MAC."""


SUITE_PREFIX = "qkd-hake-v1"


def suite_name(long_term_algorithm: str, ephemeral_algorithm: str) -> str:
    """The ciphersuite identifier carried in M1, e.g.

    ``qkd-hake-v1/ML-KEM-768/ML-KEM-768``.
    """
    return f"{SUITE_PREFIX}/{long_term_algorithm}/{ephemeral_algorithm}"


def parse_suite(suite: str) -> tuple[str, str]:
    parts = suite.split("/")
    if len(parts) != 3 or parts[0] != SUITE_PREFIX:
        raise ProtocolError(f"unrecognised suite {suite!r}")
    return parts[1], parts[2]


@dataclass
class Session:
    """The ground truth about one completed (or failed) handshake."""

    session_id: bytes
    role: str
    peer_id: str
    suite: str
    session_key: bytes = b""
    security_mode: SecurityMode = SecurityMode.COMPUTATIONAL_ONLY
    qkd_key_id: Optional[str] = None
    downgraded: bool = False
    transcript_hash: bytes = b""
    bytes_sent: int = 0
    bytes_received: int = 0
    #: True when this handshake never intended to use QKD (pure-PQC baseline).
    qkd_disabled: bool = False
    messages: dict[str, int] = field(default_factory=dict)

    @property
    def is_hybrid(self) -> bool:
        return self.security_mode is SecurityMode.HYBRID


@dataclass
class HandshakeResult:
    """What `handshake()` hands back to the application.

    `downgraded` is `None` in `REFERENCE_SILENT` -- not `False`. "I was not
    told" and "it did not happen" are different facts, and conflating them is
    exactly the failure mode under study.
    """

    established: bool
    session_id: bytes
    session_key: bytes
    peer_id: str
    downgraded: Optional[bool]
    #: Measurement oracle. A realistic application ignores this field; the
    #: experiments read it to score what the application could not see.
    internal_session: Session

    @property
    def app_visible_downgrade(self) -> bool:
        """Did the application actually receive a downgrade signal?"""
        return self.downgraded is True


DEFAULT_SUITE = suite_name(DEFAULT_KEM, DEFAULT_KEM)


def build_result(session: Session, qkd_client: Optional[QKDClient]) -> HandshakeResult:
    """Project the true `Session` onto what the application is allowed to see.

    This function is the entire mechanism behind the three modes
    (DECISIONS.md D5): under `REFERENCE_SILENT` the public `downgraded` is
    `None`, so no amount of inspecting the public result reveals that the QKD
    contribution was missing.
    """
    mode = qkd_client.mode if qkd_client is not None else None

    if mode is QKDMode.EXPLICIT_DOWNGRADE:
        public_downgraded: Optional[bool] = session.downgraded
        if session.downgraded:
            warnings.warn(
                f"session {session.session_id.hex()} with {session.peer_id} completed "
                f"without QKD key material: security_mode={session.security_mode.value}",
                SecurityDowngradeWarning,
                stacklevel=3,
            )
    elif mode is QKDMode.REFERENCE_SILENT:
        # Deliberately withheld. This is the phenomenon under study.
        public_downgraded = None
    else:
        # STRICT_ERROR can only reach here having used QKD, and the pure-PQC
        # baseline never claimed hybrid security in the first place.
        public_downgraded = False

    return HandshakeResult(
        established=True,
        session_id=session.session_id,
        session_key=session.session_key,
        peer_id=session.peer_id,
        downgraded=public_downgraded,
        internal_session=session,
    )


def flags_for(session: Session) -> int:
    """The M4 flag byte describing what was negotiated."""
    flags = 0
    if session.security_mode is SecurityMode.HYBRID:
        flags |= FLAG_HYBRID
    if session.downgraded:
        flags |= FLAG_DOWNGRADED
    return flags
