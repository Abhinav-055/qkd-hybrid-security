"""Four-message signature-free hybrid PQC+QKD authenticated key exchange.

Public API:

    peers = PeerPair.generate("ML-KEM-768")        # long-term trust, out-of-band
    outcome = run_handshake(peers, initiator_qkd=client, responder_qkd=client)
    outcome.initiator.session_key == outcome.responder.session_key
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from crypto.kem import DEFAULT_KEM, LongTermKEM

from .initiator import Initiator
from .messages import Message1, Message2, Message3, Message4, MessageFormatError
from .responder import Responder
from .session import (
    DEFAULT_SUITE,
    HandshakeResult,
    ProtocolError,
    SecurityDowngradeWarning,
    SecurityMode,
    Session,
    parse_suite,
    suite_name,
)
from .state_machine import (
    HandshakeFailed,
    HandshakeState,
    InvalidTransition,
    StateMachine,
)

__all__ = [
    "DEFAULT_SUITE",
    "HandshakeFailed",
    "HandshakeOutcome",
    "HandshakeResult",
    "HandshakeState",
    "Initiator",
    "InvalidTransition",
    "Message1",
    "Message2",
    "Message3",
    "Message4",
    "MessageFormatError",
    "PeerPair",
    "ProtocolError",
    "Responder",
    "SecurityDowngradeWarning",
    "SecurityMode",
    "Session",
    "StateMachine",
    "parse_suite",
    "run_handshake",
    "suite_name",
]


@dataclass(frozen=True)
class PeerPair:
    """Long-term identity keys for the two parties, plus the trust they share.

    Generated once and reused across handshakes, which is the point of a
    long-term key: keygen cost must not be charged to every session.
    """

    initiator_id: str
    responder_id: str
    initiator_long_term: LongTermKEM
    responder_long_term: LongTermKEM

    @classmethod
    def generate(
        cls,
        algorithm: str = DEFAULT_KEM,
        initiator_id: str = "SAE-ALICE",
        responder_id: str = "SAE-BOB",
    ) -> "PeerPair":
        return cls(
            initiator_id=initiator_id,
            responder_id=responder_id,
            initiator_long_term=LongTermKEM(algorithm),
            responder_long_term=LongTermKEM(algorithm),
        )

    @property
    def algorithm(self) -> str:
        return self.initiator_long_term.algorithm


@dataclass
class HandshakeOutcome:
    """Both sides' public results, plus the cost of the exchange."""

    initiator: HandshakeResult
    responder: HandshakeResult
    latency_ms: float
    cpu_ms: float
    #: From the initiator's point of view (DECISIONS.md D8).
    bytes_sent: int
    bytes_received: int

    @property
    def keys_match(self) -> bool:
        return (
            self.initiator.session_key == self.responder.session_key
            and len(self.initiator.session_key) == 32
        )


def run_handshake(
    peers: PeerPair,
    initiator_qkd=None,
    responder_qkd=None,
    ephemeral_algorithm: Optional[str] = None,
    initiator_cls: type[Initiator] = Initiator,
    responder_cls: type[Responder] = Responder,
) -> HandshakeOutcome:
    """Drive one complete handshake, handing message bytes between the roles.

    Messages are exchanged in-process (DECISIONS.md D8): only the QKD client
    does network I/O. Raises whatever the protocol raises -- `QKDUnavailable`
    under `STRICT_ERROR`, `HandshakeFailed` on a MAC or format failure.
    """
    initiator = initiator_cls(
        identity_id=peers.initiator_id,
        long_term=peers.initiator_long_term,
        peer_public_key=peers.responder_long_term.public_key,
        peer_id=peers.responder_id,
        qkd_client=initiator_qkd,
        ephemeral_algorithm=ephemeral_algorithm,
    )
    responder = responder_cls(
        identity_id=peers.responder_id,
        long_term=peers.responder_long_term,
        peer_public_key=peers.initiator_long_term.public_key,
        peer_id=peers.initiator_id,
        qkd_client=responder_qkd,
        ephemeral_algorithm=ephemeral_algorithm,
    )

    wall_start = time.perf_counter()
    cpu_start = time.process_time()

    m1 = initiator.start()
    m2 = responder.receive_message_1(m1)
    m3 = initiator.receive_message_2(m2)
    m4 = responder.receive_message_3(m3)
    initiator_result = initiator.receive_message_4(m4)

    latency_ms = (time.perf_counter() - wall_start) * 1000.0
    cpu_ms = (time.process_time() - cpu_start) * 1000.0

    return HandshakeOutcome(
        initiator=initiator_result,
        responder=responder.result(),
        latency_ms=latency_ms,
        cpu_ms=cpu_ms,
        bytes_sent=initiator.session.bytes_sent,
        bytes_received=initiator.session.bytes_received,
    )
