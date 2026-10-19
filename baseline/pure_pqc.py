"""Pure-PQC baseline: the same four-message HAKE with no QKD at all.

This exists so the benchmark can quote an honest "cost of hybridization"
number. It reuses the protocol's state machine, wire format, and crypto
layer unchanged -- the only difference is that no QKD client is constructed,
so the KDF's QKD contribution is `b""` on both sides.

That makes the comparison clean: any latency, CPU, or wire-size difference
against the hybrid run is attributable to QKD key acquisition, not to a
different protocol.

A baseline session is `COMPUTATIONAL_ONLY` but **not** `downgraded`: it never
claimed hybrid security, so there is nothing to have lost. Keeping those two
facts separate is what lets the downgrade study count only real downgrades.
"""
from __future__ import annotations

from typing import Optional

from crypto.kem import DEFAULT_KEM
from protocol import HandshakeOutcome, PeerPair, run_handshake
from protocol.initiator import Initiator
from protocol.responder import Responder
from protocol.session import SecurityMode

PROTOCOL_NAME = "pure-pqc"


class PurePQCInitiator(Initiator):
    """An `Initiator` that structurally cannot use QKD."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.pop("qkd_client", None)
        super().__init__(*args, qkd_client=None, **kwargs)  # type: ignore[arg-type]


class PurePQCResponder(Responder):
    """A `Responder` that structurally cannot use QKD."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.pop("qkd_client", None)
        super().__init__(*args, qkd_client=None, **kwargs)  # type: ignore[arg-type]


def generate_peers(
    algorithm: str = DEFAULT_KEM,
    initiator_id: str = "SAE-ALICE",
    responder_id: str = "SAE-BOB",
) -> PeerPair:
    """Long-term identity keys for the baseline, same shape as the hybrid run."""
    return PeerPair.generate(algorithm, initiator_id=initiator_id, responder_id=responder_id)


def run_pure_pqc_handshake(
    peers: PeerPair, ephemeral_algorithm: Optional[str] = None
) -> HandshakeOutcome:
    """One baseline handshake. Never touches the QKD server."""
    outcome = run_handshake(
        peers,
        initiator_qkd=None,
        responder_qkd=None,
        ephemeral_algorithm=ephemeral_algorithm,
        initiator_cls=PurePQCInitiator,
        responder_cls=PurePQCResponder,
    )
    session = outcome.initiator.internal_session
    # Invariants worth asserting: a baseline run that somehow acquired QKD
    # material, or that reported a downgrade, would silently corrupt the
    # "cost of hybridization" comparison.
    assert session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
    assert session.qkd_key_id is None
    assert session.downgraded is False
    assert session.qkd_disabled is True
    return outcome
