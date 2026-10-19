"""Initiator side of the four-message signature-free HAKE.

Key schedule (DECISIONS.md D1/D3):

    ss_longterm = ss_lt_I || ss_lt_R          # mutual implicit authentication
    ikm         = ss_longterm || ss_eph || (qkd_key or b"")
    th3         = SHA3-256(M1 || M2 || M3_body)
    th4         = SHA3-256(M1 || M2 || M3_body || M4_body)
    k_conf_*    = HKDF(ikm, salt=th3, info=".. | confirmation-key | <role> | ..")
    session_key = HKDF(ikm, salt=th4, info=".. | session-key | ..")

When `qkd_key` is absent the concatenation contributes `b""` and the session
is computationally-only secure. Reproducing that silently is the experiment.
"""
from __future__ import annotations

import secrets
from dataclasses import replace
from typing import Optional

from crypto.kdf import derive_confirmation_key, derive_session_key, transcript_hash
from crypto.kem import EphemeralKEM, LongTermKEM
from crypto.mac import compute_mac, verify_mac
from qkd_client import QKDClient, QKDUnavailable

from .messages import (
    NONCE_BYTES,
    SESSION_ID_BYTES,
    Message1,
    Message2,
    Message3,
    Message4,
    MessageFormatError,
)
from .session import (
    HandshakeResult,
    ProtocolError,
    SecurityMode,
    Session,
    build_result,
    suite_name,
)
from .state_machine import HandshakeState, StateMachine


class Initiator:
    """One handshake attempt, driven by `start()` then the two receive steps.

    An instance is single-use: a second handshake needs a new `Initiator`,
    because the ephemeral keypair and nonces must be fresh.
    """

    role = "initiator"

    def __init__(
        self,
        identity_id: str,
        long_term: LongTermKEM,
        peer_public_key: bytes,
        peer_id: str,
        qkd_client: Optional[QKDClient] = None,
        ephemeral_algorithm: Optional[str] = None,
        session_id: Optional[bytes] = None,
    ) -> None:
        self.identity_id = identity_id
        self.long_term = long_term
        self.peer_public_key = peer_public_key
        self.peer_id = peer_id
        self.qkd_client = qkd_client
        self.ephemeral = EphemeralKEM(ephemeral_algorithm or long_term.algorithm)
        self.suite = suite_name(long_term.algorithm, self.ephemeral.algorithm)

        self.machine = StateMachine(self.role)
        self.session = Session(
            session_id=session_id or secrets.token_bytes(SESSION_ID_BYTES),
            role=self.role,
            peer_id=peer_id,
            suite=self.suite,
            qkd_disabled=qkd_client is None,
        )

        self._nonce_i = b""
        self._qkd_key: Optional[bytes] = None
        self._m1 = b""
        self._m2 = b""
        self._m3_body = b""
        self._ikm = b""
        self._th3 = b""

    # -- flight 1 ------------------------------------------------------------

    def start(self) -> bytes:
        """Produce M1: fresh ephemeral key, nonce, and a QKD key id if we got one.

        Under `STRICT_ERROR` an empty pool raises `QKDUnavailable` here, and
        the handshake never leaves INIT with a usable message.
        """
        self.machine.require(HandshakeState.INIT)

        self._nonce_i = secrets.token_bytes(NONCE_BYTES)
        epk_i = self.ephemeral.generate()
        qkd_key_id = ""

        if self.qkd_client is not None:
            try:
                key_result = self.qkd_client.get_key(peer_id=self.peer_id)
            except QKDUnavailable:
                # STRICT_ERROR: let QKDUnavailable propagate to the caller, as
                # specified, having recorded the failure on the state machine.
                self.machine.fail("QKD unavailable at initiator")
                raise
            if key_result.qkd_used:
                self._qkd_key = key_result.key
                qkd_key_id = key_result.key_id or ""
                self.session.qkd_key_id = key_result.key_id
            else:
                # Empty pool in a non-strict mode: carry on without QKD. The
                # application is not told yet -- and under REFERENCE_SILENT it
                # never will be.
                self.session.downgraded = True

        message = Message1(
            session_id=self.session.session_id,
            nonce_i=self._nonce_i,
            suite=self.suite,
            epk_i=epk_i,
            qkd_key_id=qkd_key_id,
        )
        self._m1 = message.encode()
        self.session.bytes_sent += len(self._m1)
        self.session.messages["m1"] = len(self._m1)
        self.machine.transition(HandshakeState.SEND_1)
        self.machine.transition(HandshakeState.WAIT_2)
        return self._m1

    # -- flight 2/3 ----------------------------------------------------------

    def receive_message_2(self, data: bytes) -> bytes:
        """Consume M2, derive the key material, and produce M3 with our MAC."""
        self.machine.require(HandshakeState.WAIT_2)
        try:
            m2 = Message2.decode(data)
        except MessageFormatError as exc:
            raise self.machine.fail(f"malformed M2: {exc}") from exc
        if m2.session_id != self.session.session_id:
            raise self.machine.fail("M2 session_id does not match M1")

        self._m2 = data
        self.session.bytes_received += len(data)
        self.session.messages["m2"] = len(data)

        # ss_eph: forward secrecy. ss_lt_i: we prove we own sk_I by recovering it.
        try:
            ss_eph = self.ephemeral.decapsulate(m2.ct_eph)
            ss_lt_i = self.long_term.decapsulate(m2.ct_lt_i)
        except Exception as exc:  # liboqs size/format rejection
            raise self.machine.fail(f"decapsulation failed: {exc}") from exc

        # The responder could not use the QKD key we named, so we must drop it
        # too or our session keys would differ (DECISIONS.md D4).
        if self._qkd_key is not None and not m2.qkd_ack:
            self._qkd_key = None
            self.session.qkd_key_id = None
            self.session.downgraded = True

        # ss_lt_r: the responder proves it owns sk_R by recovering this.
        encapsulation = self.long_term.encapsulate_to(self.peer_public_key)
        ss_lt_r = encapsulation.shared_secret

        self._ikm = ss_lt_i + ss_lt_r + ss_eph + (self._qkd_key or b"")
        self.ephemeral.forget()

        m3 = Message3(session_id=self.session.session_id, ct_lt_r=encapsulation.ciphertext)
        self._m3_body = m3.body()
        self._th3 = transcript_hash(self._m1, self._m2, self._m3_body)

        k_conf_i = derive_confirmation_key(self._ikm, self._th3, "initiator")
        mac_i = compute_mac(k_conf_i, self._m1 + self._m2 + self._m3_body)

        encoded = replace(m3, mac=mac_i).encode()
        self.session.bytes_sent += len(encoded)
        self.session.messages["m3"] = len(encoded)
        self.machine.transition(HandshakeState.SEND_3)
        self.machine.transition(HandshakeState.WAIT_4)
        return encoded

    # -- flight 4 ------------------------------------------------------------

    def receive_message_4(self, data: bytes) -> HandshakeResult:
        """Verify the responder's MAC, derive the session key, and report."""
        self.machine.require(HandshakeState.WAIT_4)
        try:
            m4 = Message4.decode(data)
        except MessageFormatError as exc:
            raise self.machine.fail(f"malformed M4: {exc}") from exc
        if m4.session_id != self.session.session_id:
            raise self.machine.fail("M4 session_id does not match M1")

        self.session.bytes_received += len(data)
        self.session.messages["m4"] = len(data)
        self.machine.transition(HandshakeState.CONFIRM)

        m4_body = m4.body()
        full_transcript = self._m1 + self._m2 + self._m3_body + m4_body
        k_conf_r = derive_confirmation_key(self._ikm, self._th3, "responder")
        if not verify_mac(k_conf_r, full_transcript, m4.mac):
            raise self.machine.fail("responder MAC verification failed")

        # The flags are MAC-protected, so a mismatch is real disagreement
        # about what was negotiated, not tampering.
        expected_hybrid = self._qkd_key is not None
        if m4.hybrid != expected_hybrid:
            raise self.machine.fail(
                f"security mode disagreement: responder says hybrid={m4.hybrid}, "
                f"we hold qkd_key={expected_hybrid}"
            )

        th4 = transcript_hash(full_transcript)
        self.session.transcript_hash = th4
        self.session.session_key = derive_session_key(self._ikm, th4)
        self.session.security_mode = (
            SecurityMode.HYBRID if expected_hybrid else SecurityMode.COMPUTATIONAL_ONLY
        )
        if m4.downgraded:
            self.session.downgraded = True
        self.machine.transition(HandshakeState.ESTABLISHED)
        return self._result()

    # -- convenience ---------------------------------------------------------

    def result(self) -> HandshakeResult:
        if not self.machine.is_established:
            raise ProtocolError(f"handshake is in {self.machine.state.value}, not established")
        return self._result()

    def _result(self) -> HandshakeResult:
        return build_result(self.session, self.qkd_client)

    @property
    def state(self) -> HandshakeState:
        return self.machine.state
