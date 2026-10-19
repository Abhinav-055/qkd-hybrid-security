"""Responder side of the four-message signature-free HAKE.

The responder never pulls a key from the pool. It fetches the key material
the initiator already paid for, by id, over ETSI ``dec_keys`` -- so one
handshake still costs exactly one QKD key, which is what makes the
``supply_bps / 256`` ceiling meaningful (DECISIONS.md D4).
"""
from __future__ import annotations

import secrets
from dataclasses import replace
from typing import Optional

from crypto.kdf import derive_confirmation_key, derive_session_key, transcript_hash
from crypto.kem import EphemeralKEM, LongTermKEM
from crypto.mac import compute_mac, verify_mac
from qkd_client import QKDClient, QKDMode, QKDServerError, QKDUnavailable

from .messages import (
    FLAG_QKD_ACK,
    NONCE_BYTES,
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
    flags_for,
    suite_name,
)
from .state_machine import HandshakeState, StateMachine


class Responder:
    """One handshake attempt, driven by the two receive steps.

    Like `Initiator`, an instance is single-use.
    """

    role = "responder"

    def __init__(
        self,
        identity_id: str,
        long_term: LongTermKEM,
        peer_public_key: bytes,
        peer_id: str,
        qkd_client: Optional[QKDClient] = None,
        ephemeral_algorithm: Optional[str] = None,
    ) -> None:
        self.identity_id = identity_id
        self.long_term = long_term
        self.peer_public_key = peer_public_key
        self.peer_id = peer_id
        self.qkd_client = qkd_client
        self.ephemeral = EphemeralKEM(ephemeral_algorithm or long_term.algorithm)
        self.expected_suite = suite_name(long_term.algorithm, self.ephemeral.algorithm)

        self.machine = StateMachine(self.role)
        self.session = Session(
            session_id=b"",
            role=self.role,
            peer_id=peer_id,
            suite=self.expected_suite,
            qkd_disabled=qkd_client is None,
        )

        self._qkd_key: Optional[bytes] = None
        self._m1 = b""
        self._m2 = b""
        self._m3_body = b""
        self._ikm_prefix = b""
        self._ss_lt_i = b""
        self._ss_eph = b""

    # -- flight 1/2 ----------------------------------------------------------

    def receive_message_1(self, data: bytes) -> bytes:
        """Consume M1, fetch the named QKD key if we can, and produce M2."""
        self.machine.require(HandshakeState.INIT)
        try:
            m1 = Message1.decode(data)
        except MessageFormatError as exc:
            raise self.machine.fail(f"malformed M1: {exc}") from exc

        if m1.suite != self.expected_suite:
            raise self.machine.fail(
                f"suite mismatch: peer offered {m1.suite!r}, we speak {self.expected_suite!r}"
            )

        self.session.session_id = m1.session_id
        self._m1 = data
        self.session.bytes_received += len(data)
        self.session.messages["m1"] = len(data)

        qkd_ack = self._acquire_qkd_key(m1.qkd_key_id)

        # ss_eph to the initiator's ephemeral key: forward secrecy.
        # ss_lt_i to the initiator's long-term key: authenticates the initiator.
        try:
            eph = self.ephemeral.encapsulate_to(m1.epk_i)
            lt_i = self.long_term.encapsulate_to(self.peer_public_key)
        except Exception as exc:  # liboqs size/format rejection
            raise self.machine.fail(f"encapsulation failed: {exc}") from exc

        self._ss_eph = eph.shared_secret
        self._ss_lt_i = lt_i.shared_secret

        m2 = Message2(
            session_id=self.session.session_id,
            nonce_r=secrets.token_bytes(NONCE_BYTES),
            ct_eph=eph.ciphertext,
            ct_lt_i=lt_i.ciphertext,
            flags=FLAG_QKD_ACK if qkd_ack else 0,
        )
        self._m2 = m2.encode()
        self.session.bytes_sent += len(self._m2)
        self.session.messages["m2"] = len(self._m2)
        self.machine.transition(HandshakeState.SEND_1)
        self.machine.transition(HandshakeState.WAIT_2)
        return self._m2

    def _acquire_qkd_key(self, qkd_key_id: str) -> bool:
        """Fetch the initiator's QKD key by id. Returns whether QKD is in play.

        Three ways this ends without QKD:
        * the initiator had no key to name (its pool was empty, or it is the
          pure-PQC baseline),
        * we have no QKD client at all,
        * the KME will not give us that key.

        Under `STRICT_ERROR` the first and third abort the handshake: a strict
        responder refuses to complete a session it believed would be hybrid.
        """
        if self.qkd_client is None:
            return False

        strict = self.qkd_client.mode is QKDMode.STRICT_ERROR

        if not qkd_key_id:
            if strict:
                self.machine.fail("initiator supplied no QKD key id")
                raise QKDUnavailable(
                    "initiator supplied no QKD key id and this responder is strict"
                )
            self.session.downgraded = True
            return False

        try:
            self._qkd_key = self.qkd_client.get_key_by_id(qkd_key_id)
        except (QKDUnavailable, QKDServerError) as exc:
            if strict:
                self.machine.fail(f"QKD key {qkd_key_id} unavailable: {exc}")
                raise QKDUnavailable(f"QKD key {qkd_key_id} unavailable: {exc}") from exc
            self._qkd_key = None
            self.session.downgraded = True
            return False

        self.session.qkd_key_id = qkd_key_id
        return True

    # -- flight 3/4 ----------------------------------------------------------

    def receive_message_3(self, data: bytes) -> bytes:
        """Verify the initiator's MAC, derive the session key, and produce M4."""
        self.machine.require(HandshakeState.WAIT_2)
        try:
            m3 = Message3.decode(data)
        except MessageFormatError as exc:
            raise self.machine.fail(f"malformed M3: {exc}") from exc
        if m3.session_id != self.session.session_id:
            raise self.machine.fail("M3 session_id does not match M1")

        self.session.bytes_received += len(data)
        self.session.messages["m3"] = len(data)
        self.machine.transition(HandshakeState.SEND_3)

        # ss_lt_r: we prove we own sk_R by recovering the initiator's
        # encapsulation to our long-term key.
        try:
            ss_lt_r = self.long_term.decapsulate(m3.ct_lt_r)
        except Exception as exc:
            raise self.machine.fail(f"decapsulation failed: {exc}") from exc

        ikm = self._ss_lt_i + ss_lt_r + self._ss_eph + (self._qkd_key or b"")
        self._m3_body = m3.body()
        th3 = transcript_hash(self._m1, self._m2, self._m3_body)

        k_conf_i = derive_confirmation_key(ikm, th3, "initiator")
        if not verify_mac(k_conf_i, self._m1 + self._m2 + self._m3_body, m3.mac):
            raise self.machine.fail("initiator MAC verification failed")
        self.machine.transition(HandshakeState.WAIT_4)

        self.session.security_mode = (
            SecurityMode.HYBRID if self._qkd_key is not None else SecurityMode.COMPUTATIONAL_ONLY
        )

        m4 = Message4(session_id=self.session.session_id, flags=flags_for(self.session))
        full_transcript = self._m1 + self._m2 + self._m3_body + m4.body()
        k_conf_r = derive_confirmation_key(ikm, th3, "responder")
        mac_r = compute_mac(k_conf_r, full_transcript)

        th4 = transcript_hash(full_transcript)
        self.session.transcript_hash = th4
        self.session.session_key = derive_session_key(ikm, th4)

        encoded = replace(m4, mac=mac_r).encode()
        self.session.bytes_sent += len(encoded)
        self.session.messages["m4"] = len(encoded)
        self.machine.transition(HandshakeState.CONFIRM)
        self.machine.transition(HandshakeState.ESTABLISHED)
        return encoded

    # -- convenience ---------------------------------------------------------

    def result(self) -> HandshakeResult:
        if not self.machine.is_established:
            raise ProtocolError(f"handshake is in {self.machine.state.value}, not established")
        return build_result(self.session, self.qkd_client)

    @property
    def state(self) -> HandshakeState:
        return self.machine.state
