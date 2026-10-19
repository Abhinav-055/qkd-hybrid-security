"""Protocol: round-trip, key agreement, tampering, and mode wiring.

The mode tests run end-to-end against a live key server, including
one forced permanently empty, because the whole point is how the protocol
behaves when the real HTTP API says 503.
"""
from __future__ import annotations

import warnings
from dataclasses import replace

import pytest

from crypto.kdf import derive_session_key, transcript_hash
from protocol import (
    HandshakeFailed,
    HandshakeState,
    Initiator,
    Message1,
    Message2,
    Message3,
    Message4,
    PeerPair,
    Responder,
    SecurityDowngradeWarning,
    SecurityMode,
    run_handshake,
)
from protocol.messages import FLAG_HYBRID
from protocol.session import ProtocolError
from qkd_client import QKDClient, QKDMode, QKDUnavailable

ALICE = "SAE-ALICE"
BOB = "SAE-BOB"


@pytest.fixture(scope="module")
def peers() -> PeerPair:
    """Long-term keys, generated once: that is what makes them long-term."""
    return PeerPair.generate("ML-KEM-768", initiator_id=ALICE, responder_id=BOB)


@pytest.fixture
def qkd_clients():
    """Factory for role-paired QKD clients, closed at teardown."""
    opened: list[QKDClient] = []

    def make(server, mode: QKDMode) -> tuple[QKDClient, QKDClient]:
        pair = (
            QKDClient(server.base_url, BOB, mode),
            QKDClient(server.base_url, ALICE, mode),
        )
        opened.extend(pair)
        return pair

    yield make

    for client in opened:
        client.close()


# -- round trip ---------------------------------------------------------------


def test_round_trip_without_qkd_agrees_on_a_key(peers):
    outcome = run_handshake(peers)

    assert outcome.keys_match
    assert outcome.initiator.established and outcome.responder.established
    assert outcome.initiator.internal_session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
    assert outcome.initiator.internal_session.downgraded is False  # never claimed hybrid


def test_round_trip_with_qkd_is_hybrid_on_both_sides(peers, stocked_qkd_server, qkd_clients):
    initiator_client, responder_client = qkd_clients(stocked_qkd_server, QKDMode.REFERENCE_SILENT)
    outcome = run_handshake(peers, initiator_client, responder_client)

    initiator_session = outcome.initiator.internal_session
    responder_session = outcome.responder.internal_session

    assert outcome.keys_match
    assert initiator_session.security_mode is SecurityMode.HYBRID
    assert responder_session.security_mode is SecurityMode.HYBRID
    assert initiator_session.qkd_key_id == responder_session.qkd_key_id
    assert initiator_session.downgraded is False
    assert initiator_session.transcript_hash == responder_session.transcript_hash


def test_hybrid_and_pqc_only_sessions_derive_different_keys(peers, stocked_qkd_server, qkd_clients):
    """The QKD contribution actually changes the session key."""
    initiator_client, responder_client = qkd_clients(stocked_qkd_server, QKDMode.REFERENCE_SILENT)
    hybrid = run_handshake(peers, initiator_client, responder_client)
    computational = run_handshake(peers)
    assert hybrid.initiator.session_key != computational.initiator.session_key


def test_both_sides_record_the_same_wire_sizes(peers):
    outcome = run_handshake(peers)
    initiator_session = outcome.initiator.internal_session
    responder_session = outcome.responder.internal_session

    assert initiator_session.messages == responder_session.messages
    assert outcome.bytes_sent == initiator_session.messages["m1"] + initiator_session.messages["m3"]
    assert (
        outcome.bytes_received
        == initiator_session.messages["m2"] + initiator_session.messages["m4"]
    )


def test_session_key_matches_an_independent_recomputation(peers):
    """Recompute the KDF from the recorded transcript hash and IKM."""
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    m1 = initiator.start()
    m2 = responder.receive_message_1(m1)
    m3 = initiator.receive_message_2(m2)
    m4 = responder.receive_message_3(m3)
    initiator.receive_message_4(m4)

    session = initiator.session
    expected = derive_session_key(initiator._ikm, session.transcript_hash)
    assert session.session_key == expected
    assert session.transcript_hash == transcript_hash(
        m1 + m2 + Message3.decode(m3).body() + Message4.decode(m4).body()
    )


@pytest.mark.parametrize("algorithm", ["ML-KEM-512", "ML-KEM-1024", "FrodoKEM-976-AES"])
def test_round_trip_for_each_kem(algorithm):
    peers = PeerPair.generate(algorithm)
    outcome = run_handshake(peers)
    assert outcome.keys_match


def test_distinct_sessions_get_distinct_keys(peers):
    first = run_handshake(peers)
    second = run_handshake(peers)
    assert first.initiator.session_key != second.initiator.session_key
    assert first.initiator.session_id != second.initiator.session_id


# -- state machine traversal --------------------------------------------------


def test_both_roles_reach_established_through_the_declared_states(peers):
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    assert initiator.state is HandshakeState.INIT
    m1 = initiator.start()
    assert initiator.state is HandshakeState.WAIT_2
    m2 = responder.receive_message_1(m1)
    assert responder.state is HandshakeState.WAIT_2
    m3 = initiator.receive_message_2(m2)
    assert initiator.state is HandshakeState.WAIT_4
    m4 = responder.receive_message_3(m3)
    assert responder.state is HandshakeState.ESTABLISHED
    initiator.receive_message_4(m4)
    assert initiator.state is HandshakeState.ESTABLISHED

    expected = (
        HandshakeState.INIT,
        HandshakeState.SEND_1,
        HandshakeState.WAIT_2,
        HandshakeState.SEND_3,
        HandshakeState.WAIT_4,
        HandshakeState.CONFIRM,
        HandshakeState.ESTABLISHED,
    )
    assert initiator.machine.history == expected
    assert responder.machine.history == expected


def test_out_of_order_messages_are_refused(peers):
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    with pytest.raises(Exception):
        initiator.receive_message_2(b"anything")

    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)
    with pytest.raises(Exception):
        responder.receive_message_3(b"anything")


def test_result_before_establishment_is_an_error(peers):
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    with pytest.raises(ProtocolError):
        initiator.result()


# -- tampering ----------------------------------------------------------------


def flip_last_byte(data: bytes) -> bytes:
    return data[:-1] + bytes([data[-1] ^ 0x01])


def flip_middle_byte(data: bytes) -> bytes:
    index = len(data) // 2
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def test_tampering_with_m3_mac_fails_at_the_responder(peers):
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    m2 = responder.receive_message_1(initiator.start())
    m3 = initiator.receive_message_2(m2)

    with pytest.raises(HandshakeFailed, match="initiator MAC verification failed"):
        responder.receive_message_3(flip_last_byte(m3))
    assert responder.state is HandshakeState.FAILED


def test_tampering_with_m4_mac_fails_at_the_initiator(peers):
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    m2 = responder.receive_message_1(initiator.start())
    m3 = initiator.receive_message_2(m2)
    m4 = responder.receive_message_3(m3)

    with pytest.raises(HandshakeFailed, match="responder MAC verification failed"):
        initiator.receive_message_4(flip_last_byte(m4))
    assert initiator.state is HandshakeState.FAILED


def test_tampering_with_m1_breaks_the_transcript(peers):
    """M1 is not MAC-protected on arrival, but it is bound into the transcript."""
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    m1 = initiator.start()
    # Flip a byte of the nonce: still decodes, but the responder's transcript
    # no longer matches the initiator's, so M3's MAC cannot verify.
    tampered = m1[:4 + 16] + bytes([m1[20] ^ 0x01]) + m1[21:]
    m2 = responder.receive_message_1(tampered)
    m3 = initiator.receive_message_2(m2)

    with pytest.raises(HandshakeFailed, match="MAC verification failed"):
        responder.receive_message_3(m3)


def test_tampering_with_m2_is_detected(peers):
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    m1 = initiator.start()
    m2 = responder.receive_message_1(m1)
    decoded = Message2.decode(m2)
    # Corrupt the ephemeral ciphertext: decapsulation gives the initiator a
    # different shared secret, so the MACs cannot agree.
    tampered = replace(decoded, ct_eph=flip_middle_byte(decoded.ct_eph)).encode()

    m3 = initiator.receive_message_2(tampered)
    with pytest.raises(HandshakeFailed, match="MAC verification failed"):
        responder.receive_message_3(m3)


def test_a_wrong_session_id_is_refused(peers):
    initiator = Initiator(ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB)
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    m2 = responder.receive_message_1(initiator.start())
    tampered = replace(Message2.decode(m2), session_id=bytes(16)).encode()
    with pytest.raises(HandshakeFailed, match="session_id"):
        initiator.receive_message_2(tampered)


def test_an_impostor_long_term_key_cannot_complete(peers):
    """Implicit authentication: a peer without sk_R derives a different key."""
    impostor = PeerPair.generate("ML-KEM-768")
    initiator = Initiator(
        ALICE, peers.initiator_long_term, impostor.responder_long_term.public_key, BOB
    )
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    m2 = responder.receive_message_1(initiator.start())
    m3 = initiator.receive_message_2(m2)
    # The initiator encapsulated ss_lt_R to the impostor's key, so the real
    # responder recovers something else and the MAC fails.
    with pytest.raises(HandshakeFailed, match="MAC verification failed"):
        responder.receive_message_3(m3)


def test_suite_mismatch_is_refused():
    alice = PeerPair.generate("ML-KEM-512")
    bob_long_term = PeerPair.generate("ML-KEM-768").responder_long_term

    initiator = Initiator(ALICE, alice.initiator_long_term, bob_long_term.public_key, BOB)
    responder = Responder(BOB, bob_long_term, alice.initiator_long_term.public_key, ALICE)

    with pytest.raises(HandshakeFailed, match="suite mismatch"):
        responder.receive_message_1(initiator.start())


def test_a_forged_hybrid_flag_is_detected(peers):
    """A responder cannot claim hybrid security the initiator did not get."""
    initiator = Initiator(
        ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB
    )
    responder = Responder(BOB, peers.responder_long_term, peers.initiator_long_term.public_key, ALICE)

    m2 = responder.receive_message_1(initiator.start())
    m3 = initiator.receive_message_2(m2)
    m4 = responder.receive_message_3(m3)
    forged = replace(Message4.decode(m4), flags=FLAG_HYBRID).encode()

    with pytest.raises(HandshakeFailed):
        initiator.receive_message_4(forged)


# -- mode wiring, end to end against a live key server -----------------------


def test_reference_silent_completes_and_hides_the_downgrade(peers, empty_qkd_server, qkd_clients):
    """The headline phenomenon: success, PQC-only, and the app cannot tell."""
    initiator_client, responder_client = qkd_clients(empty_qkd_server, QKDMode.REFERENCE_SILENT)

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning here would be a signal
        outcome = run_handshake(peers, initiator_client, responder_client)

    assert outcome.keys_match
    assert outcome.initiator.established is True
    # What the application sees:
    assert outcome.initiator.downgraded is None
    assert outcome.initiator.app_visible_downgrade is False
    # What actually happened:
    assert outcome.initiator.internal_session.downgraded is True
    assert outcome.initiator.internal_session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
    assert outcome.initiator.internal_session.qkd_key_id is None
    assert outcome.responder.internal_session.downgraded is True


def test_strict_error_aborts_when_the_pool_is_empty(peers, empty_qkd_server, qkd_clients):
    initiator_client, responder_client = qkd_clients(empty_qkd_server, QKDMode.STRICT_ERROR)

    with pytest.raises(QKDUnavailable):
        run_handshake(peers, initiator_client, responder_client)


def test_strict_error_succeeds_while_keys_remain(peers, stocked_qkd_server, qkd_clients):
    initiator_client, responder_client = qkd_clients(stocked_qkd_server, QKDMode.STRICT_ERROR)
    outcome = run_handshake(peers, initiator_client, responder_client)

    assert outcome.keys_match
    assert outcome.initiator.internal_session.security_mode is SecurityMode.HYBRID
    assert outcome.initiator.downgraded is False


def test_strict_responder_refuses_a_handshake_with_no_qkd_key_id(peers, stocked_qkd_server, qkd_clients):
    """A strict responder will not complete a session it expected to be hybrid."""
    _, responder_client = qkd_clients(stocked_qkd_server, QKDMode.STRICT_ERROR)
    initiator = Initiator(
        ALICE, peers.initiator_long_term, peers.responder_long_term.public_key, BOB
    )  # no QKD client: names no key id
    responder = Responder(
        BOB,
        peers.responder_long_term,
        peers.initiator_long_term.public_key,
        ALICE,
        qkd_client=responder_client,
    )

    with pytest.raises(QKDUnavailable):
        responder.receive_message_1(initiator.start())
    assert responder.state is HandshakeState.FAILED


def test_explicit_downgrade_surfaces_the_signal_and_warns(peers, empty_qkd_server, qkd_clients):
    initiator_client, responder_client = qkd_clients(empty_qkd_server, QKDMode.EXPLICIT_DOWNGRADE)

    with pytest.warns(SecurityDowngradeWarning):
        outcome = run_handshake(peers, initiator_client, responder_client)

    assert outcome.keys_match
    assert outcome.initiator.downgraded is True
    assert outcome.initiator.app_visible_downgrade is True
    assert outcome.responder.downgraded is True
    assert outcome.initiator.internal_session.security_mode is SecurityMode.COMPUTATIONAL_ONLY


def test_explicit_downgrade_stays_quiet_when_qkd_is_available(peers, stocked_qkd_server, qkd_clients):
    initiator_client, responder_client = qkd_clients(
        stocked_qkd_server, QKDMode.EXPLICIT_DOWNGRADE
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        outcome = run_handshake(peers, initiator_client, responder_client)

    assert outcome.initiator.downgraded is False
    assert outcome.initiator.internal_session.security_mode is SecurityMode.HYBRID


def test_both_non_strict_modes_produce_the_same_session_state(peers, empty_qkd_server, qkd_clients):
    """Only the *visibility* differs; the cryptography is identical."""
    silent_clients = qkd_clients(empty_qkd_server, QKDMode.REFERENCE_SILENT)
    explicit_clients = qkd_clients(empty_qkd_server, QKDMode.EXPLICIT_DOWNGRADE)

    silent = run_handshake(peers, *silent_clients)
    with pytest.warns(SecurityDowngradeWarning):
        explicit = run_handshake(peers, *explicit_clients)

    for outcome in (silent, explicit):
        session = outcome.initiator.internal_session
        assert session.downgraded is True
        assert session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
    assert silent.initiator.downgraded is None
    assert explicit.initiator.downgraded is True


def test_responder_that_cannot_fetch_the_key_forces_the_initiator_to_drop_it(
    peers, stocked_qkd_server, qkd_server_factory
):
    """DECISIONS.md D4: both sides must end up with the same QKD contribution."""
    other_kme = qkd_server_factory(refill_rate_bps=2_000_000, max_keys=64, kme_id="KME-OTHER")
    initiator_client = QKDClient(stocked_qkd_server.base_url, BOB, QKDMode.REFERENCE_SILENT)
    # The responder asks a *different* KME, which never issued that key id.
    responder_client = QKDClient(other_kme.base_url, ALICE, QKDMode.REFERENCE_SILENT)

    try:
        outcome = run_handshake(peers, initiator_client, responder_client)
    finally:
        initiator_client.close()
        responder_client.close()

    assert outcome.keys_match  # agreement preserved
    assert outcome.initiator.internal_session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
    assert outcome.initiator.internal_session.downgraded is True
    assert outcome.initiator.internal_session.qkd_key_id is None


def test_pool_drains_and_later_handshakes_silently_downgrade(peers, qkd_server_factory, qkd_clients):
    """Exactly two keys: handshake 1 and 2 are hybrid, 3 is silently PQC-only."""
    server = qkd_server_factory(refill_rate_bps=0, max_keys=16, prefill_keys=2)
    initiator_client, responder_client = qkd_clients(server, QKDMode.REFERENCE_SILENT)

    modes = []
    for _ in range(3):
        outcome = run_handshake(peers, initiator_client, responder_client)
        assert outcome.keys_match
        modes.append(outcome.initiator.internal_session.security_mode)

    assert modes == [SecurityMode.HYBRID, SecurityMode.HYBRID, SecurityMode.COMPUTATIONAL_ONLY]
    assert initiator_client.starvation_events == 1
