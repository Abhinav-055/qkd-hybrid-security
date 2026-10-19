"""Baseline: the same protocol minus QKD."""
from __future__ import annotations

import pathlib

import pytest

from baseline import generate_peers, run_pure_pqc_handshake
from baseline.pure_pqc import PurePQCInitiator, PurePQCResponder
from crypto import SUPPORTED_KEMS
from protocol import SecurityMode, run_handshake
from qkd_client import QKDClient, QKDMode


@pytest.fixture(scope="module")
def peers():
    return generate_peers("ML-KEM-768")


def test_baseline_handshake_agrees_on_a_key(peers):
    outcome = run_pure_pqc_handshake(peers)

    assert outcome.keys_match
    session = outcome.initiator.internal_session
    assert session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
    assert session.qkd_key_id is None
    assert session.qkd_disabled is True


def test_baseline_is_computational_only_but_not_downgraded(peers):
    """It never claimed hybrid security, so nothing was lost."""
    outcome = run_pure_pqc_handshake(peers)
    assert outcome.initiator.internal_session.downgraded is False
    assert outcome.initiator.downgraded is False  # a definite "no", not None


@pytest.mark.parametrize("algorithm", SUPPORTED_KEMS)
def test_baseline_runs_for_every_study_kem(algorithm):
    outcome = run_pure_pqc_handshake(generate_peers(algorithm))
    assert outcome.keys_match


def test_baseline_uses_the_same_wire_format_as_the_hybrid_protocol(peers):
    """Identical message sizes: the structure is unchanged, only QKD is absent."""
    baseline = run_pure_pqc_handshake(peers)
    hybrid_framework = run_handshake(peers)

    assert (
        baseline.initiator.internal_session.messages
        == hybrid_framework.initiator.internal_session.messages
    )


def test_baseline_refuses_a_qkd_client_even_if_one_is_passed(peers, stocked_qkd_server):
    """Structurally impossible to hybridize the baseline by accident."""
    client = QKDClient(stocked_qkd_server.base_url, "SAE-BOB", QKDMode.REFERENCE_SILENT)
    try:
        initiator = PurePQCInitiator(
            "SAE-ALICE",
            peers.initiator_long_term,
            peers.responder_long_term.public_key,
            "SAE-BOB",
            qkd_client=client,
        )
        responder = PurePQCResponder(
            "SAE-BOB",
            peers.responder_long_term,
            peers.initiator_long_term.public_key,
            "SAE-ALICE",
            qkd_client=client,
        )
        assert initiator.qkd_client is None
        assert responder.qkd_client is None

        m2 = responder.receive_message_1(initiator.start())
        m3 = initiator.receive_message_2(m2)
        result = initiator.receive_message_4(responder.receive_message_3(m3))

        assert result.internal_session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
        assert client.keys_requested == 0  # the pool was never touched
    finally:
        client.close()


def test_baseline_never_imports_the_qkd_client():
    source = pathlib.Path("baseline/pure_pqc.py").read_text(encoding="utf-8")
    assert "QKDClient" not in source
    assert "httpx" not in source


def test_baseline_and_hybrid_sessions_differ_only_in_the_qkd_contribution(
    peers, stocked_qkd_server
):
    initiator_client = QKDClient(stocked_qkd_server.base_url, "SAE-BOB", QKDMode.REFERENCE_SILENT)
    responder_client = QKDClient(
        stocked_qkd_server.base_url, "SAE-ALICE", QKDMode.REFERENCE_SILENT
    )
    try:
        hybrid = run_handshake(peers, initiator_client, responder_client)
    finally:
        initiator_client.close()
        responder_client.close()
    baseline = run_pure_pqc_handshake(peers)

    assert hybrid.initiator.internal_session.security_mode is SecurityMode.HYBRID
    assert baseline.initiator.internal_session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
    # Same wire cost: the QKD key id rides in M1 and the key itself never does.
    assert hybrid.bytes_received == baseline.bytes_received
    assert hybrid.bytes_sent > baseline.bytes_sent  # M1 carries a 36-char key id
