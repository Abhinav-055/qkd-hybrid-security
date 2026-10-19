"""Mitigations: quota, admission control, and downgrade signalling."""
from __future__ import annotations

import time

import pytest

from mitigations import (
    AdmissionController,
    AdmissionPolicy,
    HandshakeRejected,
    PeerQuota,
    QuotaPolicy,
    SignalLog,
    handshake_with_signal,
    make_explicit_clients,
)
from protocol import PeerPair, SecurityDowngradeWarning, SecurityMode, run_handshake
from qkd_client import QKDClient, QKDMode

# -- quota -------------------------------------------------------------------


def test_token_bucket_grants_up_to_the_quota_then_refuses():
    quota = PeerQuota(QuotaPolicy(keys_per_window=3, window_seconds=60.0))

    assert [quota.try_consume("peer-a") for _ in range(3)] == [True, True, True]
    assert quota.try_consume("peer-a") is False


def test_quota_is_per_peer_not_global():
    """The bug this guards: one shared bucket would collapse all peers into one."""
    quota = PeerQuota(QuotaPolicy(keys_per_window=2, window_seconds=60.0))

    assert quota.try_consume("peer-a") and quota.try_consume("peer-a")
    assert quota.try_consume("peer-a") is False
    # peer-b's allowance is untouched by peer-a's greed.
    assert quota.try_consume("peer-b") and quota.try_consume("peer-b")
    assert quota.try_consume("peer-b") is False


def test_tokens_refill_over_time():
    quota = PeerQuota(QuotaPolicy(keys_per_window=100, window_seconds=1.0))
    for _ in range(100):
        quota.try_consume("peer-a")
    assert quota.try_consume("peer-a") is False

    time.sleep(0.1)  # 100 keys/sec -> ~10 tokens back
    assert quota.try_consume("peer-a") is True


def test_bucket_never_exceeds_its_capacity():
    quota = PeerQuota(QuotaPolicy(keys_per_window=5, window_seconds=0.01))
    time.sleep(0.1)  # far more than one window's worth of refill
    assert quota.tokens_available("peer-a") == pytest.approx(5.0)


def test_all_or_nothing_consumption():
    quota = PeerQuota(QuotaPolicy(keys_per_window=2, window_seconds=60.0))
    assert quota.try_consume("peer-a", count=5) is False
    # The refused request spent nothing.
    assert quota.tokens_available("peer-a") == pytest.approx(2.0, abs=0.01)


def test_quota_from_share_splits_supply_evenly():
    policy = QuotaPolicy.from_share(supply_bps=10_000, peers=4, key_size_bits=256)
    # 10000/256 = 39.06 keys/sec, split four ways.
    assert policy.tokens_per_second == pytest.approx(39.0625 / 4)


def test_per_peer_override_policies():
    quota = PeerQuota(
        default_policy=QuotaPolicy(keys_per_window=1, window_seconds=60.0),
        per_peer_policies={"vip": QuotaPolicy(keys_per_window=5, window_seconds=60.0)},
    )
    assert sum(quota.try_consume("vip") for _ in range(5)) == 5
    assert sum(quota.try_consume("plebe") for _ in range(5)) == 1


def test_quota_stats_report_grants_and_rejections():
    quota = PeerQuota(QuotaPolicy(keys_per_window=1, window_seconds=60.0))
    quota.try_consume("peer-a")
    quota.try_consume("peer-a")
    assert quota.stats()["peer-a"] == {"granted": 1, "rejected": 1}


def test_quota_exhaustion_looks_like_an_empty_pool_end_to_end(stocked_qkd_server):
    """The handshake silently downgrades even though the pool is full."""
    quota = PeerQuota(QuotaPolicy(keys_per_window=1, window_seconds=600.0))
    peers = PeerPair.generate("ML-KEM-768", initiator_id="SAE-ALICE", responder_id="peer-a")
    initiator = QKDClient(
        stocked_qkd_server.base_url, "SAE-BOB", QKDMode.REFERENCE_SILENT, gate=quota
    )
    responder = QKDClient(stocked_qkd_server.base_url, "SAE-ALICE", QKDMode.REFERENCE_SILENT)
    try:
        first = run_handshake(peers, initiator, responder)
        second = run_handshake(peers, initiator, responder)
    finally:
        initiator.close()
        responder.close()

    assert first.initiator.internal_session.security_mode is SecurityMode.HYBRID
    assert second.initiator.internal_session.security_mode is SecurityMode.COMPUTATIONAL_ONLY
    assert second.initiator.internal_session.downgraded is True
    assert second.keys_match  # still a working session, just not hybrid
    assert initiator.quota_rejections == 1


# -- admission control --------------------------------------------------------


def make_controller(depth: int, supply_bps: float = 10_000, **policy_kwargs):
    """A controller over a mutable fake pool depth."""
    state = {"depth": depth}
    controller = AdmissionController(
        occupancy_fn=lambda: state["depth"],
        refill_rate_bps=supply_bps,
        policy=AdmissionPolicy(**policy_kwargs),
    )
    return controller, state


def test_admits_while_the_projected_pool_suffices():
    controller, _ = make_controller(depth=50)
    ticket = controller.admit("peer-a")
    assert ticket.keys == 1
    assert controller.admitted == 1


def test_rejects_when_the_pool_is_empty():
    controller, _ = make_controller(depth=0)
    with pytest.raises(HandshakeRejected) as excinfo:
        controller.admit("peer-a")
    assert excinfo.value.needed == 1
    assert controller.rejected == 1


def test_rejection_happens_before_any_crypto_work(stocked_qkd_server):
    """A rejected handshake must cost no KEM operations and no key request."""
    controller, _ = make_controller(depth=0)
    client = QKDClient(stocked_qkd_server.base_url, "SAE-BOB", QKDMode.REFERENCE_SILENT)
    try:
        with pytest.raises(HandshakeRejected):
            controller.admit("peer-a")
        assert client.keys_requested == 0
    finally:
        client.close()


def test_concurrent_admissions_cannot_double_promise_one_key():
    """Debiting at admission time is what closes the race."""
    controller, _ = make_controller(depth=3, supply_bps=0, safety_margin_keys=0.0)
    admitted = 0
    for _ in range(10):
        try:
            controller.admit("peer-a")
            admitted += 1
        except HandshakeRejected:
            pass
    assert admitted == 3  # exactly the keys that existed


def test_releasing_an_unconsumed_ticket_credits_the_key_back():
    controller, _ = make_controller(depth=1, supply_bps=0, safety_margin_keys=0.0)
    ticket = controller.admit("peer-a")
    with pytest.raises(HandshakeRejected):
        controller.admit("peer-b")

    controller.release(ticket, consumed=False)
    assert controller.credited_back == 1
    controller.admit("peer-b")  # the key is available again


def test_releasing_a_consumed_ticket_keeps_the_debit():
    controller, _ = make_controller(depth=1, supply_bps=0, safety_margin_keys=0.0)
    ticket = controller.admit("peer-a")
    controller.release(ticket, consumed=True)
    with pytest.raises(HandshakeRejected):
        controller.admit("peer-b")


def test_double_release_is_harmless():
    controller, _ = make_controller(depth=1, supply_bps=0, safety_margin_keys=0.0)
    ticket = controller.admit("peer-a")
    controller.release(ticket, consumed=False)
    controller.release(ticket, consumed=False)
    assert controller.credited_back == 1


def test_a_stale_high_reading_cannot_inflate_the_estimate():
    """The re-sync only ever lowers: this is the fix for the leaked guarantee."""
    controller, state = make_controller(depth=2, supply_bps=0, safety_margin_keys=0.0)
    controller.admit("peer-a")
    controller.admit("peer-a")
    # Pool reports 2 again (a stale reading), but our debits already spent them.
    state["depth"] = 2
    with pytest.raises(HandshakeRejected):
        controller.admit("peer-a")


def test_resync_adopts_an_authoritative_reading():
    controller, state = make_controller(depth=100, supply_bps=0, safety_margin_keys=0.0)
    state["depth"] = 0
    controller.resync(0)
    with pytest.raises(HandshakeRejected):
        controller.admit("peer-a")


def test_safety_margin_is_raised_to_cover_sampling_staleness():
    controller, _ = make_controller(
        depth=10, supply_bps=10_000, safety_margin_keys=1.0, occupancy_staleness_seconds=0.1
    )
    # 39.06 keys/sec * 0.1 s = 3.9 keys of possible overstatement.
    assert controller.effective_margin_keys == pytest.approx(3.90625)


def test_refill_credit_makes_admission_predictive():
    """Admission looks at the pool *at completion*, not only at arrival.

    An empty pool refilling fast enough to produce a key within the horizon
    is admitted; one too slow to make it in time is rejected.
    """
    fast, _ = make_controller(
        # 100 kbps = 390.6 keys/sec, so 50 ms yields ~19.5 keys.
        depth=0, supply_bps=100_000, safety_margin_keys=0.0, occupancy_staleness_seconds=0.0
    )
    fast.admit("peer-a")

    slow, _ = make_controller(
        # 1 kbps = 3.9 keys/sec, so 50 ms yields only ~0.2 of a key.
        depth=0, supply_bps=1_000, safety_margin_keys=0.0, occupancy_staleness_seconds=0.0
    )
    with pytest.raises(HandshakeRejected):
        slow.admit("peer-a")


def test_stats_shape():
    controller, _ = make_controller(depth=1, supply_bps=0, safety_margin_keys=0.0)
    controller.admit("peer-a")
    try:
        controller.admit("peer-b")
    except HandshakeRejected:
        pass
    stats = controller.stats()
    assert stats["admitted"] == 1 and stats["rejected"] == 1
    assert stats["rejection_rate"] == pytest.approx(0.5)
    assert stats["per_peer_admitted"] == {"peer-a": 1}
    assert stats["per_peer_rejected"] == {"peer-b": 1}


# -- explicit downgrade signalling -------------------------------------------


def test_signal_log_records_a_downgrade(empty_qkd_server):
    peers = PeerPair.generate("ML-KEM-768")
    initiator, responder = make_explicit_clients(empty_qkd_server.base_url)
    log = SignalLog()
    try:
        result = handshake_with_signal(peers, initiator, responder, log)
    finally:
        initiator.close()
        responder.close()

    assert result.downgraded is True
    assert log.signalled == 1
    assert log.signal_rate == 1.0
    assert log.warnings_seen >= 1
    assert log.entries[0]["security_mode"] == "computational_only"


def test_signal_log_stays_quiet_when_qkd_is_available(stocked_qkd_server):
    peers = PeerPair.generate("ML-KEM-768")
    initiator, responder = make_explicit_clients(stocked_qkd_server.base_url)
    log = SignalLog()
    try:
        result = handshake_with_signal(peers, initiator, responder, log)
    finally:
        initiator.close()
        responder.close()

    assert result.downgraded is False
    assert log.signalled == 0
    assert log.warnings_seen == 0
    assert log.entries[0]["qkd_key_id"] is not None


def test_the_demo_caller_logs_every_signal(empty_qkd_server):
    from mitigations.downgrade_signal import demo

    log = demo(empty_qkd_server.base_url, handshakes=3)
    assert log.sessions == 3
    assert log.signalled == 3
    assert all(entry["downgraded"] is True for entry in log.entries)


def test_signalling_changes_visibility_not_cryptography(empty_qkd_server):
    """Same session state as the reference; only the app's knowledge differs."""
    peers = PeerPair.generate("ML-KEM-768")
    silent_pair = (
        QKDClient(empty_qkd_server.base_url, "SAE-BOB", QKDMode.REFERENCE_SILENT),
        QKDClient(empty_qkd_server.base_url, "SAE-ALICE", QKDMode.REFERENCE_SILENT),
    )
    explicit_pair = make_explicit_clients(empty_qkd_server.base_url)
    try:
        silent = run_handshake(peers, *silent_pair)
        with pytest.warns(SecurityDowngradeWarning):
            explicit = run_handshake(peers, *explicit_pair)
    finally:
        for client in (*silent_pair, *explicit_pair):
            client.close()

    for outcome in (silent, explicit):
        assert outcome.keys_match
        assert outcome.initiator.internal_session.security_mode is (
            SecurityMode.COMPUTATIONAL_ONLY
        )
    assert silent.initiator.downgraded is None      # not told
    assert explicit.initiator.downgraded is True    # told
