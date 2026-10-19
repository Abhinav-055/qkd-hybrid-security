"""The 10,000-handshake protocol correctness validation.

Marked slow, so it is deselected by default (see `pyproject.toml`). Run it
explicitly:

    pytest -m slow tests/integration -v

or via the pipeline, which writes the same CSV:

    python run_all.py --only validate
"""
from __future__ import annotations

import pytest

from experiments.harness import RESULTS_DIR, QKDServerProcess
from experiments.validation import run_validation
from qkd_client import QKDMode

FAST_RUNS = 200
FULL_RUNS = 10_000


@pytest.fixture(scope="module")
def well_stocked_server():
    """Supply far above demand, so starvation never confounds correctness."""
    server = QKDServerProcess(refill_rate_bps=20_000_000, max_keys=4096).start()
    server.wait_for_keys(64)
    yield server
    server.stop()


@pytest.mark.slow
def test_ten_thousand_handshakes_all_succeed_and_agree(well_stocked_server):
    summary = run_validation(
        runs=FULL_RUNS,
        kem="ML-KEM-768",
        base_url=well_stocked_server.base_url,
        mode=QKDMode.REFERENCE_SILENT,
        csv_path=RESULTS_DIR / "handshake_validation.csv",
    )

    assert summary.runs == FULL_RUNS
    assert summary.all_established, "some handshakes failed to establish"
    assert summary.all_keys_match, "initiator and responder disagreed on a session key"
    assert summary.all_transcripts_verify, "a transcript hash or MAC check failed"
    # With supply this far above demand, nothing should have downgraded.
    assert summary.hybrid_sessions == FULL_RUNS
    assert summary.downgraded_sessions == 0
    assert summary.csv_path is not None and summary.csv_path.exists()


def test_validation_driver_agrees_on_a_short_run(well_stocked_server, tmp_path):
    """Fast guard on the same code path the slow test uses."""
    summary = run_validation(
        runs=FAST_RUNS,
        kem="ML-KEM-768",
        base_url=well_stocked_server.base_url,
        csv_path=tmp_path / "validation.csv",
        progress_every=FAST_RUNS + 1,
    )

    assert summary.ok
    assert summary.hybrid_sessions == FAST_RUNS


def test_validation_driver_works_without_qkd(tmp_path):
    summary = run_validation(
        runs=50, kem="ML-KEM-512", base_url=None, csv_path=tmp_path / "pqc.csv"
    )
    assert summary.ok
    assert summary.hybrid_sessions == 0
    assert summary.downgraded_sessions == 0  # pure PQC never claimed hybrid
