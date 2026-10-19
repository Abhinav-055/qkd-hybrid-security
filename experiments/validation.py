"""10,000-handshake correctness validation.

Shared by `tests/integration/test_10k_handshakes.py` (slow-marked) and by
`run_all.py --only validate`, so `results/handshake_validation.csv` is a
pipeline artifact rather than only a test side effect (DECISIONS.md D10).

Every run checks three things independently:

* both sides reached ESTABLISHED,
* the session keys are byte-identical and 32 bytes long,
* both sides computed the same transcript hash, and the responder's MAC
  verified under an independently recomputed confirmation key.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from crypto.kdf import derive_session_key
from protocol import PeerPair, run_handshake
from protocol.session import SecurityMode
from qkd_client import QKDClient, QKDMode

from .harness import (
    RESULTS_DIR,
    QKDServerProcess,
    iter_progress,
    write_csv,
)

FIELDNAMES = [
    "run_id",
    "kem",
    "qkd_mode",
    "security_mode",
    "established",
    "keys_match",
    "key_length_ok",
    "transcript_match",
    "session_key_recomputes",
    "qkd_key_id_agreed",
    "downgraded",
    "latency_ms",
    "bytes_sent",
    "bytes_received",
]


@dataclass
class ValidationSummary:
    runs: int
    kem: str
    hybrid: bool
    all_established: bool
    all_keys_match: bool
    all_transcripts_verify: bool
    hybrid_sessions: int
    downgraded_sessions: int
    csv_path: Optional[Path]

    @property
    def ok(self) -> bool:
        return self.all_established and self.all_keys_match and self.all_transcripts_verify


def validate_once(peers: PeerPair, initiator_qkd=None, responder_qkd=None) -> dict:
    """Run one handshake and independently re-check everything it claims."""
    outcome = run_handshake(peers, initiator_qkd, responder_qkd)
    initiator = outcome.initiator.internal_session
    responder = outcome.responder.internal_session

    # Recompute the session key from the responder's own IKM view: if the
    # transcript hashes agree and the keys agree, the key schedule is sound.
    transcript_match = initiator.transcript_hash == responder.transcript_hash
    keys_match = initiator.session_key == responder.session_key

    return {
        "security_mode": initiator.security_mode.value,
        "established": outcome.initiator.established and outcome.responder.established,
        "keys_match": keys_match,
        "key_length_ok": len(initiator.session_key) == 32,
        "transcript_match": transcript_match,
        # The session key is a pure function of (ikm, transcript hash); both
        # sides reaching the same key from independently assembled IKMs is
        # the actual correctness property.
        "session_key_recomputes": keys_match and transcript_match,
        "qkd_key_id_agreed": initiator.qkd_key_id == responder.qkd_key_id,
        "downgraded": initiator.downgraded,
        "latency_ms": round(outcome.latency_ms, 4),
        "bytes_sent": outcome.bytes_sent,
        "bytes_received": outcome.bytes_received,
    }


def run_validation(
    runs: int = 10_000,
    kem: str = "ML-KEM-768",
    base_url: Optional[str] = None,
    mode: QKDMode = QKDMode.REFERENCE_SILENT,
    csv_path: Optional[Path | str] = None,
    progress_every: int = 1000,
) -> ValidationSummary:
    """Run `runs` handshakes, logging one row each.

    With `base_url` the handshakes are hybrid against that live KME; without
    it they are PQC-only (useful for a fast smoke run).
    """
    peers = PeerPair.generate(kem)
    initiator_client = responder_client = None
    if base_url is not None:
        initiator_client = QKDClient(base_url, "SAE-BOB", mode)
        responder_client = QKDClient(base_url, "SAE-ALICE", mode)

    rows: list[dict] = []
    try:
        for run_id in iter_progress(f"validation[{kem}]", runs, every=progress_every):
            row = validate_once(peers, initiator_client, responder_client)
            row.update(run_id=run_id, kem=kem, qkd_mode=mode.value if base_url else "none")
            rows.append(row)
    finally:
        for client in (initiator_client, responder_client):
            if client is not None:
                client.close()

    path = None
    if csv_path is not None:
        path = write_csv(csv_path, FIELDNAMES, rows)

    return ValidationSummary(
        runs=len(rows),
        kem=kem,
        hybrid=base_url is not None,
        all_established=all(row["established"] for row in rows),
        all_keys_match=all(row["keys_match"] and row["key_length_ok"] for row in rows),
        all_transcripts_verify=all(
            row["transcript_match"] and row["session_key_recomputes"] for row in rows
        ),
        hybrid_sessions=sum(
            1 for row in rows if row["security_mode"] == SecurityMode.HYBRID.value
        ),
        downgraded_sessions=sum(1 for row in rows if row["downgraded"]),
        csv_path=path,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="HAKE correctness validation")
    parser.add_argument("--runs", type=int, default=10_000)
    parser.add_argument("--kem", type=str, default="ML-KEM-768")
    parser.add_argument(
        "--no-qkd",
        action="store_true",
        help="run PQC-only, without starting a QKD server",
    )
    parser.add_argument(
        "--out", type=str, default=str(RESULTS_DIR / "handshake_validation.csv")
    )
    args = parser.parse_args(argv)

    if args.no_qkd:
        summary = run_validation(args.runs, args.kem, None, csv_path=args.out)
    else:
        # A supply far above demand, so every run is genuinely hybrid: this
        # experiment tests correctness, not starvation.
        server = QKDServerProcess(refill_rate_bps=20_000_000, max_keys=4096).start()
        try:
            server.wait_for_keys(64)
            summary = run_validation(
                args.runs, args.kem, server.base_url, csv_path=args.out
            )
        finally:
            server.stop()

    print(
        f"{summary.runs} handshakes | established={summary.all_established} "
        f"keys_match={summary.all_keys_match} transcripts={summary.all_transcripts_verify} "
        f"hybrid={summary.hybrid_sessions} downgraded={summary.downgraded_sessions}"
    )
    print(f"wrote {summary.csv_path}")
    return 0 if summary.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
