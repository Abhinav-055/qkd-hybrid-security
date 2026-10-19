"""Mitigation 3: explicit downgrade signalling, wired end to end.

This is not a separate algorithm. It is `QKDMode.EXPLICIT_DOWNGRADE` carried
all the way to the application: `HandshakeResult.downgraded` becomes `True`
instead of `None`, and a `SecurityDowngradeWarning` is emitted.

It does not prevent a downgrade -- the session key still rests on the KEMs
alone -- so throughput and hybrid ratio are identical to the reference
configuration. What changes is that the application *knows*, and can decide
for itself: refuse the session, re-key later, or proceed with reduced
assurance. In the compromise matrix (analysis/security_matrix.md) it moves
the "QKD absent" row from an unknown-unknown to a known risk.

Demo:

    python -m mitigations.downgrade_signal
"""
from __future__ import annotations

import argparse
import logging
import warnings
from dataclasses import dataclass, field
from typing import Optional

from protocol import PeerPair, SecurityDowngradeWarning, run_handshake
from protocol.session import HandshakeResult
from qkd_client import QKDClient, QKDMode

logger = logging.getLogger("mitigations.downgrade_signal")


@dataclass
class SignalLog:
    """What an application that actually reads the signal would record."""

    sessions: int = 0
    signalled: int = 0
    warnings_seen: int = 0
    entries: list[dict] = field(default_factory=list)

    def record(self, result: HandshakeResult, warning_messages: list[str]) -> None:
        self.sessions += 1
        session = result.internal_session
        if result.app_visible_downgrade:
            self.signalled += 1
        self.warnings_seen += len(warning_messages)
        entry = {
            "session_id": result.session_id.hex(),
            "peer_id": result.peer_id,
            "downgraded": result.downgraded,
            "security_mode": session.security_mode.value,
            "qkd_key_id": session.qkd_key_id,
            "warnings": warning_messages,
        }
        self.entries.append(entry)
        if result.app_visible_downgrade:
            logger.warning(
                "QKD downgrade signalled for session %s with %s: security_mode=%s",
                entry["session_id"],
                entry["peer_id"],
                entry["security_mode"],
            )
        else:
            logger.info(
                "session %s with %s established hybrid (qkd_key_id=%s)",
                entry["session_id"],
                entry["peer_id"],
                entry["qkd_key_id"],
            )

    @property
    def signal_rate(self) -> float:
        return self.signalled / self.sessions if self.sessions else 0.0


def make_explicit_clients(
    base_url: str, initiator_sae: str = "SAE-BOB", responder_sae: str = "SAE-ALICE"
) -> tuple[QKDClient, QKDClient]:
    """A client pair in `EXPLICIT_DOWNGRADE` mode."""
    return (
        QKDClient(base_url, initiator_sae, QKDMode.EXPLICIT_DOWNGRADE),
        QKDClient(base_url, responder_sae, QKDMode.EXPLICIT_DOWNGRADE),
    )


def handshake_with_signal(
    peers: PeerPair,
    initiator_client: QKDClient,
    responder_client: QKDClient,
    log: SignalLog,
) -> HandshakeResult:
    """Run one handshake and hand any downgrade signal to `log`.

    Capturing the warning is how a real caller would notice it -- via
    `logging.captureWarnings`, a `warnings` filter, or an error reporter.
    """
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always", SecurityDowngradeWarning)
        result = run_handshake(peers, initiator_client, responder_client).initiator

    messages = [
        str(item.message)
        for item in captured
        if issubclass(item.category, SecurityDowngradeWarning)
    ]
    log.record(result, messages)
    return result


def demo(base_url: str, handshakes: int = 5, kem: str = "ML-KEM-768") -> SignalLog:
    """Small demo caller: run handshakes and log every signal received."""
    peers = PeerPair.generate(kem)
    initiator_client, responder_client = make_explicit_clients(base_url)
    log = SignalLog()
    try:
        for _ in range(handshakes):
            handshake_with_signal(peers, initiator_client, responder_client, log)
    finally:
        initiator_client.close()
        responder_client.close()
    return log


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit downgrade signal demo")
    parser.add_argument(
        "--base-url",
        type=str,
        default=None,
        help="existing QKD server; omitted, a starved one is started for the demo",
    )
    parser.add_argument("--handshakes", type=int, default=5)
    parser.add_argument(
        "--supply-bps",
        type=int,
        default=0,
        help="refill rate of the demo server (0 = permanently empty pool)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(message)s")
    # The point of this demo is the downgrade signal, not the HTTP traffic
    # underneath it.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if args.base_url:
        log = demo(args.base_url, args.handshakes)
    else:
        # Imported lazily: the demo is usable without the experiment harness.
        from experiments.harness import QKDServerProcess

        server = QKDServerProcess(
            refill_rate_bps=args.supply_bps, max_keys=64, log_path="results/qkd_server.log.jsonl"
        ).start()
        try:
            log = demo(server.base_url, args.handshakes)
        finally:
            server.stop()

    print()
    print(f"sessions={log.sessions} signalled={log.signalled} "
          f"signal_rate={log.signal_rate:.2f} warnings={log.warnings_seen}")
    print("The application was told about every downgrade; under "
          "REFERENCE_SILENT it would have been told about none.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
