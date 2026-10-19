"""Rate x supply starvation sweep, and the shared load driver.

`run_load()` is the engine behind the sweep, the downgrade study, and the
mitigation study: it offers handshakes at a fixed rate against a live
key server and records what happened to each one.

    python -m experiments.load_generator [--config configs/load_sweep.yaml]
                                         [--duration 60]

Outputs `results/starvation_sweep.csv` (one row per handshake),
`results/starvation_summary.csv` (one row per configuration), and
`results/pool_occupancy.csv` (continuous pool depth).
"""
from __future__ import annotations

import argparse
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Optional, Sequence

from mitigations.admission_control import AdmissionController, HandshakeRejected
from protocol import PeerPair, run_handshake
from protocol.session import SecurityMode
from qkd_client import QKDClient, QKDMode, QKDServerError, QKDUnavailable

from .harness import (
    KEY_SIZE_BITS,
    PoolSampler,
    QKDServerProcess,
    RateLimiter,
    ensure_results_dirs,
    jains_fairness,
    load_config,
    percentile,
    theoretical_max_rate,
    write_csv,
)

RECORD_FIELDNAMES = [
    "config_id",
    "timestamp",
    "elapsed_s",
    "qkd_supply_bps",
    "handshake_rate",
    "peer_id",
    "pool_occupancy_snapshot",
    "keys_requested",
    "keys_granted",
    "starvation",
    "latency_ms",
    "handshake_success",
    "security_mode",
    "downgraded",
    "app_visible_downgrade",
    "admission_rejected",
    "error",
]

SUMMARY_FIELDNAMES = [
    "config_id",
    "qkd_supply_bps",
    "handshake_rate",
    "duration_s",
    "theoretical_max_hps",
    "offered",
    "achieved_offer_hps",
    "generator_saturated",
    "completed",
    "failed",
    "admission_rejected",
    "hybrid_successes",
    "pqc_only_successes",
    "throughput_hps",
    "hybrid_throughput_hps",
    "starvation_rate",
    "downgrade_rate",
    "app_visible_downgrade_rate",
    "keys_requested",
    "keys_granted",
    "qkd_utilization",
    "latency_ms_median",
    "latency_ms_p95",
    "mean_pool_occupancy",
    "fairness_jain",
]

POOL_FIELDNAMES = ["config_id", "qkd_supply_bps", "handshake_rate", "elapsed_s", "occupancy"]

#: The generator, not the QKD supply, was the bottleneck for this attempt.
ERROR_SATURATED = "generator_saturated"


@dataclass
class HandshakeRecord:
    """One offered handshake, from the load generator's point of view."""

    config_id: str
    timestamp: float
    elapsed_s: float
    qkd_supply_bps: int
    handshake_rate: float
    peer_id: str
    pool_occupancy_snapshot: int
    keys_requested: int
    keys_granted: int
    starvation: bool
    latency_ms: float
    handshake_success: bool
    security_mode: str
    downgraded: bool
    app_visible_downgrade: bool
    admission_rejected: bool = False
    error: str = ""


@dataclass
class LoadResult:
    config_id: str
    qkd_supply_bps: int
    handshake_rate: float
    #: The true measurement window: first offer to last completion. All
    #: per-second metrics are normalized by this, not by the nominal
    #: duration, so a saturated generator cannot inflate them.
    duration_s: float
    records: list[HandshakeRecord]
    pool_samples: list[tuple[float, int]] = field(default_factory=list)
    #: Keys discarded to bring the pool to a defined (empty) starting state.
    drained_at_start: int = 0
    #: How long the generator spent offering load (~the configured duration).
    offered_window_s: float = 0.0

    @property
    def completed(self) -> list[HandshakeRecord]:
        return [record for record in self.records if record.handshake_success]

    def summary(self, peer_ids: Sequence[str]) -> dict:
        records, completed = self.records, self.completed
        hybrid = [r for r in completed if r.security_mode == SecurityMode.HYBRID.value]
        pqc_only = [r for r in completed if r.security_mode == SecurityMode.COMPUTATIONAL_ONLY.value]
        latencies = [r.latency_ms for r in completed]
        keys_requested = sum(r.keys_requested for r in records)
        keys_granted = sum(r.keys_granted for r in records)
        supplied = self.qkd_supply_bps * self.duration_s / KEY_SIZE_BITS

        # Fairness over hybrid (i.e. QKD-key-bearing) handshakes per peer: an
        # equal split across peers gives 1.0.
        per_peer = {peer: 0.0 for peer in peer_ids}
        for record in hybrid:
            per_peer[record.peer_id] = per_peer.get(record.peer_id, 0.0) + 1.0

        occupancies = [depth for _, depth in self.pool_samples]

        return {
            "config_id": self.config_id,
            "qkd_supply_bps": self.qkd_supply_bps,
            "handshake_rate": self.handshake_rate,
            "duration_s": round(self.duration_s, 3),
            "theoretical_max_hps": round(theoretical_max_rate(self.qkd_supply_bps), 4),
            "offered": len(records),
            "achieved_offer_hps": round(len(records) / self.duration_s, 4),
            "generator_saturated": sum(1 for r in records if r.error == ERROR_SATURATED),
            "completed": len(completed),
            "failed": sum(1 for r in records if not r.handshake_success and not r.admission_rejected),
            "admission_rejected": sum(1 for r in records if r.admission_rejected),
            "hybrid_successes": len(hybrid),
            "pqc_only_successes": len(pqc_only),
            "throughput_hps": round(len(completed) / self.duration_s, 4),
            "hybrid_throughput_hps": round(len(hybrid) / self.duration_s, 4),
            "starvation_rate": _ratio(sum(1 for r in records if r.starvation), len(records)),
            # The headline metric: of the handshakes that *succeeded*, what
            # fraction rested on the KEMs alone?
            "downgrade_rate": _ratio(len(pqc_only), len(completed)),
            "app_visible_downgrade_rate": _ratio(
                sum(1 for r in completed if r.app_visible_downgrade), len(completed)
            ),
            "keys_requested": keys_requested,
            "keys_granted": keys_granted,
            "qkd_utilization": _ratio(keys_granted, supplied),
            "latency_ms_median": round(percentile(latencies, 0.5), 4),
            "latency_ms_p95": round(percentile(latencies, 0.95), 4),
            "mean_pool_occupancy": (
                round(sum(occupancies) / len(occupancies), 2) if occupancies else 0.0
            ),
            "fairness_jain": round(jains_fairness(list(per_peer.values())), 4),
        }


def _ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def finally_release(
    admission: Optional[AdmissionController], ticket, consumed: bool = True
) -> None:
    """Settle an admission reservation, whatever the handshake's outcome.

    `consumed=False` credits the key back: the handshake died without ever
    pulling one, so it should not count against the projected supply.
    """
    if admission is not None and ticket is not None:
        admission.release(ticket, consumed=consumed)


class _WorkerClients:
    """Per-thread QKD client pairs.

    Each worker owns its clients, so `keys_requested`/`keys_granted` deltas
    are attributable to a single handshake without locking.
    """

    def __init__(self, base_url: str, mode: QKDMode, gate=None) -> None:
        self.base_url = base_url
        self.mode = mode
        self.gate = gate
        self._local = threading.local()
        self._all: list[QKDClient] = []
        self._lock = threading.Lock()

    def get(self) -> tuple[QKDClient, QKDClient]:
        pair = getattr(self._local, "pair", None)
        if pair is None:
            pair = (
                QKDClient(self.base_url, "SAE-BOB", self.mode, gate=self.gate),
                QKDClient(self.base_url, "SAE-ALICE", self.mode, gate=self.gate),
            )
            self._local.pair = pair
            with self._lock:
                self._all.extend(pair)
        return pair

    def close(self) -> None:
        with self._lock:
            for client in self._all:
                client.close()
            self._all.clear()


def run_load(
    server: QKDServerProcess,
    handshake_rate: float,
    duration_s: float,
    peers_by_id: dict[str, PeerPair],
    *,
    mode: QKDMode = QKDMode.REFERENCE_SILENT,
    config_id: str = "run",
    worker_threads: int = 32,
    warmup_s: float = 0.0,
    sampler_interval_s: float = 0.1,
    gate=None,
    admission: Optional["AdmissionController"] = None,
    drain_first: bool = True,
    offer_sequence: Optional[Sequence[str]] = None,
) -> LoadResult:
    """Offer `handshake_rate` handshakes/sec for `duration_s` against `server`.

    `gate` is a per-peer quota consulted inside the QKD client; `admission`
    is an `AdmissionController` whose `admit()` runs *before* any crypto
    work and raises to reject. Both are None for the reference configuration.

    `drain_first` empties the pool so every configuration starts from the
    same defined state; otherwise the keys that accumulate while the server
    boots can carry a short run and hide genuine starvation.

    `offer_sequence` is the round-robin order of offering peers; repeat a
    peer in it to give that peer a larger share of the offered load (the
    mitigation study uses this to model a greedy peer). Defaults to one
    offer per peer, in order.
    """
    peer_ids = list(peers_by_id)
    offers = list(offer_sequence) if offer_sequence else peer_ids
    drained = server.drain() if drain_first else 0
    # `drained` accumulates again after warm-up; see below.
    if drain_first and admission is not None:
        admission.resync(server.occupancy())
    clients = _WorkerClients(server.base_url, mode, gate=gate)
    sampler = PoolSampler(server, interval_seconds=sampler_interval_s)
    records: list[HandshakeRecord] = []
    # Deliberately shallow: a deep queue would let the generator absorb
    # offered load and smear the moment starvation begins.
    max_backlog = max(worker_threads * 2, 8)

    def one_handshake(peer_id: str, offered_at: float) -> HandshakeRecord:
        initiator_client, responder_client = clients.get()
        snapshot = sampler.latest
        requested_before = initiator_client.keys_requested
        granted_before = initiator_client.keys_granted
        starved_before = initiator_client.starvation_events

        base = dict(
            config_id=config_id,
            timestamp=time.time(),
            elapsed_s=round(offered_at, 4),
            qkd_supply_bps=server.refill_rate_bps,
            handshake_rate=handshake_rate,
            peer_id=peer_id,
            pool_occupancy_snapshot=snapshot,
        )

        ticket = None
        if admission is not None:
            try:
                ticket = admission.admit(peer_id)
            except HandshakeRejected as exc:
                # Rejected before any KEM operation or round trip: that is the
                # point of admission control.
                return HandshakeRecord(
                    **base,
                    keys_requested=0,
                    keys_granted=0,
                    starvation=False,
                    latency_ms=0.0,
                    handshake_success=False,
                    security_mode="rejected",
                    downgraded=False,
                    app_visible_downgrade=False,
                    admission_rejected=True,
                    error=type(exc).__name__,
                )

        start = time.perf_counter()
        try:
            outcome = run_handshake(peers_by_id[peer_id], initiator_client, responder_client)
        except (QKDUnavailable, QKDServerError) as exc:
            finally_release(
                admission, ticket, consumed=initiator_client.keys_granted > granted_before
            )
            return HandshakeRecord(
                **base,
                keys_requested=initiator_client.keys_requested - requested_before,
                keys_granted=initiator_client.keys_granted - granted_before,
                starvation=initiator_client.starvation_events > starved_before,
                latency_ms=round((time.perf_counter() - start) * 1000.0, 4),
                handshake_success=False,
                security_mode="aborted",
                downgraded=False,
                app_visible_downgrade=False,
                error=type(exc).__name__,
            )
        except Exception as exc:
            finally_release(
                admission, ticket, consumed=initiator_client.keys_granted > granted_before
            )
            return HandshakeRecord(
                **base,
                keys_requested=initiator_client.keys_requested - requested_before,
                keys_granted=initiator_client.keys_granted - granted_before,
                starvation=initiator_client.starvation_events > starved_before,
                latency_ms=round((time.perf_counter() - start) * 1000.0, 4),
                handshake_success=False,
                security_mode="error",
                downgraded=False,
                app_visible_downgrade=False,
                error=f"{type(exc).__name__}: {exc}"[:120],
            )

        finally_release(
            admission, ticket, consumed=initiator_client.keys_granted > granted_before
        )
        session = outcome.initiator.internal_session
        return HandshakeRecord(
            **base,
            keys_requested=initiator_client.keys_requested - requested_before,
            keys_granted=initiator_client.keys_granted - granted_before,
            starvation=initiator_client.starvation_events > starved_before,
            latency_ms=round(outcome.latency_ms, 4),
            handshake_success=outcome.keys_match,
            security_mode=session.security_mode.value,
            # Ground truth, then what the application was actually told.
            downgraded=session.downgraded,
            app_visible_downgrade=outcome.initiator.app_visible_downgrade,
        )

    limiter = RateLimiter(handshake_rate)
    try:
        with sampler, ThreadPoolExecutor(max_workers=worker_threads) as pool:
            # Warm-up: drive real load so the pool reaches steady state before
            # anything is recorded.
            if warmup_s > 0:
                warm_limiter = RateLimiter(handshake_rate)
                warm_limiter.start()
                warm_start = time.monotonic()
                warm_futures: list[Future] = []
                index = 0
                while time.monotonic() - warm_start < warmup_s:
                    warm_limiter.wait_next()
                    if len(warm_futures) < max_backlog:
                        warm_futures.append(
                            pool.submit(one_handshake, offers[index % len(offers)], 0.0)
                        )
                    index += 1
                    warm_futures = [f for f in warm_futures if not f.done()]
                for future in warm_futures:
                    future.exception()
                if drain_first:
                    # Warm-up leaves whatever stock its own offered rate
                    # happened to allow. Draining again means measurement
                    # starts from a defined empty pool with the code paths and
                    # HTTP connections already warm, so hybrid throughput
                    # converges on supply/256 from below instead of being
                    # topped up by an arbitrary head start.
                    drained += server.drain()
                    if admission is not None:
                        # The drain is invisible to the pool sampler for up to
                        # one interval; tell the controller directly.
                        admission.resync(server.occupancy())

            limiter.start()
            measure_start = time.monotonic()
            futures: list[Future] = []
            pending: list[Future] = []
            index = 0
            while True:
                offered_at = limiter.wait_next()
                if offered_at >= duration_s:
                    break
                peer_id = offers[index % len(offers)]
                index += 1
                pending = [f for f in pending if not f.done()]
                if len(pending) >= max_backlog:
                    # Record the attempt, but flag that we -- not the QKD
                    # supply -- were the limiting factor.
                    records.append(
                        HandshakeRecord(
                            config_id=config_id,
                            timestamp=time.time(),
                            elapsed_s=round(offered_at, 4),
                            qkd_supply_bps=server.refill_rate_bps,
                            handshake_rate=handshake_rate,
                            peer_id=peer_id,
                            pool_occupancy_snapshot=sampler.latest,
                            keys_requested=0,
                            keys_granted=0,
                            starvation=False,
                            latency_ms=0.0,
                            handshake_success=False,
                            security_mode="not_attempted",
                            downgraded=False,
                            app_visible_downgrade=False,
                            error=ERROR_SATURATED,
                        )
                    )
                    continue
                future = pool.submit(one_handshake, peer_id, offered_at)
                futures.append(future)
                pending.append(future)

            offered_window = time.monotonic() - measure_start
            for future in futures:
                records.append(future.result())
            # Includes the tail of in-flight handshakes, which also drew on
            # the QKD supply and so must be inside the window we divide by.
            window = time.monotonic() - measure_start
    finally:
        clients.close()

    return LoadResult(
        config_id=config_id,
        qkd_supply_bps=server.refill_rate_bps,
        handshake_rate=handshake_rate,
        duration_s=window,
        records=records,
        pool_samples=[(sample.elapsed_s, sample.occupancy) for sample in sampler.samples],
        drained_at_start=drained,
        offered_window_s=round(offered_window, 3),
    )


def build_peers(peer_ids: Sequence[str], kem: str) -> dict[str, PeerPair]:
    """One long-term identity per simulated peer, generated once.

    Each simulated peer is a distinct **remote** counterpart of one local
    SAE, so `Initiator.peer_id` -- the id the QKD client hands to a quota
    gate -- differs per peer. Making them all share one responder identity
    would collapse every peer into a single quota bucket.
    """
    return {
        peer_id: PeerPair.generate(kem, initiator_id="SAE-ALICE", responder_id=peer_id)
        for peer_id in peer_ids
    }


def default_peer_ids(count: int = 4) -> list[str]:
    return [f"peer-{index}" for index in range(count)]


def run_sweep(config: Optional[dict] = None, duration_override: Optional[float] = None) -> dict:
    """The 6 x 3 rate x supply sweep."""
    config = config or load_config("load_sweep.yaml")
    settings = config["sweep"]
    output = config["output"]

    rates = list(settings["handshake_rates_hps"])
    supplies = list(settings["qkd_supply_bps"])
    duration = float(duration_override or settings["duration_seconds"])
    kem = settings["kem"]
    mode = QKDMode(settings["qkd_mode"])
    workers = int(settings["worker_threads"])
    warmup = float(settings.get("warmup_seconds", 0.0))
    sampler_interval = float(settings.get("sampler_interval_seconds", 0.1))
    pool_settings = settings.get("pool", {})

    ensure_results_dirs()
    peer_ids = default_peer_ids()
    peers_by_id = build_peers(peer_ids, kem)

    all_records: list[dict] = []
    summaries: list[dict] = []
    pool_rows: list[dict] = []

    total = len(supplies) * len(rates)
    index = 0
    for supply in supplies:
        for rate in rates:
            index += 1
            config_id = f"s{supply}_r{rate}"
            ceiling = theoretical_max_rate(supply)
            print(
                f"[{index}/{total}] supply={supply} bps ({ceiling:.1f} hybrid hps ceiling) "
                f"rate={rate} hps duration={duration}s",
                flush=True,
            )
            server = QKDServerProcess(
                refill_rate_bps=supply,
                max_keys=int(pool_settings.get("max_keys", 1024)),
                key_size_bits=int(pool_settings.get("key_size_bits", KEY_SIZE_BITS)),
                log_path=output.get("server_log"),
            ).start()
            try:
                result = run_load(
                    server,
                    handshake_rate=rate,
                    duration_s=duration,
                    peers_by_id=peers_by_id,
                    mode=mode,
                    config_id=config_id,
                    worker_threads=workers,
                    warmup_s=warmup,
                    sampler_interval_s=sampler_interval,
                )
            finally:
                server.stop()

            summary = result.summary(peer_ids)
            summaries.append(summary)
            all_records.extend(asdict(record) for record in result.records)
            pool_rows.extend(
                {
                    "config_id": config_id,
                    "qkd_supply_bps": supply,
                    "handshake_rate": rate,
                    "elapsed_s": round(elapsed, 3),
                    "occupancy": occupancy,
                }
                for elapsed, occupancy in result.pool_samples
            )
            print(
                f"    throughput={summary['throughput_hps']:.2f} hps "
                f"hybrid={summary['hybrid_throughput_hps']:.2f} hps "
                f"downgrade_rate={summary['downgrade_rate']:.3f} "
                f"starvation_rate={summary['starvation_rate']:.3f}",
                flush=True,
            )

    sweep_path = write_csv(output["sweep_csv"], RECORD_FIELDNAMES, all_records)
    summary_path = write_csv(
        output.get("sweep_summary_csv", "results/starvation_summary.csv"),
        SUMMARY_FIELDNAMES,
        summaries,
    )
    pool_path = write_csv(output["pool_csv"], POOL_FIELDNAMES, pool_rows)

    print(f"wrote {sweep_path} ({len(all_records)} rows)")
    print(f"wrote {summary_path} ({len(summaries)} configurations)")
    print(f"wrote {pool_path} ({len(pool_rows)} samples)")
    return {"summaries": summaries}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="QKD starvation load sweep")
    parser.add_argument("--config", type=str, default="load_sweep.yaml")
    parser.add_argument("--duration", type=float, default=None, help="seconds per configuration")
    args = parser.parse_args(argv)

    run_sweep(load_config(args.config), duration_override=args.duration)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
