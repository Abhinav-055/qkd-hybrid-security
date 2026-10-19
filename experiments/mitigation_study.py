"""Mitigation comparison: reference vs quota vs admission control vs signalling.

The same load sweep is run four times against the same fixed QKD supply,
with four simulated peers of which one is greedy. For each configuration
and load level we record throughput, rejection rate, silent-downgrade rate,
P95 latency, QKD utilization, and Jain's fairness index across peers.

The comparison the study is after:

* **reference** -- throughput holds up, security quietly evaporates.
* **quota** -- same aggregate hybrid ceiling, but hybrid sessions are shared
  fairly instead of captured by the greedy peer.
* **admission_control** -- silent downgrades go to zero, paid for with
  visible rejections.
* **explicit_downgrade** -- identical numbers to reference, except the
  application is actually told.

    python -m experiments.mitigation_study [--duration 30]
"""
from __future__ import annotations

import argparse
import warnings
from dataclasses import asdict
from typing import Optional

from mitigations.admission_control import AdmissionController, AdmissionPolicy
from mitigations.quota import PeerQuota, QuotaPolicy
from protocol import SecurityDowngradeWarning
from protocol.session import SecurityMode
from qkd_client import QKDMode

from .harness import (
    KEY_SIZE_BITS,
    PoolSampler,
    QKDServerProcess,
    ensure_results_dirs,
    jains_fairness,
    load_config,
    theoretical_max_rate,
    write_csv,
    write_json,
)
from .load_generator import RECORD_FIELDNAMES, build_peers, run_load

RESULT_FIELDNAMES = [
    "configuration",
    "description",
    "qkd_mode",
    "qkd_supply_bps",
    "handshake_rate",
    "duration_s",
    "theoretical_max_hps",
    "offered",
    "completed",
    "throughput_hps",
    "hybrid_throughput_hps",
    "rejection_rate",
    "silent_downgrade_rate",
    "signalled_downgrade_rate",
    "downgrade_rate",
    "latency_ms_p95",
    "latency_ms_median",
    "qkd_utilization",
    "fairness_jain",
    "greedy_peer_hybrid_share",
    "admitted_but_downgraded",
    "generator_saturated",
]


def _peer_ids(count: int) -> list[str]:
    return [f"peer-{index}" for index in range(count)]


def _offer_sequence(peer_ids: list[str], greedy_multiplier: float) -> list[str]:
    """Round-robin order in which `peer-0` appears `greedy_multiplier` times."""
    repeats = max(int(round(greedy_multiplier)), 1)
    return [peer_ids[0]] * repeats + peer_ids[1:]


def _analyse(
    result,
    peer_ids: list[str],
    configuration: dict,
    supply: int,
) -> dict:
    base = result.summary(peer_ids)
    records = result.records
    completed = result.completed
    hybrid = [r for r in completed if r.security_mode == SecurityMode.HYBRID.value]

    # Silent vs signalled: both are downgrades, but only one is visible to
    # the application. This distinction is the whole point of the study.
    downgraded = [r for r in completed if r.security_mode == SecurityMode.COMPUTATIONAL_ONLY.value]
    signalled = [r for r in downgraded if r.app_visible_downgrade]
    silent = [r for r in downgraded if not r.app_visible_downgrade]

    per_peer_hybrid = {peer: 0 for peer in peer_ids}
    for record in hybrid:
        per_peer_hybrid[record.peer_id] = per_peer_hybrid.get(record.peer_id, 0) + 1
    greedy_share = (
        per_peer_hybrid.get(peer_ids[0], 0) / len(hybrid) if hybrid else 0.0
    )

    # The admission-control guarantee, checked empirically: every handshake
    # that was admitted and completed must be hybrid.
    admitted_but_downgraded = (
        len(silent) + len(signalled) if configuration.get("admission_control") else 0
    )

    return {
        "configuration": configuration["name"],
        "description": configuration.get("description", ""),
        "qkd_mode": configuration["qkd_mode"],
        "qkd_supply_bps": supply,
        "handshake_rate": result.handshake_rate,
        "duration_s": round(result.duration_s, 3),
        "theoretical_max_hps": round(theoretical_max_rate(supply), 4),
        "offered": base["offered"],
        "completed": base["completed"],
        "throughput_hps": base["throughput_hps"],
        "hybrid_throughput_hps": base["hybrid_throughput_hps"],
        "rejection_rate": round(
            sum(1 for r in records if r.admission_rejected) / len(records), 6
        )
        if records
        else 0.0,
        "silent_downgrade_rate": round(len(silent) / len(completed), 6) if completed else 0.0,
        "signalled_downgrade_rate": round(len(signalled) / len(completed), 6)
        if completed
        else 0.0,
        "downgrade_rate": base["downgrade_rate"],
        "latency_ms_p95": base["latency_ms_p95"],
        "latency_ms_median": base["latency_ms_median"],
        "qkd_utilization": base["qkd_utilization"],
        "fairness_jain": round(jains_fairness([float(v) for v in per_peer_hybrid.values()]), 4),
        "greedy_peer_hybrid_share": round(greedy_share, 4),
        "admitted_but_downgraded": admitted_but_downgraded,
        "generator_saturated": base["generator_saturated"],
    }


def run_mitigation_study(
    config: Optional[dict] = None, duration_override: Optional[float] = None
) -> dict:
    config = config or load_config("mitigations.yaml")
    settings = config["mitigation_study"]
    quota_settings = config["quota"]
    admission_settings = config["admission_control"]
    output = config["output"]

    supply = int(settings["qkd_supply_bps"])
    rates = list(settings["handshake_rates_hps"])
    duration = float(duration_override or settings["duration_seconds"])
    kem = settings["kem"]
    workers = int(settings["worker_threads"])
    warmup = float(settings.get("warmup_seconds", 0.0))
    sampler_interval = float(settings.get("sampler_interval_seconds", 0.1))
    peer_count = int(settings.get("peers", 4))
    greedy = float(settings.get("greedy_peer_multiplier", 1.0))
    pool_settings = settings.get("pool", {})
    key_size_bits = int(pool_settings.get("key_size_bits", KEY_SIZE_BITS))

    ensure_results_dirs()
    peer_ids = _peer_ids(peer_count)
    offers = _offer_sequence(peer_ids, greedy)
    peers_by_id = build_peers(peer_ids, kem)

    print(
        f"mitigation study: supply={supply} bps "
        f"({theoretical_max_rate(supply):.2f} hybrid hps ceiling), "
        f"{peer_count} peers, peer-0 offers {greedy:g}x an equal share"
    )

    rows: list[dict] = []
    events: list[dict] = []
    quota_stats: dict = {}
    admission_stats: dict = {}

    configurations = list(settings["configurations"])
    total = len(configurations) * len(rates)
    index = 0

    for configuration in configurations:
        for rate in rates:
            index += 1
            config_id = f"{configuration['name']}_r{rate}"
            print(f"[{index}/{total}] {configuration['name']} rate={rate} hps", flush=True)

            server = QKDServerProcess(
                refill_rate_bps=supply,
                max_keys=int(pool_settings.get("max_keys", 1024)),
                key_size_bits=key_size_bits,
                log_path=output.get("server_log"),
            ).start()
            gate = None
            admission = None
            sampler = None
            try:
                if configuration.get("quota"):
                    gate = PeerQuota(
                        default_policy=QuotaPolicy.from_share(
                            supply_bps=supply,
                            peers=peer_count,
                            key_size_bits=key_size_bits,
                            window_seconds=float(quota_settings["window_seconds"]),
                            share=float(quota_settings["share_of_equal_split"]),
                        )
                    )
                if configuration.get("admission_control"):
                    # Admission reads the pool through its own sampler, so it
                    # adds no HTTP traffic per handshake.
                    sampler = PoolSampler(server, interval_seconds=sampler_interval).start()
                    admission = AdmissionController(
                        occupancy_fn=lambda s=sampler: s.latest,
                        refill_rate_bps=supply,
                        policy=AdmissionPolicy(
                            keys_per_handshake=int(admission_settings["keys_per_handshake"]),
                            horizon_seconds=float(admission_settings["horizon_seconds"]),
                            safety_margin_keys=float(admission_settings["safety_margin_keys"]),
                            # The controller reads this sampler, so its
                            # interval *is* the worst-case staleness.
                            occupancy_staleness_seconds=sampler_interval,
                        ),
                        key_size_bits=key_size_bits,
                        max_keys=int(pool_settings.get("max_keys", 1024)),
                    )

                # Under EXPLICIT_DOWNGRADE every downgraded handshake warns.
                # A real application handles the signal; here it is counted
                # via each record's app_visible_downgrade flag, so suppress
                # the console spam rather than losing the measurement.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SecurityDowngradeWarning)
                    result = run_load(
                        server,
                        handshake_rate=rate,
                        duration_s=duration,
                        peers_by_id=peers_by_id,
                        mode=QKDMode(configuration["qkd_mode"]),
                        config_id=config_id,
                        worker_threads=workers,
                        warmup_s=warmup,
                        sampler_interval_s=sampler_interval,
                        gate=gate,
                        admission=admission,
                        offer_sequence=offers,
                    )
            finally:
                if sampler is not None:
                    sampler.stop()
                server.stop()

            row = _analyse(result, peer_ids, configuration, supply)
            rows.append(row)
            events.extend(asdict(record) for record in result.records)
            if gate is not None:
                quota_stats[config_id] = gate.stats()
            if admission is not None:
                admission_stats[config_id] = admission.stats()

            print(
                f"    throughput={row['throughput_hps']:.2f} "
                f"hybrid={row['hybrid_throughput_hps']:.2f} "
                f"silent={row['silent_downgrade_rate']:.3f} "
                f"signalled={row['signalled_downgrade_rate']:.3f} "
                f"rejected={row['rejection_rate']:.3f} "
                f"fairness={row['fairness_jain']:.3f}",
                flush=True,
            )

    csv_path = write_csv(output["csv"], RESULT_FIELDNAMES, rows)
    events_path = write_csv(output["events_csv"], RECORD_FIELDNAMES, events)
    summary_path = write_json(
        output["summary_json"],
        {
            "qkd_supply_bps": supply,
            "theoretical_max_hps": round(theoretical_max_rate(supply), 4),
            "peers": peer_ids,
            "greedy_peer": peer_ids[0],
            "greedy_peer_multiplier": greedy,
            "quota_stats": quota_stats,
            "admission_stats": admission_stats,
            "rows": rows,
        },
    )

    print(f"wrote {csv_path} ({len(rows)} rows)")
    print(f"wrote {events_path} ({len(events)} events)")
    print(f"wrote {summary_path}")
    _print_comparison(rows)
    _check_guarantees(rows)
    return {"rows": rows}


def _print_comparison(rows: list[dict]) -> None:
    print()
    print(
        f"{'configuration':<20}{'rate':>6}{'thru':>8}{'hybrid':>8}"
        f"{'silent':>9}{'signal':>8}{'reject':>8}{'fair':>7}{'greedy%':>9}"
    )
    for row in rows:
        print(
            f"{row['configuration']:<20}{row['handshake_rate']:>6.0f}"
            f"{row['throughput_hps']:>8.1f}{row['hybrid_throughput_hps']:>8.1f}"
            f"{row['silent_downgrade_rate']:>9.3f}{row['signalled_downgrade_rate']:>8.3f}"
            f"{row['rejection_rate']:>8.3f}{row['fairness_jain']:>7.3f}"
            f"{row['greedy_peer_hybrid_share']:>9.3f}"
        )


def _check_guarantees(rows: list[dict]) -> None:
    """Report whether admission control's stated guarantee actually held."""
    admitted_violations = [
        row for row in rows if row["configuration"] == "admission_control"
        and row["admitted_but_downgraded"] > 0
    ]
    print()
    if admitted_violations:
        print(
            "WARNING: admission control admitted handshakes that downgraded "
            f"in {len(admitted_violations)} configuration(s): "
            + ", ".join(
                f"{row['handshake_rate']:g} hps ({row['admitted_but_downgraded']})"
                for row in admitted_violations
            )
        )
    else:
        print("admission control guarantee held: no admitted handshake downgraded.")

    silent = [
        row for row in rows if row["configuration"] == "explicit_downgrade"
        and row["silent_downgrade_rate"] > 0
    ]
    if silent:
        print(f"WARNING: explicit_downgrade left {len(silent)} configuration(s) with "
              "unsignalled downgrades.")
    else:
        print("explicit downgrade signalling held: every downgrade was reported.")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Mitigation comparison study")
    parser.add_argument("--config", type=str, default="mitigations.yaml")
    parser.add_argument("--duration", type=float, default=None)
    args = parser.parse_args(argv)

    run_mitigation_study(load_config(args.config), duration_override=args.duration)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
