"""Headline experiment: silent downgrade against a fixed QKD supply.

Runs `REFERENCE_SILENT` at increasing offered load against one fixed supply
and measures, per load level:

    downgrade_rate = PQC-only successful handshakes / all successful handshakes

This is the experiment that answers the research question directly. It also
locates the **throughput knee** -- the highest offered rate whose
silent-downgrade rate is still below `knee_downgrade_threshold` -- and
compares it with the theoretical ceiling `supply_bps / 256`.

Two outputs (DECISIONS.md D10):

* `results/downgrade_events.csv` -- one row per handshake attempt (the events),
* `results/downgrade_summary.csv` -- one row per load level, with the rate.

    python -m experiments.downgrade_study [--duration 30]
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from typing import Optional, Sequence

from qkd_client import QKDMode

from .harness import (
    KEY_SIZE_BITS,
    QKDServerProcess,
    ensure_results_dirs,
    load_config,
    theoretical_max_rate,
    write_csv,
)
from .load_generator import (
    RECORD_FIELDNAMES,
    SUMMARY_FIELDNAMES,
    build_peers,
    default_peer_ids,
    run_load,
)


def detect_knee(summaries: Sequence[dict], threshold: float) -> dict:
    """Locate the load level where hybrid security starts to be lost.

    `knee_hps` is the highest offered rate whose downgrade rate is still
    below `threshold`; `first_degraded_hps` is the lowest offered rate above
    it. The truth lies between them, and the theoretical ceiling should too.
    """
    ordered = sorted(summaries, key=lambda row: row["handshake_rate"])
    below = [row for row in ordered if row["downgrade_rate"] < threshold]
    above = [row for row in ordered if row["downgrade_rate"] >= threshold]

    supply = ordered[0]["qkd_supply_bps"] if ordered else 0
    theoretical = theoretical_max_rate(supply)
    knee = below[-1]["handshake_rate"] if below else None
    first_degraded = above[0]["handshake_rate"] if above else None

    # Peak measured hybrid throughput: the empirical ceiling, whatever the
    # offered rate was.
    peak_hybrid = max((row["hybrid_throughput_hps"] for row in ordered), default=0.0)

    return {
        "qkd_supply_bps": supply,
        "key_size_bits": KEY_SIZE_BITS,
        "theoretical_max_hps": round(theoretical, 4),
        "downgrade_threshold": threshold,
        "knee_hps": knee,
        "first_degraded_hps": first_degraded,
        "peak_hybrid_throughput_hps": round(peak_hybrid, 4),
        "peak_vs_theoretical": (
            round(peak_hybrid / theoretical, 4) if theoretical else None
        ),
    }


def run_downgrade_study(
    config: Optional[dict] = None, duration_override: Optional[float] = None
) -> dict:
    config = config or load_config("load_sweep.yaml")
    settings = config["downgrade_study"]
    output = config["output"]

    supply = int(settings["qkd_supply_bps"])
    rates = list(settings["handshake_rates_hps"])
    duration = float(duration_override or settings["duration_seconds"])
    kem = settings["kem"]
    workers = int(settings["worker_threads"])
    warmup = float(settings.get("warmup_seconds", 0.0))
    sampler_interval = float(settings.get("sampler_interval_seconds", 0.1))
    threshold = float(settings.get("knee_downgrade_threshold", 0.05))
    pool_settings = settings.get("pool", {})

    ensure_results_dirs()
    peer_ids = default_peer_ids()
    peers_by_id = build_peers(peer_ids, kem)

    ceiling = theoretical_max_rate(supply)
    print(
        f"downgrade study: supply={supply} bps, theoretical ceiling "
        f"{ceiling:.2f} hybrid handshakes/sec, mode=reference_silent"
    )

    events: list[dict] = []
    summaries: list[dict] = []

    for index, rate in enumerate(rates, start=1):
        config_id = f"downgrade_r{rate}"
        print(f"[{index}/{len(rates)}] rate={rate} hps duration={duration}s", flush=True)
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
                mode=QKDMode.REFERENCE_SILENT,
                config_id=config_id,
                worker_threads=workers,
                warmup_s=warmup,
                sampler_interval_s=sampler_interval,
            )
        finally:
            server.stop()

        summary = result.summary(peer_ids)
        summaries.append(summary)
        events.extend(asdict(record) for record in result.records)
        print(
            f"    completed={summary['completed']} "
            f"hybrid={summary['hybrid_successes']} pqc_only={summary['pqc_only_successes']} "
            f"downgrade_rate={summary['downgrade_rate']:.3f} "
            f"app_told={summary['app_visible_downgrade_rate']:.3f}",
            flush=True,
        )

    knee = detect_knee(summaries, threshold)

    events_path = write_csv(output["downgrade_csv"], RECORD_FIELDNAMES, events)
    summary_path = write_csv(output["downgrade_summary_csv"], SUMMARY_FIELDNAMES, summaries)

    print(f"wrote {events_path} ({len(events)} events)")
    print(f"wrote {summary_path} ({len(summaries)} load levels)")
    _print_findings(summaries, knee)
    return {"summaries": summaries, "knee": knee}


def _print_findings(summaries: list[dict], knee: dict) -> None:
    print()
    print(
        f"{'offered hps':>12}{'throughput':>12}{'hybrid hps':>12}"
        f"{'downgrade':>11}{'app told':>10}{'p95 ms':>9}"
    )
    for row in summaries:
        print(
            f"{row['handshake_rate']:>12.1f}{row['throughput_hps']:>12.2f}"
            f"{row['hybrid_throughput_hps']:>12.2f}{row['downgrade_rate']:>11.3f}"
            f"{row['app_visible_downgrade_rate']:>10.3f}{row['latency_ms_p95']:>9.1f}"
        )
    print()
    print(f"theoretical ceiling (supply/{knee['key_size_bits']}): "
          f"{knee['theoretical_max_hps']:.2f} hybrid hps")
    print(f"peak measured hybrid throughput:  {knee['peak_hybrid_throughput_hps']:.2f} hps "
          f"({knee['peak_vs_theoretical']} x theoretical)")
    print(f"knee (last rate with downgrade_rate < {knee['downgrade_threshold']}): "
          f"{knee['knee_hps']} hps; first degraded at {knee['first_degraded_hps']} hps")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Silent downgrade study")
    parser.add_argument("--config", type=str, default="load_sweep.yaml")
    parser.add_argument("--duration", type=float, default=None)
    args = parser.parse_args(argv)

    run_downgrade_study(load_config(args.config), duration_override=args.duration)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
