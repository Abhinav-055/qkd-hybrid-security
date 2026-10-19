"""Per-KEM performance benchmark: hybrid HAKE vs pure-PQC baseline.

1000 handshakes for each (protocol, KEM) pair, with the QKD pool kept far
above demand so this measures protocol cost rather than starvation. The
difference between the two protocols at the same KEM is the **cost of
hybridization**.

The two protocols are **interleaved run by run**, with the order alternating
each iteration, because the host slows measurably under sustained load. A
block-sequential version of this benchmark measured pure-PQC FrodoKEM as
25 ms *slower* than hybrid FrodoKEM -- a negative cost of hybridization,
entirely an artifact of the baseline block running last. Each configuration
also reports `latency_drift_ratio` so residual host slowdown is visible
rather than silent.

Outputs `results/benchmark.csv` (one row per run) and
`results/benchmark_summary.json` (median and P95 per configuration).

    python -m experiments.benchmark [--config configs/benchmark.yaml]
"""
from __future__ import annotations

import argparse
import time
from typing import Optional

from baseline import run_pure_pqc_handshake
from crypto.kem import kem_sizes
from protocol import PeerPair, run_handshake
from protocol.session import SecurityMode
from qkd_client import QKDClient, QKDMode

from .harness import (
    QKDServerProcess,
    ensure_results_dirs,
    iter_progress,
    load_config,
    median,
    percentile,
    write_csv,
    write_json,
)

FIELDNAMES = [
    "protocol",
    "kem",
    "run_id",
    "latency_ms",
    "cpu_ms",
    "bytes_sent",
    "bytes_received",
    "success",
]

HYBRID = "hybrid_hake"
PURE_PQC = "pure_pqc"


def _run_one(protocol: str, peers: PeerPair, clients) -> dict:
    """One handshake, timed. `clients` is (initiator, responder) or None."""
    if protocol == PURE_PQC:
        outcome = run_pure_pqc_handshake(peers)
        expected_mode = SecurityMode.COMPUTATIONAL_ONLY
    else:
        outcome = run_handshake(peers, clients[0], clients[1])
        expected_mode = SecurityMode.HYBRID

    session = outcome.initiator.internal_session
    if session.security_mode is not expected_mode:
        # A hybrid run that downgraded means the pool starved, which would
        # silently make this a baseline measurement wearing a hybrid label.
        raise RuntimeError(
            f"{protocol} run produced {session.security_mode.value}, expected "
            f"{expected_mode.value}: the benchmark's QKD supply is too low"
        )

    return {
        "latency_ms": round(outcome.latency_ms, 4),
        "cpu_ms": round(outcome.cpu_ms, 4),
        "bytes_sent": outcome.bytes_sent,
        "bytes_received": outcome.bytes_received,
        "success": outcome.keys_match,
    }


def _drift(latencies: list[float]) -> float:
    """Second-half median over first-half median, as a host-slowdown signal."""
    if len(latencies) < 4:
        return 1.0
    half = len(latencies) // 2
    first = median(latencies[:half])
    return median(latencies[half:]) / first if first else 1.0


def run_benchmark(config: Optional[dict] = None) -> dict:
    """Run every (protocol, KEM) configuration and write both outputs."""
    config = config or load_config("benchmark.yaml")
    settings = config["benchmark"]
    server_settings = config["qkd_server"]
    output = config["output"]

    runs = int(settings["runs_per_configuration"])
    kems = list(settings["kems"])
    protocols = list(settings["protocols"])
    progress_every = int(settings.get("progress_every", 0)) or runs + 1

    ensure_results_dirs()
    rows: list[dict] = []
    started = time.monotonic()

    server = QKDServerProcess(
        refill_rate_bps=int(server_settings["refill_rate_bps"]),
        max_keys=int(server_settings["max_keys"]),
        key_size_bits=int(server_settings["key_size_bits"]),
        log_path=server_settings.get("log_path"),
    ).start()
    try:
        server.wait_for_keys(int(server_settings.get("prefill_keys", 16)))

        for kem in kems:
            # One long-term identity per protocol, generated once: keygen is a
            # long-term cost and must not be charged to every session.
            peers_by_protocol = {protocol: PeerPair.generate(kem) for protocol in protocols}
            clients = (
                QKDClient(server.base_url, "SAE-BOB", QKDMode.REFERENCE_SILENT),
                QKDClient(server.base_url, "SAE-ALICE", QKDMode.REFERENCE_SILENT),
            )
            try:
                label = f"{'+'.join(protocols)}/{kem}"
                for run_id in iter_progress(label, runs, every=progress_every):
                    # Interleave the protocols instead of running all of one
                    # then all of the other. This machine slows measurably
                    # under sustained load (up to 1.6x within a single
                    # configuration), so block-sequential measurement puts the
                    # two protocols under different conditions and corrupts the
                    # paired difference -- it produced a *negative* cost of
                    # hybridization. Alternating the order each run cancels
                    # both the drift and any within-iteration ordering bias.
                    order = protocols if run_id % 2 == 0 else list(reversed(protocols))
                    for protocol in order:
                        row = _run_one(protocol, peers_by_protocol[protocol], clients)
                        row.update(protocol=protocol, kem=kem, run_id=run_id)
                        rows.append(row)
            finally:
                for client in clients:
                    client.close()
            print(f"  done {kem} ({runs} runs x {len(protocols)} protocols)", flush=True)
    finally:
        server.stop()

    csv_path = write_csv(output["csv"], FIELDNAMES, rows)
    summary = summarize(rows, runs=runs, elapsed_s=time.monotonic() - started)
    summary_path = write_json(output["summary_json"], summary)

    print(f"wrote {csv_path} ({len(rows)} rows)")
    print(f"wrote {summary_path}")
    _print_table(summary)
    return summary


def summarize(rows: list[dict], runs: int, elapsed_s: float) -> dict:
    """Median and P95 latency/CPU plus wire sizes, per configuration."""
    configurations: dict[str, dict] = {}
    for row in rows:
        key = f"{row['protocol']}|{row['kem']}"
        configurations.setdefault(key, []).append(row)

    per_configuration = {}
    for key, group in sorted(configurations.items()):
        protocol, kem = key.split("|")
        latencies = [float(row["latency_ms"]) for row in group]
        cpus = [float(row["cpu_ms"]) for row in group]
        per_configuration[key] = {
            "protocol": protocol,
            "kem": kem,
            "runs": len(group),
            "successes": sum(1 for row in group if row["success"]),
            "latency_ms_median": round(median(latencies), 4),
            "latency_ms_p95": round(percentile(latencies, 0.95), 4),
            "latency_ms_min": round(min(latencies), 4),
            "latency_ms_max": round(max(latencies), 4),
            # Per-run CPU readings are quantized by the OS scheduler tick
            # (15.625 ms on Windows), so the *mean* is the trustworthy
            # statistic: consecutive process_time deltas sum to the true total
            # CPU for the configuration, so mean = total / runs exactly.
            # Median and P95 are reported for completeness but will look like
            # 0 / one tick on fast KEMs. See README "reading the results".
            "cpu_ms_mean": round(sum(cpus) / len(cpus), 4),
            "cpu_ms_median": round(median(cpus), 4),
            "cpu_ms_p95": round(percentile(cpus, 0.95), 4),
            "bytes_sent": group[0]["bytes_sent"],
            "bytes_received": group[0]["bytes_received"],
            "bytes_total": group[0]["bytes_sent"] + group[0]["bytes_received"],
            # Machine drift check: second-half median / first-half median.
            # Well above 1.0 means the host slowed during the run (thermal or
            # power throttling), so absolute latencies are not comparable
            # across configurations. The protocols are interleaved, so the
            # paired hybrid-minus-baseline delta survives drift even when
            # this is large -- but the reader should know.
            "latency_drift_ratio": round(_drift(latencies), 4),
        }

    # Cost of hybridization: the same KEM, with and without QKD.
    hybridization_cost = {}
    for kem in sorted({row["kem"] for row in rows}):
        hybrid = per_configuration.get(f"{HYBRID}|{kem}")
        baseline = per_configuration.get(f"{PURE_PQC}|{kem}")
        if not hybrid or not baseline:
            continue
        hybridization_cost[kem] = {
            "latency_ms_median_delta": round(
                hybrid["latency_ms_median"] - baseline["latency_ms_median"], 4
            ),
            "latency_overhead_percent": round(
                100.0 * (hybrid["latency_ms_median"] / baseline["latency_ms_median"] - 1.0), 2
            ),
            "cpu_ms_mean_delta": round(hybrid["cpu_ms_mean"] - baseline["cpu_ms_mean"], 4),
            "bytes_total_delta": hybrid["bytes_total"] - baseline["bytes_total"],
        }

    return {
        "cpu_measurement_note": (
            "Per-run cpu_ms is quantized by the OS scheduler tick, so use "
            "cpu_ms_mean (= total CPU / runs); cpu_ms_median and cpu_ms_p95 "
            "are artifacts of that quantization on fast KEMs."
        ),
        "runs_per_configuration": runs,
        "total_runs": len(rows),
        "elapsed_seconds": round(elapsed_s, 1),
        "kem_parameters": kem_sizes(),
        "per_configuration": per_configuration,
        "cost_of_hybridization": hybridization_cost,
    }


def _print_table(summary: dict) -> None:
    print()
    print(
        f"{'protocol':<14}{'kem':<18}{'median ms':>11}{'p95 ms':>10}"
        f"{'cpu mean':>10}{'sent B':>9}{'recv B':>9}{'drift':>8}"
    )
    for entry in summary["per_configuration"].values():
        print(
            f"{entry['protocol']:<14}{entry['kem']:<18}"
            f"{entry['latency_ms_median']:>11.3f}{entry['latency_ms_p95']:>10.3f}"
            f"{entry['cpu_ms_mean']:>10.3f}{entry['bytes_sent']:>9}"
            f"{entry['bytes_received']:>9}{entry['latency_drift_ratio']:>8.2f}"
        )
    print()
    print("cost of hybridization (hybrid - baseline, median latency):")
    for kem, cost in summary["cost_of_hybridization"].items():
        print(
            f"  {kem:<18}{cost['latency_ms_median_delta']:+8.3f} ms "
            f"({cost['latency_overhead_percent']:+.1f}%)  "
            f"{cost['bytes_total_delta']:+d} bytes"
        )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Per-KEM HAKE benchmark")
    parser.add_argument("--config", type=str, default="benchmark.yaml")
    parser.add_argument("--runs", type=int, default=None, help="override runs per configuration")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    if args.runs is not None:
        config["benchmark"]["runs_per_configuration"] = args.runs
    run_benchmark(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
