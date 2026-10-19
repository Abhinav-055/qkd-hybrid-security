"""Reproduce every CSV and figure in `results/` from a clean checkout.

    python run_all.py                      # everything
    python run_all.py --only benchmark     # one stage
    python run_all.py --only sweep,plots   # several
    python run_all.py --quick              # short durations, for a smoke run

Stages, in dependency order:

| stage        | produces                                                    |
|--------------|-------------------------------------------------------------|
| `validate`   | `handshake_validation.csv` (10,000-handshake correctness)    |
| `benchmark`  | `benchmark.csv`, `benchmark_summary.json`                    |
| `sweep`      | `starvation_sweep.csv`, `starvation_summary.csv`, `pool_occupancy.csv` |
| `downgrade`  | `downgrade_events.csv`, `downgrade_summary.csv`              |
| `mitigations`| `mitigation_results.csv`, `mitigation_events.csv`, `mitigation_summary.json` |
| `matrix`     | `security_matrix.csv`                                        |
| `plots`      | every figure in `results/figures/`                           |

Each stage starts and stops its own key-server processes on free
ports; nothing needs to be running beforehand. All parameters come from
`configs/*.yaml` -- this script holds no experiment constants of its own,
only the `--quick` overrides and the stage wiring.
"""
from __future__ import annotations

import argparse
import sys
import time
from typing import Callable, Optional, Sequence

from experiments.benchmark import run_benchmark
from experiments.downgrade_study import run_downgrade_study
from experiments.harness import RESULTS_DIR, ensure_results_dirs, load_config
from experiments.load_generator import run_sweep
from experiments.mitigation_study import run_mitigation_study
from experiments.plots import make_figures
from experiments.security_matrix import emit_security_matrix
from experiments.validation import run_validation

STAGES = ("validate", "benchmark", "sweep", "downgrade", "mitigations", "matrix", "plots")

#: Cut-down parameters for `--quick`: proves the pipeline end to end in a few
#: minutes. Never use quick output as a result -- the durations are too short
#: for the pool to reach steady state at every rate.
QUICK = {
    "validation_runs": 200,
    "benchmark_runs": 25,
    "sweep_duration": 5.0,
    "sweep_rates": [1, 10, 100],
    "sweep_supplies": [1000, 100000],
    "downgrade_duration": 8.0,
    "downgrade_rates": [10, 39, 100],
    "mitigation_duration": 8.0,
    "mitigation_rates": [10, 100],
}


def _stage_validate(quick: bool) -> None:
    from experiments.harness import QKDServerProcess

    runs = QUICK["validation_runs"] if quick else 10_000
    # Supply far above demand: this stage tests correctness, not starvation.
    server = QKDServerProcess(refill_rate_bps=20_000_000, max_keys=4096).start()
    try:
        server.wait_for_keys(64)
        summary = run_validation(
            runs=runs,
            kem="ML-KEM-768",
            base_url=server.base_url,
            csv_path=RESULTS_DIR / "handshake_validation.csv",
        )
    finally:
        server.stop()

    print(
        f"  {summary.runs} handshakes: established={summary.all_established} "
        f"keys_match={summary.all_keys_match} transcripts={summary.all_transcripts_verify} "
        f"hybrid={summary.hybrid_sessions} downgraded={summary.downgraded_sessions}"
    )
    if not summary.ok:
        raise SystemExit("handshake validation FAILED; refusing to continue")


def _stage_benchmark(quick: bool) -> None:
    config = load_config("benchmark.yaml")
    if quick:
        config["benchmark"]["runs_per_configuration"] = QUICK["benchmark_runs"]
    run_benchmark(config)


def _stage_sweep(quick: bool) -> None:
    config = load_config("load_sweep.yaml")
    duration = None
    if quick:
        config["sweep"]["handshake_rates_hps"] = QUICK["sweep_rates"]
        config["sweep"]["qkd_supply_bps"] = QUICK["sweep_supplies"]
        duration = QUICK["sweep_duration"]
    run_sweep(config, duration_override=duration)


def _stage_downgrade(quick: bool) -> None:
    config = load_config("load_sweep.yaml")
    duration = None
    if quick:
        config["downgrade_study"]["handshake_rates_hps"] = QUICK["downgrade_rates"]
        duration = QUICK["downgrade_duration"]
    run_downgrade_study(config, duration_override=duration)


def _stage_mitigations(quick: bool) -> None:
    config = load_config("mitigations.yaml")
    duration = None
    if quick:
        config["mitigation_study"]["handshake_rates_hps"] = QUICK["mitigation_rates"]
        duration = QUICK["mitigation_duration"]
    run_mitigation_study(config, duration_override=duration)


def _stage_matrix(quick: bool) -> None:
    path = emit_security_matrix()
    print(f"  wrote {path}")


def _stage_plots(quick: bool) -> None:
    outcomes = make_figures()
    skipped = [name for name, result in outcomes.items() if result.startswith("SKIPPED")]
    if skipped:
        print(
            f"  {len(skipped)} figure(s) skipped for missing inputs: {', '.join(skipped)}\n"
            "  run the stages that produce them, or `python run_all.py`"
        )


STAGE_FUNCTIONS: dict[str, Callable[[bool], None]] = {
    "validate": _stage_validate,
    "benchmark": _stage_benchmark,
    "sweep": _stage_sweep,
    "downgrade": _stage_downgrade,
    "mitigations": _stage_mitigations,
    "matrix": _stage_matrix,
    "plots": _stage_plots,
}


def run(stages: Sequence[str], quick: bool = False) -> int:
    ensure_results_dirs()
    started = time.monotonic()
    timings: list[tuple[str, float]] = []

    for stage in stages:
        print()
        print("=" * 72)
        print(f"== stage: {stage}{'  (quick)' if quick else ''}")
        print("=" * 72, flush=True)
        stage_start = time.monotonic()
        STAGE_FUNCTIONS[stage](quick)
        timings.append((stage, time.monotonic() - stage_start))

    print()
    print("=" * 72)
    print("== done")
    print("=" * 72)
    for stage, elapsed in timings:
        print(f"  {stage:<12}{elapsed:>8.1f}s")
    print(f"  {'total':<12}{time.monotonic() - started:>8.1f}s")
    print(f"\nresults in {RESULTS_DIR}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce every result in results/ from a clean checkout",
        epilog=f"stages: {'|'.join(STAGES)}",
    )
    parser.add_argument(
        "--only",
        type=str,
        default=None,
        help="comma-separated subset of stages to run (default: all, in order)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="short durations and small run counts: proves the pipeline, not the result",
    )
    args = parser.parse_args(argv)

    if args.only:
        requested = [name.strip() for name in args.only.split(",") if name.strip()]
        unknown = [name for name in requested if name not in STAGE_FUNCTIONS]
        if unknown:
            parser.error(f"unknown stage(s): {', '.join(unknown)}; choose from {', '.join(STAGES)}")
        # Keep declared dependency order regardless of the order given.
        stages = [stage for stage in STAGES if stage in requested]
    else:
        stages = list(STAGES)

    return run(stages, quick=args.quick)


if __name__ == "__main__":
    sys.exit(main())
