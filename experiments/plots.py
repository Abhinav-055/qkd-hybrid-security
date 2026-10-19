"""Figure generation from the result CSVs.

Plain matplotlib with the Agg backend and no seaborn styling, so every
figure renders on a headless CI box. Each figure is generated from a CSV on
disk, never from in-memory experiment state, so `--only plots` works on a
checkout that already has results.

    python -m experiments.plots [--only latency_vs_kem,downgrade_rate]
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable, Optional, Sequence

import matplotlib

matplotlib.use("Agg")  # before pyplot: no display on CI
import matplotlib.pyplot as plt  # noqa: E402

from .harness import (  # noqa: E402
    FIGURES_DIR,
    KEY_SIZE_BITS,
    RESULTS_DIR,
    ensure_results_dirs,
    median,
    percentile,
    read_csv,
    theoretical_max_rate,
)

#: KEMs in increasing cost order, so every per-KEM figure reads left to right.
KEM_ORDER = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "FrodoKEM-976-AES"]
PROTOCOL_LABELS = {"hybrid_hake": "Hybrid HAKE (QKD+PQC)", "pure_pqc": "Pure PQC baseline"}
PROTOCOL_COLORS = {"hybrid_hake": "#1f4e79", "pure_pqc": "#a0a0a0"}

MITIGATION_ORDER = ["reference", "quota", "admission_control", "explicit_downgrade"]
MITIGATION_LABELS = {
    "reference": "Reference\n(silent)",
    "quota": "Per-peer\nquota",
    "admission_control": "Admission\ncontrol",
    "explicit_downgrade": "Explicit\ndowngrade",
}


class MissingInput(FileNotFoundError):
    """A figure's source CSV has not been generated yet."""


def _require(name: str) -> list[dict]:
    path = RESULTS_DIR / name
    if not path.exists():
        raise MissingInput(f"{path} not found; run the experiment that produces it first")
    rows = read_csv(path)
    if not rows:
        raise MissingInput(f"{path} is empty")
    return rows


def _save(figure, name: str) -> Path:
    ensure_results_dirs()
    path = FIGURES_DIR / name
    figure.tight_layout()
    figure.savefig(path, dpi=150)
    plt.close(figure)
    return path


def _kems_present(rows: Sequence[dict]) -> list[str]:
    present = {row["kem"] for row in rows}
    ordered = [kem for kem in KEM_ORDER if kem in present]
    return ordered + sorted(present - set(ordered))


def _grouped_bars(
    rows: Sequence[dict],
    value_fn: Callable[[Sequence[dict]], float],
    ylabel: str,
    title: str,
    name: str,
    annotate: str = "{:.2f}",
) -> Path:
    """One bar group per KEM, one bar per protocol."""
    kems = _kems_present(rows)
    protocols = [p for p in ("hybrid_hake", "pure_pqc") if any(r["protocol"] == p for r in rows)]

    figure, axes = plt.subplots(figsize=(9, 5))
    width = 0.8 / max(len(protocols), 1)
    positions = range(len(kems))

    for index, protocol in enumerate(protocols):
        offsets = [position + index * width - 0.4 + width / 2 for position in positions]
        values = [
            value_fn([r for r in rows if r["kem"] == kem and r["protocol"] == protocol])
            for kem in kems
        ]
        bars = axes.bar(
            offsets,
            values,
            width=width,
            label=PROTOCOL_LABELS.get(protocol, protocol),
            color=PROTOCOL_COLORS.get(protocol),
            edgecolor="black",
            linewidth=0.5,
        )
        for bar, value in zip(bars, values):
            axes.annotate(
                annotate.format(value),
                (bar.get_x() + bar.get_width() / 2, value),
                ha="center",
                va="bottom",
                fontsize=8,
            )

    axes.set_xticks(list(positions))
    axes.set_xticklabels(kems, fontsize=9)
    axes.set_ylabel(ylabel)
    axes.set_title(title)
    axes.legend()
    axes.grid(axis="y", alpha=0.3)
    axes.set_axisbelow(True)
    return _save(figure, name)


# -- benchmark figures --------------------------------------------------------


def latency_vs_kem() -> Path:
    rows = _require("benchmark.csv")

    def value(group: Sequence[dict]) -> float:
        return median([float(r["latency_ms"]) for r in group]) if group else 0.0

    path = _grouped_bars(
        rows,
        value,
        ylabel="Median handshake latency (ms)",
        title="Handshake latency by KEM: hybrid HAKE vs pure-PQC baseline\n"
        "(median of 1000 runs; QKD pool kept far above demand)",
        name="latency_vs_kem.png",
        annotate="{:.2f}",
    )

    # A second panel with P95, since tail latency is what a server operator
    # actually budgets for.
    kems = _kems_present(rows)
    figure, axes = plt.subplots(figsize=(9, 5))
    for protocol in ("hybrid_hake", "pure_pqc"):
        p95 = [
            percentile(
                [float(r["latency_ms"]) for r in rows if r["kem"] == kem and r["protocol"] == protocol],
                0.95,
            )
            for kem in kems
        ]
        axes.plot(
            kems, p95, marker="o", label=f"{PROTOCOL_LABELS[protocol]} P95",
            color=PROTOCOL_COLORS[protocol],
        )
    axes.set_ylabel("P95 handshake latency (ms)")
    axes.set_title("Tail (P95) handshake latency by KEM")
    axes.legend()
    axes.grid(alpha=0.3)
    _save(figure, "latency_p95_vs_kem.png")
    return path


def cpu_vs_kem() -> Path:
    rows = _require("benchmark.csv")

    def value(group: Sequence[dict]) -> float:
        # The mean, not the median: per-run process_time readings are
        # quantized by the OS scheduler tick, but consecutive deltas sum to
        # the true total, so mean = total/runs exactly. See the README.
        cpus = [float(r["cpu_ms"]) for r in group]
        return sum(cpus) / len(cpus) if cpus else 0.0

    return _grouped_bars(
        rows,
        value,
        ylabel="Mean CPU time per handshake (ms)",
        title="CPU cost by KEM: hybrid HAKE vs pure-PQC baseline\n"
        "(mean over 1000 runs; per-run readings are scheduler-tick quantized)",
        name="cpu_vs_kem.png",
        annotate="{:.2f}",
    )


def bytes_vs_kem() -> Path:
    rows = _require("benchmark.csv")

    def value(group: Sequence[dict]) -> float:
        if not group:
            return 0.0
        row = group[0]  # wire size is deterministic per configuration
        return float(row["bytes_sent"]) + float(row["bytes_received"])

    return _grouped_bars(
        rows,
        value,
        ylabel="Total handshake bytes (sent + received)",
        title="Wire cost by KEM: hybrid HAKE vs pure-PQC baseline\n"
        "(the hybrid delta is the 36-byte QKD key id in M1)",
        name="bytes_vs_kem.png",
        annotate="{:.0f}",
    )


# -- sweep figures ------------------------------------------------------------


def qkd_pool_occupancy() -> Path:
    """Pool depth over time, one line per (supply, rate) configuration."""
    rows = _require("pool_occupancy.csv")
    supplies = sorted({int(row["qkd_supply_bps"]) for row in rows})

    figure, axes_list = plt.subplots(
        len(supplies), 1, figsize=(10, 3.2 * len(supplies)), squeeze=False, sharex=True
    )
    for index, supply in enumerate(supplies):
        axes = axes_list[index][0]
        supply_rows = [row for row in rows if int(row["qkd_supply_bps"]) == supply]
        for rate in sorted({float(row["handshake_rate"]) for row in supply_rows}):
            series = [row for row in supply_rows if float(row["handshake_rate"]) == rate]
            series.sort(key=lambda row: float(row["elapsed_s"]))
            axes.plot(
                [float(row["elapsed_s"]) for row in series],
                [int(row["occupancy"]) for row in series],
                linewidth=1.0,
                label=f"{rate:g} hps",
            )
        ceiling = theoretical_max_rate(supply)
        axes.set_ylabel("Keys in pool")
        axes.set_title(
            f"QKD pool occupancy at {supply} bps supply "
            f"({ceiling:.1f} hybrid handshakes/sec ceiling)",
            fontsize=10,
        )
        axes.grid(alpha=0.3)
        axes.legend(fontsize=7, ncol=3, title="offered load")
    axes_list[-1][0].set_xlabel("Time within run (s)")
    return _save(figure, "qkd_pool_occupancy.png")


def starvation_rate() -> Path:
    rows = _require("starvation_summary.csv")
    supplies = sorted({int(row["qkd_supply_bps"]) for row in rows})

    figure, axes = plt.subplots(figsize=(9, 5.5))
    for supply in supplies:
        series = sorted(
            (row for row in rows if int(row["qkd_supply_bps"]) == supply),
            key=lambda row: float(row["handshake_rate"]),
        )
        axes.plot(
            [float(row["handshake_rate"]) for row in series],
            [float(row["starvation_rate"]) for row in series],
            marker="o",
            label=f"{supply} bps ({theoretical_max_rate(supply):.1f} hps ceiling)",
        )
    axes.set_xscale("log")
    axes.set_xlabel("Offered handshake rate (handshakes/sec, log scale)")
    axes.set_ylabel("Fraction of handshakes that hit an empty pool")
    axes.set_ylim(-0.05, 1.05)
    axes.set_title("QKD starvation rate vs offered load, by supply")
    axes.legend(title="QKD supply")
    axes.grid(alpha=0.3)
    return _save(figure, "starvation_rate.png")


def downgrade_rate() -> Path:
    """The headline figure: silent downgrade vs load, and what the app is told."""
    rows = _require("downgrade_summary.csv")
    series = sorted(rows, key=lambda row: float(row["handshake_rate"]))
    rates = [float(row["handshake_rate"]) for row in series]
    supply = int(series[0]["qkd_supply_bps"])
    ceiling = theoretical_max_rate(supply)

    figure, axes = plt.subplots(figsize=(9.5, 5.5))
    axes.plot(
        rates,
        [float(row["downgrade_rate"]) for row in series],
        marker="o",
        color="#b00020",
        label="Actually downgraded (PQC-only successes / all successes)",
    )
    axes.plot(
        rates,
        [float(row["app_visible_downgrade_rate"]) for row in series],
        marker="s",
        linestyle="--",
        color="#1f4e79",
        label="Reported to the application",
    )
    axes.axvline(
        ceiling,
        color="black",
        linestyle=":",
        label=f"Theoretical ceiling supply/{KEY_SIZE_BITS} = {ceiling:.1f} hps",
    )
    axes.set_xlabel("Offered handshake rate (handshakes/sec)")
    axes.set_ylabel("Fraction of successful handshakes")
    axes.set_ylim(-0.05, 1.05)
    axes.set_title(
        f"Silent security downgrade under REFERENCE_SILENT at {supply} bps QKD supply\n"
        "Every handshake succeeds; above the ceiling most are no longer hybrid, "
        "and none of it is reported"
    )
    axes.legend(fontsize=9, loc="upper left")
    axes.grid(alpha=0.3)
    return _save(figure, "downgrade_rate.png")


def throughput_knee() -> Path:
    """Measured hybrid throughput against the theoretical supply/256 line."""
    rows = _require("downgrade_summary.csv")
    series = sorted(rows, key=lambda row: float(row["handshake_rate"]))
    rates = [float(row["handshake_rate"]) for row in series]
    supply = int(series[0]["qkd_supply_bps"])
    ceiling = theoretical_max_rate(supply)

    figure, axes = plt.subplots(figsize=(9.5, 5.5))
    axes.plot(
        rates,
        [float(row["throughput_hps"]) for row in series],
        marker="o",
        color="#1f4e79",
        label="Total completed handshakes/sec",
    )
    axes.plot(
        rates,
        [float(row["hybrid_throughput_hps"]) for row in series],
        marker="s",
        color="#b00020",
        label="Hybrid (QKD-backed) handshakes/sec",
    )
    axes.plot(rates, rates, linestyle="-.", color="#808080", label="Offered load (y = x)")
    axes.axhline(
        ceiling,
        color="black",
        linestyle=":",
        linewidth=1.6,
        label=f"Theoretical ceiling supply/{KEY_SIZE_BITS} = {ceiling:.2f} hps",
    )

    # Mark the knee: the last offered rate still essentially fully hybrid.
    below = [row for row in series if float(row["downgrade_rate"]) < 0.05]
    if below:
        knee_rate = float(below[-1]["handshake_rate"])
        axes.axvline(knee_rate, color="green", linestyle="--", alpha=0.6)
        axes.annotate(
            f"knee ≈ {knee_rate:g} hps",
            (knee_rate, ceiling * 0.55),
            xytext=(knee_rate * 1.08, ceiling * 0.35),
            fontsize=9,
            color="green",
            arrowprops={"arrowstyle": "->", "color": "green"},
        )

    axes.set_xlabel("Offered handshake rate (handshakes/sec)")
    axes.set_ylabel("Achieved throughput (handshakes/sec)")
    axes.set_title(
        f"Throughput knee at {supply} bps QKD supply\n"
        "Total throughput scales with offered load; hybrid throughput saturates "
        f"at supply/{KEY_SIZE_BITS}"
    )
    axes.legend(fontsize=9, loc="upper left")
    axes.grid(alpha=0.3)
    return _save(figure, "throughput_knee.png")


# -- mitigation figures -------------------------------------------------------


def _mitigation_rows() -> list[dict]:
    return _require("mitigation_results.csv")


def _mitigation_panel(
    configurations: Sequence[str],
    metrics: Sequence[tuple[str, str, str]],
    title: str,
    name: str,
) -> Path:
    """One subplot per metric; grouped bars over load levels per configuration."""
    rows = [row for row in _mitigation_rows() if row["configuration"] in configurations]
    if not rows:
        raise MissingInput(f"mitigation_results.csv has no rows for {configurations}")
    rates = sorted({float(row["handshake_rate"]) for row in rows})
    present = [name_ for name_ in MITIGATION_ORDER if name_ in {r["configuration"] for r in rows}]

    figure, axes_list = plt.subplots(1, len(metrics), figsize=(5.2 * len(metrics), 5), squeeze=False)
    width = 0.8 / max(len(present), 1)

    for index, (column, ylabel, subtitle) in enumerate(metrics):
        axes = axes_list[0][index]
        for config_index, configuration in enumerate(present):
            values = []
            for rate in rates:
                match = [
                    row
                    for row in rows
                    if row["configuration"] == configuration
                    and float(row["handshake_rate"]) == rate
                ]
                values.append(float(match[0][column]) if match else 0.0)
            offsets = [
                position + config_index * width - 0.4 + width / 2
                for position in range(len(rates))
            ]
            axes.bar(
                offsets,
                values,
                width=width,
                label=MITIGATION_LABELS.get(configuration, configuration).replace("\n", " "),
                edgecolor="black",
                linewidth=0.5,
            )
        axes.set_xticks(list(range(len(rates))))
        axes.set_xticklabels([f"{rate:g}" for rate in rates])
        axes.set_xlabel("Offered handshake rate (hps)")
        axes.set_ylabel(ylabel)
        axes.set_title(subtitle, fontsize=10)
        axes.grid(axis="y", alpha=0.3)
        axes.set_axisbelow(True)
        if index == 0:
            axes.legend(fontsize=8)

    figure.suptitle(title, fontsize=12)
    return _save(figure, name)


def quota_comparison() -> Path:
    return _mitigation_panel(
        ["reference", "quota"],
        [
            ("fairness_jain", "Jain's fairness index", "Fairness across peers (1.0 = equal)"),
            ("greedy_peer_hybrid_share", "Share of hybrid sessions",
             "Greedy peer's capture of hybrid sessions"),
            ("hybrid_throughput_hps", "Hybrid handshakes/sec",
             "Aggregate hybrid throughput (unchanged)"),
        ],
        title="Per-peer quota: fairness without changing the aggregate ceiling",
        name="quota_comparison.png",
    )


def admission_control_comparison() -> Path:
    return _mitigation_panel(
        ["reference", "admission_control"],
        [
            ("silent_downgrade_rate", "Fraction of successes",
             "Silent downgrade rate (goal: zero)"),
            ("rejection_rate", "Fraction of offers", "Rejection rate (the price paid)"),
            ("latency_ms_p95", "P95 latency (ms)", "Tail latency of completed handshakes"),
        ],
        title="Admission control: silent downgrades traded for visible rejections",
        name="admission_control_comparison.png",
    )


def downgrade_signal_comparison() -> Path:
    return _mitigation_panel(
        ["reference", "explicit_downgrade"],
        [
            ("silent_downgrade_rate", "Fraction of successes", "Silent (unreported) downgrades"),
            ("signalled_downgrade_rate", "Fraction of successes", "Reported downgrades"),
            ("throughput_hps", "Handshakes/sec", "Throughput (identical: signalling is free)"),
        ],
        title="Explicit downgrade signalling: same cryptography, no longer silent",
        name="downgrade_signal_comparison.png",
    )


# -- registry -----------------------------------------------------------------

FIGURES: dict[str, Callable[[], Path]] = {
    "latency_vs_kem": latency_vs_kem,
    "cpu_vs_kem": cpu_vs_kem,
    "bytes_vs_kem": bytes_vs_kem,
    "qkd_pool_occupancy": qkd_pool_occupancy,
    "starvation_rate": starvation_rate,
    "downgrade_rate": downgrade_rate,
    "throughput_knee": throughput_knee,
    "quota_comparison": quota_comparison,
    "admission_control_comparison": admission_control_comparison,
    "downgrade_signal_comparison": downgrade_signal_comparison,
}


def make_figures(only: Optional[Sequence[str]] = None, strict: bool = False) -> dict[str, str]:
    """Generate figures, reporting which inputs were missing rather than dying."""
    names = list(only) if only else list(FIGURES)
    outcomes: dict[str, str] = {}
    for name in names:
        builder = FIGURES.get(name)
        if builder is None:
            raise KeyError(f"unknown figure {name!r}; known: {', '.join(FIGURES)}")
        try:
            path = builder()
        except MissingInput as exc:
            if strict:
                raise
            outcomes[name] = f"SKIPPED ({exc})"
            print(f"  skipped {name}: {exc}")
        else:
            outcomes[name] = str(path)
            print(f"  wrote {path}")
    return outcomes


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate figures from result CSVs")
    parser.add_argument("--only", type=str, default=None, help="comma-separated figure names")
    parser.add_argument(
        "--strict", action="store_true", help="fail instead of skipping missing inputs"
    )
    args = parser.parse_args(argv)

    only = [name.strip() for name in args.only.split(",")] if args.only else None
    outcomes = make_figures(only, strict=args.strict)
    skipped = [name for name, result in outcomes.items() if result.startswith("SKIPPED")]
    print(f"{len(outcomes) - len(skipped)}/{len(outcomes)} figures written")
    return 1 if skipped and args.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
