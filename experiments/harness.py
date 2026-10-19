"""Shared plumbing for the experiments: server processes, sampling, config, CSV.

Every experiment runs the key server as a **separate process** on a free port
and talks to it over HTTP. Nothing here imports `qkd_server` internals, and
no experiment reaches around the QKD client.
"""
from __future__ import annotations

import csv
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence

import yaml

from qkd_client import QKDClient, QKDMode, QKDServerError

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
CONFIGS_DIR = REPO_ROOT / "configs"

#: Every handshake spends exactly one 256-bit QKD key (DECISIONS.md D4), so
#: this is the divisor in the theoretical ceiling supply_bps / KEY_SIZE_BITS.
KEY_SIZE_BITS = 256


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def load_config(name: str) -> dict:
    """Load one of `configs/*.yaml`. No experiment hard-codes parameters."""
    path = name if os.path.isabs(name) else str(CONFIGS_DIR / name)
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def ensure_results_dirs() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)


class QKDServerProcess:
    """A key server in its own process, configured purely by env vars.

    Runs out-of-process so the load generator's CPU work does not contend
    with the server's refill thread for the GIL -- at 100 handshakes/s that
    would distort exactly the measurement we care about.
    """

    def __init__(
        self,
        refill_rate_bps: int,
        max_keys: int = 1024,
        key_size_bits: int = KEY_SIZE_BITS,
        log_path: Optional[str] = None,
        port: Optional[int] = None,
        kme_id: str = "KME-ALICE",
    ) -> None:
        self.refill_rate_bps = refill_rate_bps
        self.max_keys = max_keys
        self.key_size_bits = key_size_bits
        self.port = port or free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.log_path = log_path or str(RESULTS_DIR / "qkd_server.log.jsonl")
        self.kme_id = kme_id
        self._process: Optional[subprocess.Popen] = None

    def start(self, timeout: float = 30.0) -> "QKDServerProcess":
        env = dict(os.environ)
        env.update(
            QKD_HOST="127.0.0.1",
            QKD_PORT=str(self.port),
            QKD_REFILL_RATE_BPS=str(self.refill_rate_bps),
            QKD_MAX_KEYS=str(self.max_keys),
            QKD_KEY_SIZE_BITS=str(self.key_size_bits),
            QKD_KME_ID=self.kme_id,
            QKD_LOG_PATH=self.log_path,
            QKD_LOG_LEVEL="INFO",
            PYTHONPATH=str(REPO_ROOT),
        )
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
        self._process = subprocess.Popen(
            [sys.executable, "-m", "qkd_server.server"],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._wait_ready(timeout)
        return self

    def client(self, sae_id: str = "SAE-BOB", mode: QKDMode = QKDMode.REFERENCE_SILENT) -> QKDClient:
        """A QKD client for this server. Even the harness goes through it."""
        return QKDClient(self.base_url, sae_id, mode, timeout=5.0)

    def _wait_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        with self.client() as client:
            while time.monotonic() < deadline:
                if self._process is not None and self._process.poll() is not None:
                    raise RuntimeError(
                        f"QKD server exited with code {self._process.returncode} during startup"
                    )
                try:
                    client.status()
                    return
                except QKDServerError:
                    pass
                time.sleep(0.05)
        raise TimeoutError(f"QKD server at {self.base_url} did not become ready in {timeout}s")

    def occupancy(self, client: Optional[QKDClient] = None) -> int:
        if client is not None:
            return int(client.status()["stored_key_count"])
        with self.client() as owned:
            return int(owned.status()["stored_key_count"])

    def wait_for_keys(self, minimum: int, timeout: float = 60.0) -> int:
        """Block until the pool holds at least `minimum` keys."""
        deadline = time.monotonic() + timeout
        with self.client() as client:
            while time.monotonic() < deadline:
                depth = self.occupancy(client)
                if depth >= minimum:
                    return depth
                time.sleep(0.05)
        raise TimeoutError(f"pool never reached {minimum} keys within {timeout}s")

    def drain(self) -> int:
        """Bring the pool to a defined empty state, returning keys discarded.

        Without this, keys accumulate while the server process boots and a
        short run can be carried entirely by that startup stock -- making a
        starved configuration look healthy for reasons unrelated to supply
        (DECISIONS.md D12). Batched inside the QKD client so it can outrun
        the refill rate.
        """
        with self.client() as client:
            return client.drain()

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=10)
        self._process = None

    def __enter__(self) -> "QKDServerProcess":
        return self.start() if self._process is None else self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


@dataclass
class PoolSample:
    timestamp: float
    elapsed_s: float
    occupancy: int


class PoolSampler:
    """Polls `/status` on a fixed tick so per-handshake snapshots are free.

    Calling `/status` once per handshake would add HTTP load proportional to
    the handshake rate and distort the measurement (DECISIONS.md D9).
    """

    def __init__(self, server: QKDServerProcess, interval_seconds: float = 0.1) -> None:
        self.server = server
        self.interval_seconds = interval_seconds
        self.samples: list[PoolSample] = []
        self._latest = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time = 0.0

    @property
    def latest(self) -> int:
        """Most recent occupancy reading -- the per-handshake snapshot."""
        return self._latest

    def start(self) -> "PoolSampler":
        self._start_time = time.monotonic()
        self._stop.clear()

        def loop() -> None:
            with self.server.client() as client:
                while not self._stop.is_set():
                    try:
                        depth = self.server.occupancy(client)
                    except QKDServerError:
                        depth = self._latest
                    self._latest = depth
                    self.samples.append(
                        PoolSample(
                            timestamp=time.time(),
                            elapsed_s=time.monotonic() - self._start_time,
                            occupancy=depth,
                        )
                    )
                    self._stop.wait(self.interval_seconds)

        self._thread = threading.Thread(target=loop, name="pool-sampler", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def __enter__(self) -> "PoolSampler":
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


# -- output helpers ----------------------------------------------------------


def write_csv(path: Path | str, fieldnames: Sequence[str], rows: Iterable[dict]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(rows)
    return path


def append_csv(path: Path | str, fieldnames: Sequence[str], rows: Iterable[dict]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with open(path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        if not exists:
            writer.writeheader()
        writer.writerows(rows)
    return path


def write_json(path: Path | str, payload: Any) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def read_csv(path: Path | str) -> list[dict]:
    with open(path, "r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


# -- statistics --------------------------------------------------------------


def percentile(values: Sequence[float], fraction: float) -> float:
    """Linear-interpolated percentile; `fraction` in [0, 1]. Empty -> nan."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = fraction * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


def median(values: Sequence[float]) -> float:
    return percentile(values, 0.5)


def jains_fairness(shares: Sequence[float]) -> float:
    """Jain's fairness index: 1.0 is perfectly equal, 1/n is maximally unfair."""
    if not shares:
        return float("nan")
    total = sum(shares)
    if total == 0:
        return 1.0  # nobody got anything: trivially equal
    sum_of_squares = sum(value * value for value in shares)
    return (total * total) / (len(shares) * sum_of_squares)


def theoretical_max_rate(supply_bps: float, key_size_bits: int = KEY_SIZE_BITS) -> float:
    """Hybrid handshakes per second a given QKD supply can sustain."""
    return supply_bps / key_size_bits


@dataclass
class RateLimiter:
    """Fixed-interval scheduler: fires `rate_hps` times per second.

    Falling behind does not cause a burst; the next slot is computed from the
    ideal schedule so offered load stays honest.
    """

    rate_hps: float
    _start: float = field(default=0.0, init=False)
    _issued: int = field(default=0, init=False)

    def start(self) -> None:
        self._start = time.monotonic()
        self._issued = 0

    def wait_next(self) -> float:
        """Sleep until the next scheduled slot; returns its elapsed offset."""
        target = self._issued / self.rate_hps
        self._issued += 1
        now = time.monotonic() - self._start
        if target > now:
            time.sleep(target - now)
        return target


def iter_progress(label: str, total: int, every: int = 500) -> Iterator[int]:
    """Yield 0..total-1, printing a progress line every `every` items."""
    started = time.monotonic()
    for index in range(total):
        if index and index % every == 0:
            elapsed = time.monotonic() - started
            rate = index / elapsed if elapsed else 0.0
            print(
                f"  {label}: {index}/{total} ({rate:.0f}/s, "
                f"eta {(total - index) / rate:.0f}s)" if rate else f"  {label}: {index}/{total}",
                flush=True,
            )
        yield index
