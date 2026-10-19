# QKD-HAKE research testbed

A testbed for one question:

> When a finite QKD key supply becomes insufficient for the handshake
> demand, where is the throughput ceiling, what happens to security, and can
> quotas, admission control, or explicit downgrade signalling prevent the
> problem?

The short answers this testbed produces:

* **The ceiling is `supply_bps / 256`**, because one handshake spends
  exactly one 256-bit QKD key. At a 10 kbps supply that is 39.06 hybrid
  handshakes/sec, and the measured hybrid throughput saturates on that line
  to within measurement error.
* **Above the ceiling, nothing fails.** Total throughput keeps tracking
  offered load. What degrades is the *security mode*: at 100 handshakes/sec
  against 10 kbps, 61% of successful handshakes are no longer hybrid — they
  rest on the KEM alone — and by default the application is told about none
  of them (`app_visible_downgrade_rate = 0.000`).
* **All three mitigations help, none creates key material.** Quota makes
  the shortage fair (Jain's index 0.64 → 1.00), admission control makes it
  loud (silent downgrades 0.61 → 0.000, at the price of a 0.60 rejection
  rate), explicit signalling makes it visible (the same cryptography, but
  the caller is told).

The protocol itself is not novel: it is the signature-free four-message
KEM-authenticated HAKE described in `DECISIONS.md` D1. The contribution here
is the finite-supply measurement and the mitigation analysis.

## Where to start

| document | what it is for |
|---|---|
| **`OBJECTIVES.md`** | Each project objective, what was built to meet it, and the evidence |
| **`RESULTS.md`** | Every measurement, in full, with the caveats that apply to each |
| **`ARCHITECTURE.md`** | How the code is put together and why; the protocol spec and key schedule |
| `analysis/deployment_recommendation.md` | The practical answer: should you deploy this, and where |
| `analysis/security_matrix.md` | Four-cell compromise matrix, in prose |
| `analysis/game_hops.md` | CK01-style game-hop outline |
| `DECISIONS.md` | Every under-specified choice, the option taken, and why |

The rest of this file is install, reproduction and a guide to reading the
figures.

---

## Install

```bash
pip install -r requirements.txt
```

### The liboqs system dependency

`liboqs-python` is a thin `ctypes` binding; it needs the native **liboqs**
shared library. On first import it will try to download, build and install
liboqs into `~/_oqs` automatically, which requires a **C compiler, CMake and
Ninja** on `PATH`. That first import takes several minutes and prints build
output; later imports are instant.

If you would rather install liboqs yourself (or the auto-build fails):

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel
cmake --install liboqs/build          # or set OQS_INSTALL_PATH to a prefix
```

Verify the four KEMs this study needs are enabled:

```bash
python -c "import oqs; print([m for m in oqs.get_enabled_kem_mechanisms() if 'ML-KEM' in m or 'Frodo' in m])"
```

`ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` and `FrodoKEM-976-AES` must all
appear; `tests/crypto/test_kem.py::test_all_four_study_kems_are_available`
fails loudly if they do not.

## One-command reproduction

```bash
python run_all.py
```

That regenerates every CSV in `results/` and every figure in
`results/figures/` from scratch. Individual stages:

```bash
python run_all.py --only benchmark
python run_all.py --only sweep,downgrade
python run_all.py --only plots          # re-draw from existing CSVs
python run_all.py --quick               # ~5 min pipeline smoke test
```

Stages run in dependency order regardless of the order you list them.
Each stage starts and stops its own key-server processes on free
ports, so nothing needs to be running first. Every parameter lives in
`configs/*.yaml`; `run_all.py` contains no experiment constants beyond the
`--quick` overrides.

### Expected runtime

Measured wall times from the reference run on a Windows 11 laptop:

| stage | wall time | what dominates |
|---|---|---|
| `validate` | 131 s | 10,000 handshakes |
| `benchmark` | 196 s | 8,000 handshakes; FrodoKEM ~70 ms each |
| `sweep` | 1194 s | 18 configurations × 60 s |
| `downgrade` | 340 s | 9 load levels × 30 s |
| `mitigations` | 590 s | 16 configurations × 30 s |
| `matrix` + `plots` | 5 s | |
| **total** | **2498 s (41.6 min)** | |

`--quick` does the same stages in about 5 minutes with short durations and
small run counts. Use it to check the pipeline, never to draw a conclusion:
the durations are too short for the pool to reach steady state at every
rate.

### Tests

```bash
pytest                      # 204 tests, ~56 s; the slow validation deselected
pytest -m slow              # the 10,000-handshake validation, ~118 s
pytest tests/crypto -v      # KATs and label separation
```

If a run hangs for minutes with no output, a server subprocess from an
earlier interrupted run is probably still holding a port; kill stray
`python` processes and re-run.

---

## Directory guide

| path | what it is |
|---|---|
| `qkd_server/` | Mock ETSI GS QKD 014 key management server: key pool, refill loop, the three endpoints. |
| `qkd_client/client.py` | The only module that speaks to the key server. Three operating modes. |
| `crypto/kem.py` | liboqs wrapper; long-term and ephemeral KEM roles. |
| `crypto/kdf.py` | HKDF-SHA3-256; every protocol label is built here and nowhere else. |
| `crypto/mac.py` | HMAC-SHA3-256 transcript MAC, constant-time verify. |
| `protocol/messages.py` | Binary wire format for M1..M4. |
| `protocol/state_machine.py` | `INIT → SEND_1 → WAIT_2 → SEND_3 → WAIT_4 → CONFIRM → ESTABLISHED`. |
| `protocol/initiator.py`, `responder.py` | The two roles. |
| `protocol/session.py` | `Session` (the truth) vs `HandshakeResult` (what the app sees). |
| `baseline/pure_pqc.py` | Same protocol with no QKD, for the cost-of-hybridization number. |
| `mitigations/` | Per-peer quota, admission control, downgrade signalling. |
| `experiments/` | Benchmark, load generator, the two studies, plots. |
| `analysis/` | Compromise matrix, game-hop outline, deployment recommendation. |
| `OBJECTIVES.md`, `RESULTS.md`, `ARCHITECTURE.md` | Objectives met, full measurements, and design. |
| `configs/*.yaml` | Every experiment parameter. |
| `results/` | Generated CSVs and figures. Safe to delete; `run_all.py` rebuilds it. |
| `DECISIONS.md` | Every under-specified design point, the choice made, and why. |

Three files extend the planned layout, for reasons recorded in
`DECISIONS.md` D10: `experiments/harness.py` (server processes, sampling,
CSV/stats helpers), `experiments/validation.py` (the 10,000-handshake driver,
shared by the slow test and the pipeline), and
`experiments/security_matrix.py` (projects the prose matrix into CSV).

---

## How to read the results

### Start here: `results/figures/throughput_knee.png`

The headline figure. Three lines matter:

* **Total completed handshakes/sec** follows the offered-load diagonal all
  the way to 100 hps. From a throughput monitor, nothing is wrong.
* **Hybrid (QKD-backed) handshakes/sec** tracks that diagonal only up to the
  knee, then goes flat.
* **The dotted horizontal line** is the theoretical ceiling
  `supply_bps / 256`. The hybrid line saturates on it.

The green marker is the detected knee — the highest offered rate whose
silent-downgrade rate is still under 5% (`knee_downgrade_threshold` in
`configs/load_sweep.yaml`). It lands at 39 hps against a theoretical 39.06:
the ceiling is not an artifact of the implementation, it is arithmetic.

### `results/figures/downgrade_rate.png` — the security consequence

Two curves against offered load: the fraction of successful handshakes that
*actually* lost their QKD contribution, and the fraction the application was
*told* about. Under the default `REFERENCE_SILENT` mode the second curve sits
on zero at every load level while the first climbs past 60%. That gap is the
phenomenon this project exists to measure.

### `results/figures/qkd_pool_occupancy.png` — the mechanism

Pool depth over time, one panel per supply. Below the ceiling the pool
accumulates (and clips at `max_keys`). Above it, the pool sits pinned at
zero for the whole run: every handshake arrives to find an empty pool,
requests a key, is refused with HTTP 503, and continues anyway.

### `results/figures/starvation_rate.png` — the 6 × 3 sweep

Fraction of handshakes that hit an empty pool, for each of the three
supplies across all six rates. The three curves are the same curve shifted:
starvation begins wherever offered load crosses that supply's own
`supply/256`.

### Cost of hybridization: `latency_vs_kem`, `cpu_vs_kem`, `bytes_vs_kem`

Hybrid HAKE against the pure-PQC baseline, per KEM, with a fully stocked
pool so no run is downgraded. The latency delta is dominated by the two
extra HTTP round trips to the KME (`enc_keys` for the initiator, `dec_keys`
for the responder), not by cryptography: it is roughly constant in absolute
terms, so it looks large next to ML-KEM-512 and small next to
FrodoKEM-976-AES. The wire delta is a flat **+36 bytes** — the QKD key id in
M1 — because key material itself never travels on the handshake wire.

**Read the delta, not the absolute latencies.** This host slows under
sustained load — up to 1.6× within a single 1000-run configuration — so
absolute milliseconds are not comparable across configurations, and
`benchmark_summary.json` reports a `latency_drift_ratio` per configuration
(second-half median ÷ first-half median) to make that visible. The two
protocols are therefore **interleaved run by run**, with the order
alternating each iteration, so both experience identical conditions and the
paired hybrid-minus-baseline difference survives the drift. This matters:
measuring them block-sequentially put pure-PQC FrodoKEM 25 ms *slower* than
hybrid FrodoKEM — a negative cost of hybridization, purely because the
baseline block ran last. If you see a negative overhead in your own run,
the host was throttling, not the protocol getting cheaper.

`latency_p95_vs_kem.png` is generated alongside these as an extra panel:
tail latency is what a server operator actually budgets for, and the P95
line separates the KEMs more cleanly than the median bars do.

**A caveat on the CPU figure.** `latency_ms` and `bytes_*` are exact per
run, but per-run `cpu_ms` from `time.process_time()` is quantized by the OS
scheduler tick (15.625 ms on Windows), so individual readings are 0 or one
tick. Consecutive deltas still sum to the true total, so the *mean* over
1000 runs is exact — that is what `cpu_vs_kem.png` and
`benchmark_summary.json`'s `cpu_ms_mean` report. Ignore `cpu_ms_median` and
`cpu_ms_p95`; they are artifacts of the quantization, and are kept only
because the per-run column was specified.

### Mitigations: the three `*_comparison.png` figures

Each puts one mitigation next to the reference configuration, with the same
supply, the same load levels, and four simulated peers of which `peer-0`
offers 4× an equal share.

* **`quota_comparison.png`** — fairness rises to 1.00 and the greedy peer's
  capture of hybrid sessions falls from 0.58 to 0.24 (an equal share of four
  peers is 0.25), while aggregate hybrid throughput is unchanged. A quota
  redistributes the shortage; it cannot end it.
* **`admission_control_comparison.png`** — silent downgrades go to exactly
  zero and QKD utilization stays high, paid for with a ~0.60 rejection rate
  at 100 hps. The failure becomes an error the caller must handle.
* **`downgrade_signal_comparison.png`** — silent downgrades go to zero and
  *signalled* downgrades take their place at the same rate; throughput is
  identical to the reference. Signalling costs nothing and fixes nothing; it
  only makes the risk known.

### The CSVs

| file | grain | notes |
|---|---|---|
| `benchmark.csv` | one row per run | `protocol,kem,run_id,latency_ms,cpu_ms,bytes_sent,bytes_received,success` |
| `benchmark_summary.json` | per configuration | median, P95, `cpu_ms_mean`, and `cost_of_hybridization` |
| `handshake_validation.csv` | one row per run | the 10,000-handshake correctness log |
| `starvation_sweep.csv` | one row per handshake | the 6 × 3 sweep, with `pool_occupancy_snapshot` |
| `starvation_summary.csv` | one row per configuration | aggregates for the figures |
| `pool_occupancy.csv` | one sample per 100 ms | continuous pool depth |
| `downgrade_events.csv` | one row per handshake | the headline experiment's events |
| `downgrade_summary.csv` | one row per load level | includes `downgrade_rate` |
| `mitigation_results.csv` | one row per (configuration, rate) | throughput, rejection, silent/signalled downgrade, P95, utilization, fairness |
| `mitigation_events.csv` | one row per handshake | the raw mitigation events |
| `security_matrix.csv` | one row per cell | machine-readable `analysis/security_matrix.md` |
| `qkd_server.log.jsonl` | one line per key event | the key server's own log |

Two columns deserve attention when reading any sweep CSV:

* **`downgraded` vs `app_visible_downgrade`** — the first is ground truth,
  read from `Session`; the second is what the application was actually told.
  Their difference *is* the result. See `DECISIONS.md` D5.
* **`generator_saturated`** — offers the load generator could not attempt
  because its own worker pool was full. It is 0 in the published
  configurations (16 workers sustain ~112 hps against a 100 hps top rate),
  and it is reported so that a configuration where the *generator* rather
  than the QKD supply was the limit cannot be mistaken for a finding.

### The analysis documents

* **`analysis/security_matrix.md`** — the four-cell QKD ✓/✗ × KEM ✓/✗
  compromise matrix in prose. The load experiments populate Cell C.
* **`analysis/game_hops.md`** — a CK01-style game-hop outline (not a proof).
  Its punchline: hop G5, the one that consumes the QKD key's uniformity,
  becomes vacuous when the pool is empty, so the security statement
  collapses from a disjunction to its computational branch alone.

---

## Measurement decisions worth knowing about

These were found by running the experiments and are recorded here because
they change how the numbers should be read.

1. **The pool is drained to empty before every measured run**, and again
   after warm-up. Keys accumulate while a server process boots, and without
   draining, a short run can be carried entirely by that startup stock —
   which made a starved configuration look healthy for reasons unrelated to
   supply. A side effect: the first handshake or two of every run genuinely
   starve, which is why below-ceiling rows show a downgrade rate of ~0.01
   rather than exactly 0.
2. **Per-second metrics are normalized by the true measurement window**
   (first offer to last completion), not the configured duration, so
   in-flight handshakes that drew on the supply after the offer loop ended
   cannot inflate a throughput number.
3. **Worker count is 16, not 32.** The mock KME's synchronous endpoints
   thrash under deeper concurrency: measured on this machine, 16 workers
   sustain ~112 hybrid handshakes/sec while 48 collapse to ~45. More threads
   made the generator slower.
4. **The handshake itself runs in-process.** Only the QKD client does
   network I/O (`DECISIONS.md` D8). Wire sizes are still recorded from the
   initiator's point of view, so the KEM comparison is real; handshake
   *transport* latency is not modelled.

## Known limitations

* **No real QKD.** The key server models key *supply* and nothing about QKD
  physics; `ε_QKD` is a black-box parameter in the analysis.
* **The KME does not authenticate SAEs** (`# TODO(auth)` in
  `qkd_server/server.py`), so any caller can fetch any `key_ID` via
  `dec_keys`. The residual authentication attributed to the QKD key in
  matrix Cell B therefore is not demonstrated by this testbed, only argued.
* **No TLS, no TLS integration, no formal proof** — all explicit non-goals.
* **`EphemeralKEM.forget()` documents intent, not erasure.** Python offers
  no guarantee that secret key bytes leave memory, so the forward-secrecy
  claim is about the protocol, not about this process's memory hygiene.
* **Single-host measurement.** Client, server and both handshake roles share
  one machine, so absolute latencies include no network path and the
  generator competes with the server for CPU.

### Follow-up notes on the key server

The key server implements the ETSI GS QKD 014 surface and nothing beyond it.
Two additions would have simplified the rest of the testbed, but both sit
outside that standard, so they are recorded here as future work rather than
built:

1. **A set-occupancy test hook.** Every experiment brings the pool to a
   defined empty state by consuming its contents (`QKDClient.drain()`). Doing
   that one key at a time tops out near 400 keys/sec, which **cannot empty a
   pool that refills faster than that** — it spins indefinitely. The
   workaround is to batch via the standard `number` parameter (up to the
   advertised `max_key_per_request`, halving whenever the pool cannot fill a
   batch), which converges in about 0.5 s even against a 20 Mbps supply. A
   `QKD_INITIAL_KEYS` env var, or an admin endpoint that sets pool depth
   directly, would make the setup exact rather than merely fast.
2. **A pool-depth field on the key response.** Reading occupancy currently
   needs a separate `/status` call, which is why the experiments run a
   background sampler and accept a 100 ms staleness — and that staleness is
   exactly what forced admission control to carry its own pool model and a
   `resync()` call. Returning `stored_key_count` alongside granted keys would
   let a client track depth exactly, with no extra requests.

Neither is an ETSI GS QKD 014 feature, so both would have to be clearly
marked as testbed extensions outside the standard surface.
