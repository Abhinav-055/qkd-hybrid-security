# DECISIONS.md

Under-specified design points, the option chosen, and why. Each entry is the
simplest reasonable choice that keeps the research question measurable.

## D1 — HAKE instantiation (signature-free, four messages)

The brief says "use the signature-free four-message HAKE from the 2026
reference paper" but the paper's exact message layout was not supplied. We
instantiate the standard signature-free construction it describes (the
Muckle+ family shape): mutual *implicit* authentication by KEM
encapsulation to long-term public keys held out-of-band (SSH
`known_hosts` style), forward secrecy from a per-handshake ephemeral KEM,
and explicit key confirmation by transcript MAC.

```
I (initiator)                                     R (responder)
  knows pk_R                                        knows pk_I
M1 -->  session_id, nonce_I, suite, epk_I, qkd_key_id
M2 <--  session_id, nonce_R, ct_eph(epk_I), ct_lt_I(pk_I), flags
M3 -->  session_id, ct_lt_R(pk_R), mac_I
M4 <--  session_id, flags, mac_R
```

* `ct_lt_I` authenticates **I** to R (only the owner of sk_I recovers
  `ss_lt_I`); `ct_lt_R` authenticates **R** to I. Both long-term shared
  secrets enter the KDF, so mutual implicit authentication holds.
* `ct_eph` supplies forward secrecy: `epk_I`/its secret key are discarded
  after the handshake.
* No signatures anywhere.

## D2 — Wire format of M1..M4

Compact big-endian binary, not JSON, so `bytes_sent`/`bytes_received` in the
benchmark are realistic rather than base64-inflated.

```
every message:  magic b"QH1" | msg_type u8 | session_id 16B | <fields>
variable field: u32 length prefix || bytes
```

The **MAC is always the final 32 bytes of a message that carries one**, so
"the message minus its MAC field" is exactly `encoded[:-32]`. This is what
makes the transcript definition in D3 unambiguous.

## D3 — Transcript and which hash feeds which key

`transcript = M1 || M2 || M3_body || M4_body`, where `_body` is the encoding
minus the trailing MAC field (D2).

* `th3 = SHA3-256(M1 || M2 || M3_body)` — available to both parties as soon
  as M3 is formed, which is the first moment both hold every KDF input.
  Both confirmation keys are derived from `th3` with role-separated labels.
* `th4 = SHA3-256(M1 || M2 || M3_body || M4_body)` — salts the session key,
  so the session key commits to all four messages.
* `mac_I = HMAC(k_conf_I, M1 || M2 || M3_body)`,
  `mac_R = HMAC(k_conf_R, M1 || M2 || M3_body || M4_body)`.

## D4 — QKD key agreement between the two parties

The initiator pulls a key with ETSI `enc_keys` (consumes pool depth) and
puts only the `key_ID` on the wire in M1. The responder fetches the same
key material with `dec_keys` by id (does **not** consume pool depth). This
mirrors real ETSI 014 usage, and means **one handshake costs exactly one
256-bit QKD key**, which is what makes the theoretical ceiling
`supply_bps / 256` meaningful.

If the initiator holds a QKD key but the responder cannot fetch it (404, or
the responder's own mode/quota blocks it), the responder clears
`qkd_ack` in M2 and the initiator **drops its QKD key too**. Otherwise the
two sides would derive different session keys. The handshake still
completes, downgraded.

## D5 — How REFERENCE_SILENT hides the downgrade

`Session` always records the truth (`security_mode`, `qkd_key_id`,
`downgraded`). What differs by mode is the *public* return of
`handshake()`:

| mode | `HandshakeResult.downgraded` | warning | outcome |
|---|---|---|---|
| `REFERENCE_SILENT` | `None` ("caller cannot tell") | none | success |
| `EXPLICIT_DOWNGRADE` | `True` / `False` | `SecurityDowngradeWarning` | success |
| `STRICT_ERROR` | n/a | none | `QKDUnavailable` raised |

The experiments read `HandshakeResult.internal_session.downgraded`. That
field is the **measurement oracle** — it is deliberately the thing a normal
application does not look at. This is why the silent-downgrade rate is
measurable at all.

## D6 — Shared state names for both roles

The brief fixes one chain: `INIT -> SEND_1 -> WAIT_2 -> SEND_3 -> WAIT_4 ->
CONFIRM -> ESTABLISHED`. We use the same node sequence for the responder,
reading each node as "flight k handled":

| state | initiator | responder |
|---|---|---|
| `SEND_1` | M1 sent | M1 received + validated |
| `WAIT_2` | awaiting M2 | M2 sent |
| `SEND_3` | M3 sent | M3 received + parsed |
| `WAIT_4` | awaiting M4 | `mac_I` verified |
| `CONFIRM` | verifying `mac_R` | M4 sent with `mac_R` |
| `ESTABLISHED` | session key ready | session key ready |

## D7 — HTTP 503 is not retried

The QKD client retries transient 5xx (500/502/504) with backoff, but
treats **503 as pool-exhausted, never as transient**. The key server returns
503 only for `PoolEmpty`, and retrying it would smear the very starvation
signal we are trying to measure.

## D8 — Transport for the handshake itself

Only the QKD client speaks HTTP. The handshake messages are exchanged
in-process (byte strings handed between an `Initiator` and a `Responder`),
because the research question is about QKD key supply, not about network
transport. `bytes_sent`/`bytes_received` are still recorded from the
**initiator's** point of view (`sent = |M1| + |M3|`,
`received = |M2| + |M4|`) so the wire-cost comparison between KEMs is real.

## D9 — Pool occupancy sampling during load

Calling `/status` once per handshake would add HTTP load proportional to the
handshake rate and distort the measurement. Instead each load run starts one
background sampler thread that polls `/status` every
`sampler_interval_seconds` (default 100 ms, matching the server's refill
tick) into `results/pool_occupancy.csv`; per-handshake
`pool_occupancy_snapshot` is the most recent sample.

## D10 — Extra files beyond the required layout

* `experiments/harness.py` — spawns a key-server subprocess on a
  free port, waits for readiness, tears it down. Shared by every experiment
  so no experiment imports `qkd_server` internals.
* `experiments/validation.py` — the 10,000-handshake correctness driver,
  shared by `tests/integration/test_10k_handshakes.py` (slow-marked) and by
  `run_all.py --only validate`, so `results/handshake_validation.csv` is a
  pipeline artifact and not only a test side effect.
* `experiments/security_matrix.py` — projects the prose compromise matrix
  into `results/security_matrix.csv`, so the machine-readable version cannot
  drift from `analysis/security_matrix.md`.
* `experiments/plots.py` also emits `latency_p95_vs_kem.png` beyond the
  required ten figures: tail latency separates the KEMs more clearly than the
  median bars.
* `results/pool_occupancy.csv`, `results/downgrade_summary.csv`,
  `results/starvation_summary.csv`, `results/mitigation_events.csv`,
  `results/benchmark_summary.json`, `results/mitigation_summary.json` —
  inputs for the required figures, and per-configuration aggregates of the
  per-handshake CSVs.

## D11 — KDF label style

`info = b"qkd-hake v1 | <purpose> | <hex transcript hash>"`. Purpose strings
live only in `crypto/kdf.py`; no other module builds a label by hand.

## D12 — The pool is drained to a defined state before every measured run, in batches

Keys accumulate while a server process boots (a few seconds at any
realistic rate), and a short run can be carried entirely by that startup
stock. Measured: a 100 hps run against a 39 hps supply showed a **0%**
downgrade rate purely because the pool had banked ~130 keys during startup.

So `run_load()` drains the pool to empty before the warm-up, and **again
immediately after it** — the warm-up itself leaves whatever stock its own
offered rate happened to allow. With both drains the measured hybrid
throughput converges on `supply_bps / 256` from below (1.00x theoretical,
against 1.23x with a single drain).

The cost is a small transient: the first handshake or two of every run
genuinely starve, so below-ceiling configurations report a downgrade rate
around 0.01 rather than exactly 0. That is a real measurement of a real
(if artificial) empty pool, so it is left in rather than filtered out.

The drain **batches** its requests (`QKDClient.drain()`, up to the KME's
advertised `max_key_per_request`, halving whenever the pool cannot fill a
batch). Draining one key at a time tops out near 400 keys/sec and therefore
cannot empty a pool refilling faster than that — measured against a 1 Mbps
supply it never converged, popping 20,000 keys in 38 s with the pool still
full. Batched, it finishes in about 0.5 s at every supply from 1 kbps to
20 Mbps. The batching lives in the QKD client, since that is the only module
allowed to talk to the server, and is excluded from the client's
`keys_requested`/`starvation_events` counters because it is harness plumbing
rather than handshake demand.

## D13 — Per-second metrics use the true measurement window

`LoadResult.duration_s` is the wall time from the first offer to the **last
completion**, not the configured duration. In-flight handshakes that finish
after the offer loop ends still drew on the QKD supply, so excluding them
inflates every per-second rate. `offered_window_s` records the offer loop's
own duration separately.

`achieved_offer_hps` and `generator_saturated` are reported alongside, so a
configuration where the load generator rather than the QKD supply was the
binding constraint is visible in the CSV instead of silently becoming a
finding.

## D14 — 16 worker threads, not more

The mock KME's synchronous FastAPI endpoints thrash under deep concurrency.
Measured on the development machine, full hybrid handshakes:

| workers | throughput |
|---|---|
| 16 | ~112 hps |
| 48 | ~45 hps |

More threads made the generator *slower*. 16 sits comfortably above the
100 hps top offered rate, so the QKD supply stays the binding constraint
across the whole sweep. The queue depth is also kept shallow
(`worker_threads * 2`): a deep queue would absorb offered load and smear
the moment starvation begins.

## D15 — Admission control keeps its own pool model

The natural implementation — read pool depth, subtract outstanding
reservations — fails its own guarantee under concurrency, because a depth
reading is always slightly stale and keys consumed since that reading are
invisible. Measured: **283** admitted handshakes downgraded anyway.

`AdmissionController` therefore maintains an estimate it debits at
admission time, credits with refill over time, and re-syncs **downwards
only** against observed occupancy (a stale-high reading can never inflate
it). Two further corrections were needed to reach zero violations:

* the safety margin is raised to `keys_per_second * sampler_interval`, the
  most a stale reading can overstate the pool;
* `resync()` is called after the harness drains the pool, because an
  external drain is invisible to the sampler for up to one interval — this
  alone accounted for the last handful of violations, including one at
  10 hps where supply was never the issue.

## D16 — Per-handshake CPU time is reported but not trusted

`time.process_time()` is quantized by the OS scheduler tick (15.625 ms on
Windows), so a ~2 ms ML-KEM handshake reads as 0 or one whole tick. The
per-run `cpu_ms` column is kept because it was specified, but consecutive
deltas sum to the true total, so `cpu_ms_mean` (= total / runs) is exact and
is what the summary JSON and `cpu_vs_kem.png` report. `cpu_ms_median` and
`cpu_ms_p95` are artifacts of the quantization.

## D17 — The benchmark interleaves the two protocols

The host slows measurably under sustained load: within a single 1000-run
configuration, second-half median latency ran up to **1.6x** the first half
(thermal/power throttling on a laptop).

Measuring 1000 hybrid handshakes and then 1000 baseline handshakes therefore
compares two different machines. It produced a **negative cost of
hybridization** — pure-PQC FrodoKEM at 119.8 ms median against hybrid
FrodoKEM at 94.0 ms, i.e. -21.5% — purely because the baseline block ran
last.

The benchmark now interleaves the protocols run by run, alternating which
goes first each iteration, so both see the same conditions and the paired
difference is valid even under drift. Each configuration additionally
reports `latency_drift_ratio` in the summary JSON and in the printed table,
so residual host slowdown is visible rather than silent.

Absolute latencies from this benchmark should be read as indicative only;
the hybrid-minus-baseline delta and the wire sizes are the trustworthy
outputs. Wire sizes are deterministic and immune to all of this.

## D18 — The per-peer quota is fixed, not work-conserving

`mitigations/quota.py` implements a fixed per-peer token bucket: peer *p*
may consume `Q_p` keys per window and no more, even when the pool holds keys
nobody else wants. That is the simplest reading of the brief, and it is what
gets measured.

It has a real cost, and the full-duration run exposed it: at exactly the
39.06 hps ceiling with demand split 4:1:1:1 across four peers, the quota
delivered **26.5** hybrid hps against the unmitigated reference's **38.9** --
32% of the available information-theoretic security destroyed by enforcing
fairness.

The mechanism is that unused allowance cannot be lent. Predicted throughput
is `sum(min(demand_p, quota_p))`, and the stranded remainder is
`sum(max(0, quota_p - demand_p))`:

| offered | predicted | measured |
|---|---|---|
| 39 hps | 26.48 | 26.5 |
| 60 hps | 35.48 | 35.4 |
| 100 hps | 39.06 | 38.8 |

The effect disappears once every peer's demand exceeds its quota, which is
why a short pilot sampling only 10 and 100 hps showed no cost at all. It is
worst at the knee, and it scales with the skew of demand rather than with
overload.

Kept as-is and reported rather than silently replaced with a borrowing
variant: measuring the cost of the obvious implementation is a result, and
the work-conserving quota (borrowing/hierarchical token bucket, or weighted
fair queueing over the pool) is the clearest future work the data points to.
See `analysis/deployment_recommendation.md`.
