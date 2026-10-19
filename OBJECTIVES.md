# Objectives and how each was met

This document answers the project brief point by point: what was asked, what
was built, where it lives, and what evidence backs it. Numbers here are
summarised; `RESULTS.md` carries the full measurement tables and
`ARCHITECTURE.md` the design.

Test counts refer to `pytest` on this tree: **204 passing**, plus one
slow-marked test (the 10,000-handshake validation) that passes in 118 s.

---

## Primary objective 1 — ETSI GS QKD 014 mock server

> Build a small ETSI GS QKD 014 mock server: an in-memory key pool with a
> configurable refill rate and depth, exposing GetKey and GetKeyWithIDs so
> both sides can pull the same key by ID.


| Requirement | Where |
|---|---|
| In-memory key pool | `qkd_server/key_pool.py` — thread-safe `deque` plus an id index so consumed keys remain retrievable |
| Configurable refill rate | `pool.refill_rate_bps`, with fractional bit-credit carry so low rates still refill |
| Configurable depth | `pool.max_keys`; excess key material at the cap is discarded and logged |
| GetKey | `POST /api/v1/keys/{slave_SAE_ID}/enc_keys` — consumes pool depth, all-or-nothing on a batch |
| GetKeyWithIDs | `POST /api/v1/keys/{master_SAE_ID}/dec_keys` — retrieves by `key_ID`, does **not** consume depth |
| Both sides pull the same key by ID | Initiator calls `enc_keys` and puts only the `key_ID` in M1; responder calls `dec_keys` with that id. Verified end to end by `test_get_key_by_id_matches_initiator_material` and by 10,000 hybrid handshakes agreeing on `qkd_key_id` |
| Starvation behaviour | Empty pool raises `PoolEmpty` → HTTP 503, unchanged |

Configuration is YAML plus environment overrides (`qkd_server/config.py`),
which is what lets the load harness spawn 40+ differently-configured server
processes across a run. 22 tests.

## Primary objective 2 — Design and specify the signature-free HAKE

> Design and specify a signature-free HAKE that mixes a long-term KEM for
> authentication, an ephemeral KEM for forward secrecy, and a QKD key, all
> through a labelled HKDF-SHA3-256 chain and confirmed with a MAC over the
> transcript.

**Met.** Specified in `DECISIONS.md` D1–D3 and `ARCHITECTURE.md`; implemented
in `protocol/`.

```
I (initiator)                                        R (responder)
  holds sk_I, knows pk_R                      holds sk_R, knows pk_I
M1 -->  session_id, nonce_I, suite, epk_I, qkd_key_id
M2 <--  session_id, nonce_R, ct_eph(epk_I), ct_lt_I(pk_I), flags
M3 -->  session_id, ct_lt_R(pk_R), mac_I
M4 <--  session_id, flags, mac_R
```

* **No signatures anywhere.** Authentication is implicit and mutual:
  `ct_lt_I` is encapsulated to the initiator's long-term key and `ct_lt_R` to
  the responder's, so each side's shared secret is recoverable only by the
  genuine key holder. Verified by `test_an_impostor_long_term_key_cannot_complete`.
* **Ephemeral KEM for forward secrecy:** a fresh keypair per handshake,
  discarded via `EphemeralKEM.forget()`.
* **Labelled HKDF-SHA3-256 chain:** every label is built in `crypto/kdf.py`
  and nowhere else, shaped `qkd-hake v1 | <purpose> | <hex transcript hash>`,
  with role separation between the two confirmation keys.

```
ikm         = ss_lt_I || ss_lt_R || ss_eph || (qkd_key or b"")
th3         = SHA3-256(M1 || M2 || M3_body)
th4         = SHA3-256(M1 || M2 || M3_body || M4_body)
k_conf_*    = HKDF(ikm, salt=th3, info="... | confirmation-key | <role> | th3")
session_key = HKDF(ikm, salt=th4, info="... | session-key | th4")
```

* **MAC over the transcript:** HMAC-SHA3-256 over M1..M4 with each message's
  own MAC field removed. Constant-time verify. Tampering with any of the four
  messages causes MAC failure — one test per message.

The state machine is the brief's own chain,
`INIT → SEND_1 → WAIT_2 → SEND_3 → WAIT_4 → CONFIRM → ESTABLISHED`, with
`FAILED` reachable from anywhere and terminal, shared by both roles
(`DECISIONS.md` D6). 57 protocol tests + 27 crypto-layer tests.

## Primary objective 3 — Implement, baseline, benchmark

> Implement it, build a pure-PQC baseline for comparison, and benchmark both
> across ML-KEM-512/768/1024 and FrodoKEM-976-AES for latency, CPU time and
> bytes on the wire. Report median and 95th percentile over 1000 runs.

**Met.** `baseline/pure_pqc.py` reuses the same state machine, wire format
and crypto layer with no QKD client, so the only difference is the absent
KDF contribution — and it structurally refuses a QKD client if one is
passed, so it cannot be hybridised by accident.

`experiments/benchmark.py` runs **1000 handshakes per configuration, 8000
total**, all four KEMs × both protocols, with the pool held far above demand
so no run is downgraded (a downgraded run aborts the benchmark rather than
being silently averaged in). Reports median, P95, mean CPU and wire bytes;
`results/benchmark.csv` + `results/benchmark_summary.json`.

Headline: the cost of hybridisation is **+5.9 to +11.0 ms and a flat
+36 bytes**, positive for all four KEMs. Full table in `RESULTS.md`.

Two measurement caveats, both documented rather than hidden:

* Per-run `cpu_ms` from `time.process_time()` is quantised by the OS
  scheduler tick (15.625 ms), so the summary reports `cpu_ms_mean`, which is
  exact because consecutive deltas sum to the true total (`DECISIONS.md` D16).
* The host slows under sustained load, so the two protocols are
  **interleaved run by run** with alternating order. Block-sequential
  measurement produced a *negative* cost of hybridisation
  (`DECISIONS.md` D17). Each configuration reports a `latency_drift_ratio`.

## Primary objective 4 — Rate × supply sweep and the knee

> Sweep handshake rate (1/5/10/20/50/100 per second) against QKD supply
> (1/10/100 kbps), log latency and pool occupancy, and plot the knee where
> the key store, not the cryptography, becomes the bottleneck.

**Met.** `experiments/load_generator.py`, 6 × 3 = **18 configurations at 60 s
each**, 33,480 logged handshakes. Per handshake:
timestamp, supply, rate, `pool_occupancy_snapshot`, keys requested/granted,
starvation flag, latency, success, `security_mode`, `downgraded`.
Pool depth is additionally sampled every 100 ms into
`results/pool_occupancy.csv` (`DECISIONS.md` D9).

The knee is detected numerically, not eyeballed: `detect_knee()` returns the
highest offered rate whose downgrade rate is still under 5%. Measured
**39 hps against a theoretical 39.06** at 10 kbps, and
`figures/throughput_knee.png` overlays the measured hybrid throughput on the
`supply/256` line.

That the key store and not the cryptography is the bottleneck is shown three
independent ways: hybrid throughput pins at `supply/256` while *total*
throughput keeps tracking offered load; QKD utilisation saturates at 0.997–1.000
at the knee; and mean pool occupancy collapses from 526 keys to 3.8.

## Primary objective 5 — Three starvation fixes, each costed

> Implement three fixes for key starvation and measure what each costs:
> per-peer quotas, admission control that refuses instead of degrading, and
> an explicit signal that the session has dropped to computational-only
> security.

**Met.** `mitigations/`, measured by `experiments/mitigation_study.py` over
16 configurations (4 policies × 4 load levels), four peers with demand split
4:1:1:1 so one peer is greedy. 25 tests.

| Fix | Implementation | What it costs |
|---|---|---|
| Per-peer quota | `quota.py` — token bucket consulted *inside* the QKD client, so exhaustion is indistinguishable from an empty pool | **32% of hybrid throughput at the knee** (26.5 vs 38.9 hps), because a fixed quota is not work-conserving. Buys Jain 0.645 → 1.000 |
| Admission control | `admission_control.py` — rejects before any crypto work, against a self-maintained supply model | 60.7% rejection at 100 hps; **nearly free below the knee** (0.1% at 39 hps). Buys silent downgrades → exactly 0.000 |
| Explicit downgrade signal | `downgrade_signal.py` — `EXPLICIT_DOWNGRADE` wired to the application, plus a demo caller that logs each signal | Nothing measurable; throughput identical to reference. Buys visibility only |

Both guarantees are asserted empirically on every run, not just claimed:
"no admitted handshake downgraded" and "every downgrade was reported".

## Primary objective 6 — Modular security analysis

> Write a modular security analysis: a compromise matrix over four failure
> cases (nothing broken, QKD broken, KEM broken, both broken) against three
> properties, plus a CK01 game-hop outline. Full reductions are not expected.

**Met.** `analysis/security_matrix.md` covers the four cases in prose against
**four** properties — confidentiality, authentication, forward secrecy, and
store-now-decrypt-later resistance (the third being the one that actually
motivates QKD). `results/security_matrix.csv` is the machine-readable
projection, generated from the prose so the two cannot drift.

`analysis/game_hops.md` gives a CK01-style outline, G0–G8, naming the
assumption and loss term for each hop: SHA3 collision resistance (G1),
IND-CCA of the ephemeral KEM (G2), IND-CCA of the long-term KEM under each
party's key (G3, G4), QKD key uniformity `ε_QKD` (G5), HKDF extract-and-expand
(G6), and HMAC EUF-CMA (G7). No simulator is constructed and the losses are
indicative — full reductions were explicitly not expected.

Its useful conclusion is structural: the hybrid claim is a **disjunction**
that hop G6 discharges from *any one* surviving IKM component, and hop G5
becomes vacuous when the pool is empty. That is the silent downgrade stated
formally.

---

## End product 1 — reproducible open-source testbed

> A working, reproducible signature-free HAKE testbed ... released as
> open-source scripts with a one-command reproduction path.

**Met, with one gap.** `python run_all.py` regenerates every CSV and figure
from a clean checkout in ~42 minutes; seven stages are individually
selectable and `--quick` proves the pipeline in ~4.5 minutes. Every parameter
lives in `configs/*.yaml`; the orchestrator holds no experiment constants.
Python + liboqs-python + the ETSI mock server, 204 tests.

**Gap:** there is no `LICENSE` file and the tree is not a git repository, so
it is not yet *released* in the sense the brief means. That needs a licence
decision (MIT matches liboqs; Apache-2.0 adds a patent grant) — a one-step
job once chosen.

## End product 2 — the measurements

> The first measurement of how a finite QKD key supply bounds handshake
> throughput, and the first proper account of the silent downgrade.

**Met.** The bound: hybrid throughput saturates on `supply_bps / 256`,
confirmed at three supplies an order of magnitude apart — 3.90 vs 3.906 hps
at 1 kbps, 39.06 vs 39.06 at 10 kbps, and never reached at 100 kbps up to
100 hps. The knee sits at 39 hps with first degradation at 50, bracketing the
theoretical value.

The silent downgrade: up to **96.1%** of successful handshakes lose their QKD
contribution, with `app_visible_downgrade_rate = 0.000` at every load level
and P95 latency flat at ~20 ms. The degradation is invisible in throughput,
in latency, *and* in the handshake's return value simultaneously — the only
place it appears is a `security_mode` field nothing is obliged to read.

Whether this is the *first* such measurement is a claim about the literature
that I cannot verify from inside this repository; I have not read ePrint
2026/1231 or surveyed prior art, so that framing needs your own check.

## End product 3 — a practical answer

> Are per-peer quotas and admission control enough to keep this protocol
> information-theoretically secure at realistic key rates, or is QKD-backed
> key exchange stuck serving low-session-rate links?

**Met.** `analysis/deployment_recommendation.md`.

Short answer: **no, they are not enough, and they cannot be** — neither
mitigation creates key material, so neither moves the ceiling, and a fixed
quota actually lowers it. QKD-backed key exchange is viable exactly where the
session establishment rate stays below `supply_bps / 256`: inter-datacentre
trunks, gateways and long-lived tunnels (a 10 kbps link carries ~140,000
hourly-rekeyed tunnels), not per-connection key exchange at web scale (short
by two to three orders of magnitude).

The lever that works is the denominator — QKD bits per session — via rekey
interval and key amortisation, not admission control. And the single most
important operational recommendation: never ship the `REFERENCE_SILENT`
equivalent, because explicit signalling is free and without it the security
mode of your sessions is unobservable.
