# Architecture

How the testbed is put together, and why. `OBJECTIVES.md` says what was
asked for, `RESULTS.md` what it measured, `DECISIONS.md` records every
under-specified choice with its reasoning.

---

## 1. Layering and the design rules that hold it together

```
                    experiments/            run_all.py
                  (benchmark, sweep,     (stage orchestration)
                   studies, plots)
                          |
        +-----------------+------------------+
        |                 |                  |
   protocol/          baseline/         mitigations/
   (HAKE, M1..M4,    (pure PQC,        (quota, admission,
    state machine)    no QKD)           downgrade signal)
        |                 |                  |
        +--------+--------+                  |
                 |                           |
             crypto/                         |
      (KEM roles, HKDF, MAC)                 |
                                             |
                 +---------------------------+
                 |
            qkd_client/          <-- the ONLY module that speaks HTTP
                 |
                 | ETSI GS QKD 014 over HTTP
                 v
            qkd_server/          <-- mock ETSI GS QKD 014 KME
     (key pool, refill loop, enc_keys / dec_keys / status)
```

Four rules are enforced, not merely intended:

1. **Only `qkd_client` talks to the QKD server.** Everything else — including
   the experiment harness, which needs pool depth — goes through it. A test
   greps the crypto layer for `httpx` and `qkd_client` and fails if either
   appears.
2. **The crypto layer never knows the QKD server exists.** QKD key material
   arrives as plain bytes, handed in by the protocol layer.
3. **No component imports `qkd_server`.** Only test fixtures do, to start
   one. Experiments spawn it as a subprocess and reach it over HTTP.
4. **No experiment constants in Python.** Every parameter is in
   `configs/*.yaml`; `run_all.py` holds only stage wiring and `--quick`
   overrides.

## 2. The QKD key server

`qkd_server/` was supplied complete. It maintains a thread-safe pool of
256-bit keys with a background refill loop, and serves three ETSI GS QKD 014
operations:

| endpoint | role | pool effect |
|---|---|---|
| `GET .../{sae}/status` | depth and KME parameters | none |
| `POST .../{sae}/enc_keys` | GetKey — initiator side | **consumes** depth |
| `POST .../{sae}/dec_keys` | GetKeyWithIDs — responder side | none |

Two properties matter downstream. Every key ever issued stays indexed by id,
so the responder can fetch material the initiator has already consumed. And
an empty pool raises `PoolEmpty` → **HTTP 503**, which is the signal the
entire study is built on.

Configuration is YAML plus environment-variable overrides, which is what lets
the harness spawn 40+ differently-configured server processes in one run.

## 3. The QKD client and the three modes

`qkd_client/client.py`. The experimental treatment lives here.

```python
class QKDMode(Enum):
    REFERENCE_SILENT   = "reference_silent"    # empty pool -> None, app not told
    STRICT_ERROR       = "strict_error"        # empty pool -> raise, abort
    EXPLICIT_DOWNGRADE = "explicit_downgrade"  # empty pool -> None + signal
```

`get_key()` returns `KeyResult(key_id, key, qkd_used, downgraded)`.
Both non-strict modes return **the identical** `KeyResult(None, None, False,
True)` on an empty pool — the difference between them is decided by the
protocol layer, not here. `STRICT_ERROR` raises `QKDUnavailable`.

Three details that turned out to matter:

* **503 is never retried** (`DECISIONS.md` D7). The key server returns it only
  for `PoolEmpty`, so it is a semantic answer, and retrying would smear the
  starvation signal being measured. Genuine transients (500/502/504) do retry
  with exponential backoff.
* **A `KeyRequestGate` hook** lets the quota mitigation refuse a request
  *before* the HTTP call, so quota exhaustion is indistinguishable from an
  empty pool and the mode behaviour applies unchanged.
* **`drain()` batches.** Bringing a pool to a defined empty state one key at a
  time tops out near 400 keys/s and therefore cannot empty a pool refilling
  faster than that. It requests up to `max_key_per_request` and halves on
  503, converging in ~0.5 s even against a 20 Mbps supply, and is excluded
  from the client's measurement counters (`DECISIONS.md` D12).

## 4. The crypto layer

`crypto/`, a thin layer over liboqs plus hashlib. It implements no primitives.

### `kem.py` — two roles, one primitive

The distinction is **lifecycle, not algorithm**; the same KEM serves both.

* `LongTermKEM` — a persistent identity keypair, trusted out of band like an
  SSH `known_hosts` entry. Encapsulating to a peer's long-term public key is
  what provides *implicit* authentication: only the holder of the matching
  secret key can decapsulate and derive the same session key. No signature is
  ever computed.
* `EphemeralKEM` — a fresh keypair per handshake, dropped afterwards via
  `forget()`. This is the forward-secrecy contribution.

`KEM` itself is stateless: each operation creates and frees its own liboqs
object, so one instance is safe to share across the load generator's threads.

### `kdf.py` — every label, in one place

HKDF-SHA3-256 (RFC 5869 extract-then-expand). All labels are built here and
nowhere else (`DECISIONS.md` D11):

```
b"qkd-hake v1 | <purpose> | <hex transcript hash>"
```

with the two confirmation keys additionally role-separated. That separation
is load-bearing for the proof sketch — without it, game hop G6 in
`analysis/game_hops.md` does not go through and key confirmation could leak
information about the session key.

### `mac.py` — transcript confirmation

HMAC-SHA3-256 over the full transcript, `hmac.compare_digest` for
verification. A test greps the source to prevent a refactor back to `==`.

## 5. The HAKE protocol

`protocol/`. Four messages, no signatures, mutual implicit authentication.

```
I (initiator)                                        R (responder)
  holds sk_I, knows pk_R                      holds sk_R, knows pk_I

M1 -->  session_id | nonce_I | suite | epk_I | qkd_key_id
M2 <--  session_id | nonce_R | ct_eph(epk_I) | ct_lt_I(pk_I) | flags
M3 -->  session_id | ct_lt_R(pk_R) | mac_I
M4 <--  session_id | flags | mac_R
```

### Wire format (`messages.py`)

Compact big-endian binary, not JSON, so the benchmark's byte counts are
realistic rather than base64-inflated:

```
every message:  magic b"QH1" | msg_type u8 | session_id 16B | <fields>
variable field: u32 length prefix || bytes
```

The **MAC is always the final 32 bytes** of a message that carries one, so
"the message minus its MAC" is exactly `encoded[:-32]`. That is what makes
the transcript definition unambiguous. Decoding is strict: bad magic, wrong
type, truncation and trailing bytes are all rejected — malleable encoding
would break transcript uniqueness and everything downstream of it.

### Key schedule

```
ss_longterm = ss_lt_I || ss_lt_R          # mutual implicit authentication
ikm         = ss_longterm || ss_eph || (qkd_key or b"")
th3         = SHA3-256(M1 || M2 || M3_body)
th4         = SHA3-256(M1 || M2 || M3_body || M4_body)

k_conf_I    = HKDF(ikm, salt=th3, info="... | confirmation-key | initiator | th3")
k_conf_R    = HKDF(ikm, salt=th3, info="... | confirmation-key | responder | th3")
session_key = HKDF(ikm, salt=th4, info="... | session-key | th4")

mac_I       = HMAC(k_conf_I, M1 || M2 || M3_body)
mac_R       = HMAC(k_conf_R, M1 || M2 || M3_body || M4_body)
```

`th3` is used for the confirmation keys because M3 is the first moment both
parties hold every KDF input; `th4` salts the session key so it commits to
all four messages (`DECISIONS.md` D3).

**When the pool is empty, `qkd_key` contributes `b""`.** The handshake
completes normally and the session is computationally-only secure. That empty
concatenation is the entire phenomenon under study.

### QKD key agreement

The initiator pulls a key via `enc_keys` and puts only the **`key_ID`** in
M1; the responder fetches the same material via `dec_keys`. So one handshake
costs exactly one 256-bit key, which is what makes `supply_bps / 256`
meaningful, and key material never crosses the handshake wire.

If the responder cannot fetch the named key it clears `qkd_ack` in M2 and the
initiator **drops its own key too** — otherwise the two sides would derive
different session keys (`DECISIONS.md` D4). The handshake still completes,
downgraded, and both sides agree.

### State machine (`state_machine.py`)

```
INIT -> SEND_1 -> WAIT_2 -> SEND_3 -> WAIT_4 -> CONFIRM -> ESTABLISHED
                                                      \-> FAILED
```

Both roles walk the same nodes, each read as "flight *k* handled"
(`DECISIONS.md` D6). `FAILED` is reachable from any non-terminal state and is
terminal; out-of-order steps raise rather than proceeding.

### The mechanism behind the three modes

This is the most important design decision in the project
(`DECISIONS.md` D5), and it lives in one function, `session.build_result()`:

| | `Session` (ground truth) | `HandshakeResult` (what the app sees) |
|---|---|---|
| `REFERENCE_SILENT` | `downgraded = True` | `downgraded = **None**` |
| `EXPLICIT_DOWNGRADE` | `downgraded = True` | `downgraded = True` + warning |
| `STRICT_ERROR` | n/a | `QKDUnavailable` raised |

`None` rather than `False` is deliberate: "I was not told" and "it did not
happen" are different facts, and conflating them is exactly the failure mode
being measured. The experiments read
`HandshakeResult.internal_session.downgraded` — the **measurement oracle**,
deliberately the field a normal application does not look at. That is the
only reason the silent-downgrade rate is measurable at all.

### Transport

Handshake messages are exchanged **in process**, as byte strings handed
between an `Initiator` and a `Responder` (`DECISIONS.md` D8). Only the QKD
client does network I/O, because the research question is about key supply,
not transport. Wire sizes are still recorded from the initiator's point of
view, so the KEM comparison is real.

## 6. The pure-PQC baseline

`baseline/pure_pqc.py` subclasses the protocol roles and **drops any
`qkd_client` passed to it**, so the baseline cannot be hybridised by
accident — verified by a test that hands it a live client and checks the pool
was never touched. Same state machine, same wire format, same crypto, same
message sizes.

A baseline session is `COMPUTATIONAL_ONLY` but explicitly **not
`downgraded`**: it never claimed hybrid security, so nothing was lost.
Keeping those two facts separate is what lets the downgrade study count only
real downgrades.

## 7. The experiment harness

### `harness.py` — shared plumbing

* `QKDServerProcess` — starts the key server as a **subprocess** on a free port,
  configured entirely by environment variables. Out-of-process so the load
  generator's CPU work does not contend with the server's refill thread for
  the GIL, which at 100 handshakes/s would distort the measurement.
* `PoolSampler` — polls `/status` every 100 ms in a background thread.
  Sampling once per handshake would add HTTP load proportional to the
  handshake rate (`DECISIONS.md` D9); instead the per-handshake
  `pool_occupancy_snapshot` is the latest sample.
* Statistics (`percentile`, `jains_fairness`, `theoretical_max_rate`), CSV/JSON
  writers, and `RateLimiter`, which schedules from an ideal timeline so
  falling behind never produces a burst.

### `load_generator.py` — the engine

`run_load()` is shared by the sweep, the downgrade study and the mitigation
study. Per offered handshake it records supply, rate, peer, pool snapshot,
keys requested/granted, starvation, latency, success, security mode,
`downgraded`, `app_visible_downgrade`, rejection and error.

Three measurement decisions are baked in, each forced by a bug the runs
exposed:

* **Pools are drained to empty before *and* after warm-up**
  (`DECISIONS.md` D12). Keys bank while a server boots, and without draining
  a short run rides that stock — which once made a starved configuration
  report a 0% downgrade rate.
* **Per-second metrics divide by the true window**, first offer to last
  completion (`DECISIONS.md` D13). In-flight handshakes that finish after the
  offer loop still drew on the supply.
* **16 workers, queue depth `2 × workers`** (`DECISIONS.md` D14). The mock
  KME's synchronous endpoints thrash deeper: 16 workers sustain ~112 hps,
  48 collapse to ~45. A shallow queue keeps the generator from absorbing
  offered load and smearing the onset of starvation. Offers it cannot attempt
  are counted in `generator_saturated` so a generator-bound configuration
  cannot be mistaken for a finding.

### The four drivers

| module | produces |
|---|---|
| `benchmark.py` | 1000 runs × 4 KEMs × 2 protocols, **protocols interleaved** so the paired delta survives host drift (`DECISIONS.md` D17) |
| `load_generator.py` | the 6 × 3 sweep |
| `downgrade_study.py` | the headline experiment, plus numeric `detect_knee()` |
| `mitigation_study.py` | 4 policies × 4 load levels, and it *asserts* both mitigation guarantees each run |
| `validation.py` | the 10,000-handshake correctness driver, shared by the slow test and the pipeline |
| `plots.py` | 10 required figures, matplotlib/Agg, read from CSVs on disk so `--only plots` works standalone |
| `security_matrix.py` | projects the prose matrix into CSV so the two cannot drift |

## 8. The mitigations

All three act on matrix Cell C only, and **none creates key material**.

| module | mechanism | where it intervenes |
|---|---|---|
| `quota.py` | per-peer token bucket, `Q_p` keys per window `W` | inside the QKD client, via `KeyRequestGate` — so exhaustion looks exactly like an empty pool |
| `admission_control.py` | reject if `keys_needed > projected_pool_at_completion` | before any crypto work or round trip |
| `downgrade_signal.py` | `EXPLICIT_DOWNGRADE` wired to the app, plus a demo caller | at the protocol's public return |

**The quota is deliberately a fixed, non-work-conserving bucket**, and that
costs 32% of hybrid throughput at the knee by stranding allowance light peers
do not use. Measuring the cost of the obvious design is the result; the
work-conserving variant is the recommended future work (`DECISIONS.md` D18).

**Admission control maintains its own supply model** rather than trusting a
sampled pool depth (`DECISIONS.md` D15). The naive version — read depth,
subtract reservations — admitted 283 handshakes that then downgraded, because
a depth reading is always stale and keys consumed since are invisible. The
working design debits the estimate at admission time, credits refill over
time, re-syncs **downwards only**, sizes its safety margin to
`keys_per_second × sampler_interval`, and exposes `resync()` for when the
harness drains the pool underneath it.

## 9. Reproducibility

```bash
python run_all.py                 # everything, ~42 min
python run_all.py --only sweep    # one stage
python run_all.py --quick         # ~4.5 min pipeline smoke test
```

Seven stages — `validate`, `benchmark`, `sweep`, `downgrade`, `mitigations`,
`matrix`, `plots` — run in declared dependency order regardless of the order
requested. Each starts and stops its own server processes on free ports, so
nothing needs to be running first. `validate` aborts the pipeline if
correctness fails, so no measurement stage can run against a broken protocol.

## 10. Tests

204 passing, plus one slow-marked test deselected by default.

| suite | count | covers |
|---|---|---|
| `tests/qkd_server/` | 22 | The key server: pool, refill, endpoints |
| `tests/qkd_client/` | 23 | three modes against a live server, retries, timeouts, gate, batched drain |
| `tests/crypto/` | 65 | KEM roundtrips per algorithm, both roles, HKDF/HMAC KATs, label separation |
| `tests/protocol/` | 67 | wire format, state machine, key agreement, tampering per message, mode wiring, baseline |
| `tests/integration/` | 27 + 1 slow | mitigations end to end, 10,000-handshake validation |

The KAT strategy is worth noting, since no published HKDF-SHA3-256 vectors
exist: an independent generic HKDF written in the test file is first
validated against RFC 5869's SHA-256 vectors, then the module is checked
against it under SHA3-256, cross-checked against `cryptography`'s HKDF, and
pinned with frozen vectors. HMAC is checked against a from-scratch RFC 2104
implementation that does not use the `hmac` module at all, itself validated
on RFC 4231 vectors.

## 11. Known architectural limitations

* **No real QKD.** The mock models key supply only; `ε_QKD` is a black-box
  parameter.
* **The KME does not authenticate SAEs** (`# TODO(auth)` in
  `qkd_server/server.py`), so any caller can fetch any `key_ID`. The residual
  authentication attributed to the QKD key in matrix Cell B is therefore
  argued, not demonstrated.
* **`EphemeralKEM.forget()` documents intent, not erasure.** Python gives no
  guarantee secret bytes leave memory.
* **Single-host measurement.** No network path, and the generator competes
  with the server for CPU.
* **No TLS integration and no formal proof** — both explicit non-goals.
