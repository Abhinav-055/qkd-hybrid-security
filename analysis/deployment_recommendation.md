# Are quotas and admission control enough? A deployment recommendation

The question this project set out to answer:

> Are per-peer quotas and admission control enough to keep this protocol
> information-theoretically secure at realistic key rates, or is QKD-backed
> key exchange stuck serving low-session-rate links like inter-datacentre
> trunks?

**Answer: no, they are not enough — and they cannot be. Neither mitigation
creates key material, so neither moves the ceiling. QKD-backed key exchange
is viable exactly where the session establishment rate stays below
`supply_bps / 256`, which today means trunks, gateways and long-lived
tunnels, not per-connection key exchange at web scale.**

What the mitigations buy is not more security — it is the *choice of failure
mode*. That turns out to be the practically important contribution, because
the default failure mode is the worst one available.

---

## 1. The ceiling is arithmetic, not an implementation limit

One handshake consumes exactly one 256-bit QKD key (`DECISIONS.md` D4), so
the maximum sustainable rate of *information-theoretically hedged*
handshakes is

```
max_hybrid_handshakes_per_second = supply_bps / 256
```

Measured against that line, at full 60-second runs:

| QKD supply | theoretical ceiling | measured hybrid ceiling |
|---|---|---|
| 1 kbps | 3.906 hps | **3.90 hps** |
| 10 kbps | 39.06 hps | **39.06 hps** |

The measured value sits on the theoretical line to three significant
figures, and stays there no matter how much load is offered above it: at
1 kbps supply, offering 10, 20, 50 and 100 handshakes/sec all yield the same
3.90 hybrid hps. Excess demand does not queue, fail, or slow down — it is
served without QKD.

This is why no amount of engineering inside the protocol helps. The ceiling
is set by the key store, exactly as the project premise anticipated.

## 2. Total throughput hides the problem completely

At 1 kbps supply with 100 handshakes/sec offered:

* total completed handshakes: **99.98/sec** — the system looks healthy
* hybrid handshakes: **3.90/sec**
* successful handshakes that silently dropped to computational-only:
  **96.1%**
* downgrades reported to the application: **0**

Every handshake succeeds. Every session key is well-formed, agreed by both
parties, and confirmed by a verifying MAC. Latency does not degrade. No
error is logged, no exception raised, no counter incremented anywhere the
application can see. A throughput dashboard, an SLO monitor and an
integration test suite would all show a perfectly healthy service whose
security has quietly reverted to that of the pure-PQC baseline.

That is the finding the existing literature treats as an availability
footnote. It is not an availability problem. It is a silent, load-dependent
security regression, and it is worst precisely when the system is busiest.

## 3. What each mitigation actually costs and buys

Measured against a 10 kbps supply (39.06 hps ceiling), four peers with
offered load split 4:1:1:1 so `peer-0` is greedy. Full 30-second runs:

| configuration | offered | total hps | hybrid hps | silent | signalled | rejected | fairness | greedy share |
|---|---|---|---|---|---|---|---|---|
| reference | 39 | 39.0 | 38.9 | 0.002 | 0 | 0 | 0.645 | 0.571 |
| reference | 60 | 60.0 | 39.0 | 0.350 | 0 | 0 | 0.644 | 0.572 |
| reference | 100 | 100.0 | 39.0 | **0.610** | 0 | 0 | 0.644 | 0.572 |
| quota | 39 | 39.0 | **26.5** | 0.320 | 0 | 0 | 0.928 | 0.371 |
| quota | 60 | 60.0 | **35.4** | 0.410 | 0 | 0 | 0.996 | 0.278 |
| quota | 100 | 100.0 | 38.8 | 0.612 | 0 | 0 | **1.000** | **0.248** |
| admission control | 39 | 39.0 | 39.0 | **0.000** | 0 | 0.001 | 0.645 | 0.571 |
| admission control | 60 | 39.3 | 39.3 | **0.000** | 0 | 0.345 | 0.641 | 0.574 |
| admission control | 100 | 39.3 | 39.3 | **0.000** | 0 | **0.607** | 0.638 | 0.576 |
| explicit downgrade | 100 | 100.0 | 39.0 | **0.000** | **0.610** | 0 | 0.656 | 0.564 |

* **Admission control** — converts a silent security failure into a loud
  availability failure. Silent downgrades go to exactly zero at every load
  level and every admitted handshake is genuinely hybrid (checked
  empirically each run). Crucially it is **nearly free below the knee**: at
  39 hps it rejects 0.1% of offers and still delivers the full 39.0 hybrid
  hps. Above the knee it holds throughput at the ceiling and rejects the
  rest — 60.7% at 100 hps. Use it when a non-hybrid session is worse than no
  session.

* **Explicit downgrade signalling** — costs nothing measurable (throughput
  identical to reference) and prevents nothing. It moves 61% of sessions
  from "silently computational-only" to "knowingly computational-only". Use
  it always; there is no reason not to.

* **Per-peer quota** — buys fairness, and **is not free**. See below.

### A fixed per-peer quota strands key material

The quota rows above contain the study's most counter-intuitive result: at
39 hps — exactly at the ceiling — the quota delivers only **26.5** hybrid
hps where the unmitigated reference delivers **38.9**. Enforcing fairness
*destroyed* 32% of the available information-theoretic security.

The cause is that a fixed per-peer quota is **not work-conserving**. Each of
the four peers is allowed `39.06 / 4 = 9.77` keys/sec. With load split
4:1:1:1, the greedy peer demands 22.29 and is capped at 9.77, while each
light peer demands 5.57 against an allowance of 9.77 — so 4.20 keys/sec per
light peer, 12.58 keys/sec in total, sits unused and **cannot be lent** to
the peer that wants it. Predicted hybrid throughput is therefore
`Σ min(demand_p, quota_p)`:

| offered | predicted | measured |
|---|---|---|
| 39 hps | 26.48 | **26.5** |
| 60 hps | 35.48 | **35.4** |
| 100 hps | 39.06 | **38.8** |

Three load levels, agreement to three significant figures. The loss is
exactly the stranded allowance, `Σ max(0, quota_p − demand_p)`, and it
vanishes once every peer's demand exceeds its quota — which is why the
effect is invisible at 100 hps and why a short pilot run that only sampled
10 and 100 hps missed it entirely.

The practical consequences:

* A fixed quota costs the most **precisely at the knee**, where the operator
  most wants every available key used — and the cost scales with how skewed
  demand is, not with how overloaded the system is.
* Fairness and utilization are in genuine tension here: the quota reached
  Jain 0.928 at 39 hps by refusing keys that existed and nobody else wanted.
* **The fix is a work-conserving quota**: let a peer borrow unused
  allowance and reclaim it only under contention — a borrowing/hierarchical
  token bucket, or weighted fair queueing over the key pool rather than
  fixed partitioning. This project implements the fixed version, measures
  its cost honestly, and recommends the work-conserving variant for
  deployment. That is the clearest piece of future work the data points to.

### What the mitigations do and do not change

No mitigation raises the number of information-theoretically hedged
sessions — none manufactures key material, and the best any of them achieves
is the ceiling itself (39.0–39.3 hps). One of them, the fixed quota,
*lowers* it when demand is skewed.

The honest framing of the mitigation study is therefore: **you cannot choose
how many sessions get information-theoretic security, only who gets them,
whether the rest are refused, and whether anyone is told — and a careless
fairness policy can reduce even that.**

## 4. Where that leaves deployment

The viability test is a single inequality:

```
new sessions per second  <  supply_bps / 256
```

Published secret-key rates for commercial metropolitan QKD are in the
single-kbps to tens-of-kbps range over tens of kilometres of fibre, rising
for short trusted-node hops. (This testbed models key *supply*, never QKD
physics — see the limitations in `README.md`.) Taking 10 kbps as a
representative metro link, 39 hybrid handshakes/sec:

| deployment shape | session establishment rate | verdict |
|---|---|---|
| Inter-datacentre trunk, IPsec/MACsec tunnels rekeying hourly | 10 kbps supports ~140,000 tunnels | **comfortable** — supply exceeds demand by orders of magnitude |
| Site-to-site VPN gateways, 60-second rekey | ~2,300 tunnels | **comfortable** |
| Backbone router pairs, per-link session keys | tens of sessions/hour | **trivially fine** |
| Enterprise VPN concentrator, per-user sessions at login storm | hundreds to thousands/sec | **marginal to infeasible** |
| Public TLS termination, per-connection key exchange | thousands/sec and up | **infeasible by 2–3 orders of magnitude** |

So the second half of the question is the accurate one: as a
*per-session* mechanism at 256 bits per handshake, QKD-backed key exchange
belongs on low-session-rate, high-value links. It is not a drop-in
hybridisation for general-purpose key establishment, and a deployment that
treats it as one will spend most of its handshakes in the computational-only
regime while believing otherwise.

## 5. The lever that actually works

Since the numerator is fixed by physics and procurement, the only real
engineering freedom is in the denominator: **QKD key bits consumed per
session.** Ranked by effect:

1. **Rekey less often.** The ceiling is per *handshake*, not per byte or per
   connection. An hourly rekey interval buys a factor of 3,600 over
   per-second rekeying. This is why long-lived tunnels are the natural fit
   and short-lived connections are not.
2. **Amortise one QKD key across many sessions.** Use a QKD key as the root
   of a KDF hierarchy or ratchet feeding many session keys. This weakens the
   information-theoretic claim to the root key only — derived keys are
   computationally bound to it — so it is a deliberate, documentable
   trade rather than the silent one this study measures. It is the single
   biggest lever available.
3. **Tier the traffic.** Reserve QKD-backed handshakes for sessions that
   justify them and run pure PQC elsewhere *by policy*. The cost of
   hybridisation measured here is modest, but the cost of an unplanned
   downgrade is that you do not know which security you have.
4. **Size supply to peak, not mean.** The downgrade rate is a function of
   instantaneous offered load. A link provisioned for average demand spends
   its busy periods in the computational-only regime — exactly when an
   attacker would choose to be recording.

## 6. Concrete recommendations

For anyone deploying this protocol, in priority order:

1. **Never run the equivalent of `REFERENCE_SILENT` in production.** Enable
   explicit downgrade signalling. It is free, and without it the security
   mode of your sessions is unobservable. This is the single most important
   recommendation in the study.
2. **Treat `security_mode` as a first-class, logged, alertable property of
   every session.** The distinction between a `Session` that records the
   truth and a result that does not surface it (`DECISIONS.md` D5) is not an
   artifact of this testbed — it is the shape of the bug in any
   implementation that returns "success" without qualification.
3. **Compute `supply_bps / 256` for your link and compare it with your peak
   session establishment rate before deploying.** If peak demand exceeds it,
   you are choosing between rejection and degradation, and you should decide
   which consciously.
4. **Add admission control if and only if a computational-only session is
   worse than no session for your application.** Otherwise it converts a
   tolerable security regression into an outage. Note that a correct
   implementation must maintain its own supply model rather than trusting a
   sampled pool depth (`DECISIONS.md` D15) — the naive version admitted 283
   handshakes that then downgraded.
5. **Add per-peer quotas in any multi-tenant deployment** — so no tenant can
   consume another's security margin — but make them **work-conserving**. A
   fixed quota strands key material when demand is skewed: measured here it
   cost 32% of hybrid throughput at exactly the ceiling (26.5 hps against
   38.9 unmitigated). Let peers borrow unused allowance and reclaim it only
   under contention.
6. **Invest in rekey-interval and key-amortisation design before investing
   in admission control.** Admission control manages a shortage; those
   reduce it.

## 7. The one-sentence version

A finite QKD supply imposes a hard ceiling of `supply_bps / 256`
information-theoretically hedged handshakes per second; above it this
protocol keeps succeeding at full throughput while silently reverting to
computational-only security for up to 96% of sessions; quotas and admission
control can make that shortage fair or loud but never smaller -- and a fixed
quota can make it *worse*, costing 32% of hybrid throughput at the knee by
stranding allowance light peers do not use; and so
QKD-backed key exchange should be deployed where session rates are low and
rekey intervals long — with explicit downgrade signalling switched on,
always.
