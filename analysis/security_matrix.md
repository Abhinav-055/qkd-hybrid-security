# Compromise matrix: what survives when QKD or the KEM fails

The point of hybridising QKD with post-quantum KEMs is that the session key
should survive the failure of *either* component. This document works out
what actually remains in each of the four cases, for the four-message
signature-free HAKE implemented in `protocol/` (see `DECISIONS.md` D1 for
the message flow).

The key schedule under analysis is:

```
ss_longterm = ss_lt_I || ss_lt_R          (KEM to each party's identity key)
ikm         = ss_longterm || ss_eph || (qkd_key or b"")
session_key = HKDF-SHA3-256(ikm, salt = transcript_hash, info = "…session-key…")
```

"QKD ✓" means the QKD key entered the KDF and is unknown to the adversary.
"KEM ✓" means ML-KEM (or FrodoKEM) remains IND-CCA secure. A machine-readable
version of this table is written to `results/security_matrix.csv`.

| | **KEM ✓ (IND-CCA holds)** | **KEM ✗ (broken)** |
|---|---|---|
| **QKD ✓** | **Cell A — full hybrid security.** The intended state. | **Cell B — confidentiality survives, authentication degrades.** |
| **QKD ✗** | **Cell C — computational security only.** The silent-downgrade state. | **Cell D — no security.** |

---

## Cell A — QKD ✓, KEM ✓: full hybrid security

Both contributions are unknown to the adversary. The session key is
indistinguishable from random under *either* assumption alone, so the
adversary must break both. Concretely:

* **Confidentiality** rests on HKDF-SHA3-256 behaving as a PRF over an IKM
  containing at least one unpredictable component — here, four of them.
* **Authentication** is mutual and implicit: only the holder of `sk_I` can
  recover `ss_lt_I`, only the holder of `sk_R` can recover `ss_lt_R`, and a
  party that recovers neither cannot produce a verifying transcript MAC.
* **Forward secrecy** comes from the per-handshake ephemeral KEM, whose
  secret key is discarded after the handshake.
* **Post-quantum store-now-decrypt-later resistance** is the strongest
  property here: even an adversary who records the transcript and later
  obtains a cryptographically relevant quantum computer cannot recover the
  session key, because the QKD contribution was never transmitted over the
  observable channel at all.

This is the only cell in which the deployment is getting what it paid for.

## Cell B — QKD ✓, KEM ✗: confidentiality survives, authentication degrades

Suppose ML-KEM falls — a cryptanalytic break, or a quantum adversary against
a parameter set that turns out to be too aggressive. The adversary can now
decapsulate `ct_eph`, `ct_lt_I` and `ct_lt_R`, so `ss_eph`, `ss_lt_I` and
`ss_lt_R` are all known to it.

**Confidentiality still holds.** The IKM is a concatenation, and HKDF is
keyed by the whole of it. With a 256-bit QKD key drawn (near-)uniformly and
unknown to the adversary, the extract-then-expand output remains
indistinguishable from random: knowing three of four IKM components does not
help. This is precisely the hedge that motivates hybridisation.

**Authentication is where it gets subtle.** The *designed* authentication
mechanism — implicit authentication by KEM decapsulation — is gone: an
adversary who can decapsulate to `pk_I` and `pk_R` can impersonate either
party at the KEM layer. But it cannot complete a session with a legitimate
peer, because it cannot produce a transcript MAC: the confirmation keys are
derived from an IKM containing the QKD key, which the adversary does not
have. So the QKD key functions as a residual implicit pre-shared secret and
supplies *de facto* authentication as well as confidentiality.

That residual authentication is only as strong as the KME's access control,
and this is a real limitation of the testbed: the key server performs no SAE
authentication (`# TODO(auth)` in `qkd_server/server.py`), so within the mock
KME's domain any caller can fetch any `key_ID` over `dec_keys`. In a
deployment with mutual-TLS-authenticated SAEs the residual authentication is
meaningful; in this testbed it is not, and no measurement here should be read
as evidence about it.

A further caveat: the adversary in this cell can mount a **downgrade attack**
against the negotiation itself. M1's `qkd_key_id` field is not
confidentiality-protected, and an active attacker who breaks the KEM can
strip it and clear `qkd_ack` in M2, pushing both parties into Cell C. The
transcript MAC detects the tampering only *after* both sides have already
derived keys from the reduced IKM — and under `REFERENCE_SILENT` the
application is not told that the session ended up computational-only. This
is the same silent-downgrade weakness the throughput experiments exercise
benignly, reached adversarially instead.

## Cell C — QKD ✗, KEM ✓: computational security only

This is the cell the whole project is about, and there are two distinct
routes into it:

1. **The QKD key was never obtained** — the pool was empty, a quota was
   exhausted, or the peer could not fetch the key by id. The QKD
   contribution is `b""`.
2. **The QKD key is known to the adversary** — a compromised KME, a
   compromised `dec_keys` path, or a QKD implementation attack.

Both land in the same place. `ikm` still contains `ss_lt_I`, `ss_lt_R` and
`ss_eph`, so:

* **Confidentiality and authentication hold** under the IND-CCA security of
  the KEM. Mutual implicit authentication and forward secrecy are intact.
  Nothing is *broken* today.
* **What is lost is the hedge.** The session is exactly as strong as pure
  post-quantum cryptography — which is what `baseline/pure_pqc.py` measures.
  Store-now-decrypt-later resistance now depends entirely on ML-KEM
  remaining unbroken for the confidentiality lifetime of the data.

The security loss is therefore *conditional* rather than immediate, which is
what makes it so easy to ship: nothing fails, no error is logged, throughput
is unaffected. `results/downgrade_events.csv` shows successful handshakes at
a rate that tracks offered load exactly, while
`results/downgrade_rate.png` shows the fraction of those sessions that have
quietly landed in this cell — 61% at 100 handshakes/sec against a 10 kbps
supply, with `app_visible_downgrade_rate = 0.000` throughout.

The three mitigations act only on this cell, and none of them creates key
material:

* **Per-peer quota** decides *who* stays in Cell A when supply is short,
  instead of letting the greediest peer take it (measured: Jain's index 0.64
  → 1.00, greedy peer's share of hybrid sessions 0.58 → 0.24).
* **Admission control** refuses sessions that would land in Cell C, so an
  accepted handshake is always in Cell A (measured: silent downgrade rate
  0.61 → 0.000, paid for with a 0.61 rejection rate).
* **Explicit downgrade signalling** leaves the session in Cell C but tells
  the application it is there, converting an unknown-unknown into a known
  risk the caller can act on.

## Cell D — QKD ✗, KEM ✗: no security

With every IKM component known to the adversary, `ikm` is fully determined
and so is the session key: HKDF is deterministic, and the transcript hash
that salts it is public. Confidentiality, authentication and forward secrecy
all fail. The transcript MAC is forgeable because its key is derivable from
the same IKM.

There is nothing to recover here. The only defence is arranging never to be
in this cell — which is the argument for keeping Cell A's margin and for
not drifting silently into Cell C, since Cell C plus one future
cryptanalytic result *is* Cell D.

---

## Summary of the dependency structure

The session key is secure iff **at least one** IKM component is unknown to
the adversary. That disjunction is the formal content of the hybrid claim,
and `analysis/game_hops.md` traces which game hop discharges it in each
case: hops G2–G4 when only the KEMs are sound (Cell C), hop G5 when only
QKD is sound (Cell B), either when both are (Cell A), and neither when
neither is (Cell D).

The operational conclusion of the measurement study is narrower than the
cryptography but more immediate: a finite QKD supply moves sessions from
Cell A to Cell C at a rate set by `supply_bps / 256`, and by default nobody
is told.
