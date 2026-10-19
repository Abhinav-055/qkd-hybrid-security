# Game-hop outline

A sketch, not a proof. The project explicitly does not require a full
formal reduction; what follows is the sequence of games one would write, the
assumption each hop rests on, and — the part that matters for this study —
**which hop stops working when the QKD supply runs out**.

The model is Canetti–Krawczyk (CK01) style key indistinguishability with
session/party corruption, adapted to a signature-free KEM-authenticated
protocol. Long-term keys are KEM keypairs distributed out of band, so there
is no PKI or signature oracle.

## Setup

* `q_s` — sessions the adversary activates; `q_p` — parties.
* The adversary `A` controls the network: it delivers, reorders, drops and
  modifies M1..M4 at will.
* `A` may corrupt parties (revealing long-term KEM secret keys), reveal
  session keys of non-test sessions, and — an addition specific to this
  setting — **reveal QKD keys**, modelling a compromised KME or QKD channel.
* `A` picks a **fresh** test session and must distinguish its session key
  from a random 256-bit string. Freshness excludes the trivial wins: no
  reveal of the test session's key or its partner's, and not *every* secret
  contribution of the test session revealed (see "What freshness has to
  say" below).
* `Adv_i` denotes `A`'s advantage in game `G_i`.

Recall the key schedule (`DECISIONS.md` D1, D3):

```
th3         = SHA3-256(M1 || M2 || M3_body)
th4         = SHA3-256(M1 || M2 || M3_body || M4_body)
ikm         = ss_lt_I || ss_lt_R || ss_eph || (qkd_key or b"")
k_conf_I    = HKDF(ikm, salt = th3, info = "… | confirmation-key | initiator | th3")
k_conf_R    = HKDF(ikm, salt = th3, info = "… | confirmation-key | responder | th3")
session_key = HKDF(ikm, salt = th4, info = "… | session-key | th4")
```

---

## G0 — the real protocol

`A` interacts with the real implementation. By definition
`Adv_0 = Adv^{KE}_{HAKE}(A)`.

## G1 — abort on randomness collisions

Abort if two sessions ever draw the same `session_id`, `nonce_I` or
`nonce_R`, or if two distinct transcripts collide under SHA3-256.

**Assumption:** a good RNG plus collision resistance of SHA3-256.
**Loss:** birthday terms — `q_s²/2^128` for the 128-bit session ids,
`q_s²/2^256` for the 256-bit nonces, plus `Adv^{CR}_{SHA3-256}`.

`|Adv_0 − Adv_1| ≤ q_s²/2^127 + Adv^{CR}_{SHA3}`.

The purpose of this hop is that every session now has a **unique
transcript**, so `th3` and `th4` are unique per session. That is what lets
later hops treat each session's derived keys as independent, and it is why
the labels in `crypto/kdf.py` embed the transcript hash.

## G2 — replace the ephemeral shared secret with random

Guess the test session (factor `q_s`). In it, replace `ss_eph` — the value
encapsulated to `epk_I` — with a uniformly random 32-byte string.

**Assumption:** IND-CCA security of the ephemeral KEM (ML-KEM / FrodoKEM,
used via liboqs). The reduction embeds the IND-CCA challenge public key as
`epk_I` and the challenge ciphertext as `ct_eph`; other sessions' ephemeral
ciphertexts are answered with the decapsulation oracle, which is why
IND-CCA rather than IND-CPA is needed — `A` can replay and maul ciphertexts
into other sessions.

**Loss:** `|Adv_1 − Adv_2| ≤ q_s · Adv^{IND-CCA}_{KEM}`.

**What it buys:** forward secrecy. Because the ephemeral secret key is
discarded (`EphemeralKEM.forget()`), corrupting either party's long-term key
*after* the session does not recover `ss_eph`.

## G3 — replace the initiator-authenticating secret with random

In the test session, replace `ss_lt_I` — encapsulated by the responder to
the initiator's long-term `pk_I` — with random.

**Assumption:** IND-CCA security of the long-term KEM, under `pk_I`, valid
only while the initiator is uncorrupted.

**Loss:** `|Adv_2 − Adv_3| ≤ q_p · q_s · Adv^{IND-CCA}_{KEM}`.

**What it buys:** implicit authentication *of the initiator*. An `A` that
does not hold `sk_I` cannot learn `ss_lt_I`, so it cannot derive the
session key — and cannot produce the M3 MAC.

## G4 — replace the responder-authenticating secret with random

Symmetrically, replace `ss_lt_R` — encapsulated by the initiator to `pk_R`
— with random. Same assumption and loss as G3, under `pk_R`, valid while
the responder is uncorrupted.

**What it buys:** implicit authentication *of the responder*, and hence
mutual authentication. This hop is what fails in the impostor test
(`test_an_impostor_long_term_key_cannot_complete`): a party that does not
hold `sk_R` derives a different IKM and the MAC check rejects.

## G5 — replace the QKD key with random

In the test session, replace `qkd_key` with a uniformly random 32-byte
string.

**Assumption:** QKD key **uniformity and secrecy** — the key delivered by
the KME is within statistical distance `ε_QKD` of uniform and unknown to
`A`. This is not a computational assumption; it is the QKD device's
security claim (privacy amplification output), and it is the only
information-theoretic step in the argument.

**Loss:** `|Adv_4 − Adv_5| ≤ q_s · ε_QKD`.

**This hop is vacuous when the pool is empty.** If the QKD contribution is
`b""`, there is nothing to replace and `Adv_5 = Adv_4`: the whole argument
must instead be carried by G2–G4, i.e. by the KEMs alone. That is the exact
formal content of a silent downgrade, and the reason
`session.security_mode` distinguishes `HYBRID` from `COMPUTATIONAL_ONLY`.
The empty concatenation in `crypto/kdf.derive_session_key` is where the
theorem quietly weakens.

## G6 — idealise the KDF

Replace HKDF-SHA3-256 with a random function of `(info)` for the test
session: first the extract step's output `PRK` with a uniformly random key,
then the expand step with a random function.

**Assumptions:**

1. **Extract** is a computational randomness extractor / dual PRF. Note the
   salt here is `th3`/`th4`, which is *public*, so this is the standard
   HKDF argument: HMAC-SHA3-256 keyed by a public salt over an IKM with
   sufficient min-entropy yields a PRK indistinguishable from uniform. After
   G2–G5 at least one IKM component is uniform and independent, so the min-
   entropy requirement is met.
2. **Expand** is PRF-secure (HMAC-SHA3-256 as a PRF keyed by `PRK`).

**Loss:** `|Adv_5 − Adv_6| ≤ q_s · (Adv^{extract} + Adv^{PRF}_{HMAC-SHA3})`.

**What it buys:** the three derived keys — `session_key`, `k_conf_I`,
`k_conf_R` — become independent uniform strings, because the labels are
distinct and domain-separated (tested by
`test_session_and_confirmation_keys_are_independent`). Without label
separation this hop would not go through and key confirmation would leak
information about the session key.

## G7 — idealise the confirmation MACs

Replace `HMAC(k_conf_*, ·)` with a random function, and abort if `A` ever
submits a verifying tag on a transcript the honest party did not produce.

**Assumption:** EUF-CMA security of HMAC-SHA3-256.
**Loss:** `|Adv_6 − Adv_7| ≤ 2 · q_s · Adv^{EUF-CMA}_{HMAC-SHA3}`.

**What it buys:** explicit key confirmation and transcript agreement. After
this hop, two sessions that accept are partnered on identical transcripts,
which is what rules out unknown-key-share and reflection attacks and what
makes the M4 security-mode flags trustworthy (they are inside the MAC, so
`test_a_forged_hybrid_flag_is_detected` fails closed).

## G8 — the session key is random

In `G_7` the test session's key is the output of a random function on a
label unique to that session (G1), so it is uniformly distributed and
independent of everything `A` sees. `Adv_8 = 0`.

## Collecting the terms

```
Adv^{KE}_{HAKE}(A) ≤ q_s²/2^127 + Adv^{CR}_{SHA3}
                   + q_s · Adv^{IND-CCA}_{KEM}                 (G2, ephemeral)
                   + 2 · q_p · q_s · Adv^{IND-CCA}_{KEM}       (G3, G4, long-term)
                   + q_s · ε_QKD                                (G5)
                   + q_s · (Adv^{extract} + Adv^{PRF}_{HMAC})   (G6)
                   + 2 · q_s · Adv^{EUF-CMA}_{HMAC}             (G7)
```

## What freshness has to say — and why the study matters

The hybrid claim is a **disjunction**, and it lives entirely in the
interaction between G2–G5 and G6. Hop G6 needs only *one* IKM component to
be uniform and unknown to `A`. So:

| adversary's reach | hop that rescues G6 | resulting guarantee |
|---|---|---|
| breaks KEMs, no QKD access | G5 | secure (matrix Cell B) |
| no KEM break, reveals QKD key or pool empty | G2–G4 | secure (matrix Cell C) |
| neither | any of G2–G5 | secure with margin (Cell A) |
| both | none | insecure (Cell D) |

A freshness condition for this protocol must therefore be stated as "not
all of `{ss_lt_I, ss_lt_R, ss_eph, qkd_key}` are revealed", not as a
condition on individual secrets. Which brings out the measurement result
in formal terms:

> When the QKD pool is empty, `qkd_key = b""` is not a *revealed* secret —
> it is a secret that was never sampled. Hop G5 contributes nothing, and the
> protocol's security statement silently collapses from the disjunction to
> its computational branch alone.

Nothing about the handshake fails when that happens. `session_key` is still
a well-formed 32-byte key, both parties still agree on it, and the MACs
still verify. Under `REFERENCE_SILENT` the application receives
`downgraded=None` and cannot tell which branch of the disjunction its
security now rests on. The experiments measure how often that occurs as a
function of offered load and QKD supply; `throughput_knee.png` shows the
frontier as the measured line `supply_bps / 256`.

## Limitations of this outline

* Not a proof. No simulator is constructed, the reduction losses are
  indicative, and the CK01 session-matching and corruption bookkeeping is
  only gestured at.
* The KEM hops assume IND-CCA of the *implementation* as used, including
  liboqs's implicit rejection behaviour, and ignore implementation-level
  side channels entirely.
* `ε_QKD` is treated as a black-box device parameter. Real QKD security
  proofs are finite-key statements with their own failure probabilities, and
  the mock server in `qkd_server/` models only key *supply*, never QKD
  physics.
* Hop G1's transcript-uniqueness argument relies on the wire format being
  unambiguously parseable, which the implementation enforces by rejecting
  trailing bytes and fixing the MAC at the final 32 bytes
  (`DECISIONS.md` D2). A malleable encoding would break G1 and, with it,
  everything downstream.
* The residual authentication attributed to the QKD key in Cell B assumes
  the KME authenticates and authorises SAEs. This testbed's KME does not
  (`# TODO(auth)`), so that property is argued, not demonstrated.
