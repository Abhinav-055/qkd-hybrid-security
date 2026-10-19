"""Mitigation 2: predictive admission control.

Before a handshake starts, check

    estimated_keys_needed <= projected_pool_at_completion

and reject with `HandshakeRejected` if not -- **before any crypto work is
done**, so a rejected handshake costs no KEM operations and no round trips.

## Why a plain occupancy reading is not enough

The obvious implementation is "read the pool depth, subtract outstanding
reservations". It does not hold up under concurrency: a depth reading is
always slightly stale, and keys consumed since that reading are invisible,
so many handshakes get admitted against the same optimistic number. Measured
on this testbed, that version admitted 283 handshakes that then downgraded --
the guarantee failed exactly when it mattered.

So the controller keeps its own model of the pool instead:

    projected  = estimate + keys_per_second * horizon_seconds
                          - effective_margin_keys

    effective_margin_keys = max(safety_margin_keys,
                                keys_per_second * occupancy_staleness_seconds)

    on admit:    estimate -= keys_per_handshake      (debited immediately)
    on refill:   estimate += keys_per_second * dt    (capped at max_keys)
    on re-sync:  estimate  = min(estimate, observed_occupancy)

Debiting at admission time -- rather than releasing on completion -- is what
closes the race: a key promised to an admitted handshake is gone from the
projection the moment it is promised. The re-sync only ever lowers the
estimate, so a stale-high reading can never inflate it. A handshake that
dies without pulling a key credits its debit back.

The trade is explicit: load above the QKD ceiling is converted from *silent
security downgrade* into *visible rejection*. The system fails loudly.

**Guarantee**: an accepted handshake never silently downgrades. The
mitigation study checks it empirically by counting admitted-but-downgraded
handshakes, which must be 0.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

KEY_SIZE_BITS = 256


class HandshakeRejected(Exception):
    """Admission control refused this handshake before any crypto work."""

    def __init__(self, reason: str, projected: float, needed: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.projected = projected
        self.needed = needed


@dataclass(frozen=True)
class AdmissionPolicy:
    #: QKD keys one handshake consumes. One, by construction (DECISIONS.md D4).
    keys_per_handshake: int = 1
    #: How long from admission to the key actually being pulled.
    horizon_seconds: float = 0.05
    #: Keys held back against rounding. The effective margin is raised to
    #: cover sampling staleness -- see `occupancy_staleness_seconds`.
    safety_margin_keys: float = 1.0
    #: Age of the worst-case occupancy reading (the pool sampler's interval).
    #: An observed depth can be this stale, and therefore this many keys too
    #: high at full consumption, so the margin must cover
    #: keys_per_second * staleness or the guarantee leaks at the edge.
    occupancy_staleness_seconds: float = 0.1


@dataclass
class Ticket:
    """One admitted handshake's debit against the projected pool."""

    peer_id: str
    keys: int
    projected_at_admission: float
    settled: bool = False


class AdmissionController:
    """Predictive admission with a self-maintained pool model.

    `occupancy_fn` returns an observed pool depth; in the experiments it is
    the pool sampler's latest reading, so admission adds no HTTP traffic of
    its own (DECISIONS.md D9). The reading is used only to *lower* the
    internal estimate, never to raise it.
    """

    def __init__(
        self,
        occupancy_fn: Callable[[], int],
        refill_rate_bps: float,
        policy: Optional[AdmissionPolicy] = None,
        key_size_bits: int = KEY_SIZE_BITS,
        max_keys: int = 1024,
    ) -> None:
        self.occupancy_fn = occupancy_fn
        self.refill_rate_bps = refill_rate_bps
        self.policy = policy or AdmissionPolicy()
        self.keys_per_second = refill_rate_bps / key_size_bits
        self.max_keys = max_keys
        #: Margin actually applied: the configured floor, raised to cover how
        #: far a stale occupancy reading can overstate the pool.
        self.effective_margin_keys = max(
            self.policy.safety_margin_keys,
            self.keys_per_second * self.policy.occupancy_staleness_seconds,
        )

        self._lock = threading.Lock()
        self._estimate = float(occupancy_fn())
        self._last_advance = time.monotonic()
        self._outstanding = 0

        self.admitted = 0
        self.rejected = 0
        self.credited_back = 0
        self.per_peer_admitted: dict[str, int] = {}
        self.per_peer_rejected: dict[str, int] = {}

    # -- pool model ---------------------------------------------------------

    def _advance_locked(self) -> float:
        """Add refill since the last call, then re-sync downwards. Caller holds the lock."""
        now = time.monotonic()
        elapsed = max(now - self._last_advance, 0.0)
        self._last_advance = now
        self._estimate = min(self._estimate + elapsed * self.keys_per_second, float(self.max_keys))
        observed = float(self.occupancy_fn())
        # Only ever lower: an optimistic stale reading must not inflate us.
        self._estimate = min(self._estimate, observed)
        return self._estimate

    def resync(self, observed: float) -> None:
        """Force the model to an authoritative pool reading.

        Needed whenever the pool changes underneath us in a way our own
        debits cannot explain -- above all after the experiment harness
        drains the pool to a defined starting state. Without this, the
        controller keeps trusting a pre-drain reading for one sampling
        interval and admits handshakes into an empty pool.
        """
        with self._lock:
            self._estimate = float(observed)
            self._last_advance = time.monotonic()

    def projected_pool(self) -> float:
        """Keys expected to be free for a *new* handshake at completion."""
        with self._lock:
            estimate = self._advance_locked()
            return (
                estimate
                + self.keys_per_second * self.policy.horizon_seconds
                - self.effective_margin_keys
            )

    @property
    def estimated_pool(self) -> float:
        with self._lock:
            return self._estimate

    @property
    def outstanding(self) -> int:
        with self._lock:
            return self._outstanding

    # -- admission ----------------------------------------------------------

    def admit(self, peer_id: str) -> Ticket:
        """Debit keys for one handshake, or raise `HandshakeRejected`."""
        needed = self.policy.keys_per_handshake
        with self._lock:
            estimate = self._advance_locked()
            projected = (
                estimate
                + self.keys_per_second * self.policy.horizon_seconds
                - self.effective_margin_keys
            )
            if projected < needed:
                self.rejected += 1
                self.per_peer_rejected[peer_id] = self.per_peer_rejected.get(peer_id, 0) + 1
                raise HandshakeRejected(
                    f"insufficient projected QKD supply for {peer_id}: need {needed}, "
                    f"projected {projected:.2f} (estimate {estimate:.2f}, "
                    f"reserved {self._outstanding})",
                    projected=projected,
                    needed=needed,
                )
            self._estimate = estimate - needed
            self._outstanding += needed
            self.admitted += 1
            self.per_peer_admitted[peer_id] = self.per_peer_admitted.get(peer_id, 0) + 1
        return Ticket(peer_id=peer_id, keys=needed, projected_at_admission=projected)

    def release(self, ticket: Ticket, consumed: bool = True) -> None:
        """Settle a ticket once its handshake is done.

        The debit stays if the key was actually pulled. If the handshake died
        without pulling one, credit it back so the projection does not drift
        pessimistically low.
        """
        if ticket.settled:
            return
        ticket.settled = True
        with self._lock:
            self._outstanding = max(self._outstanding - ticket.keys, 0)
            if not consumed:
                self._estimate = min(self._estimate + ticket.keys, float(self.max_keys))
                self.credited_back += ticket.keys

    # -- reporting ----------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            total = self.admitted + self.rejected
            return {
                "admitted": self.admitted,
                "rejected": self.rejected,
                "rejection_rate": round(self.rejected / total, 6) if total else 0.0,
                "credited_back": self.credited_back,
                "outstanding": self._outstanding,
                "estimated_pool": round(self._estimate, 3),
                "effective_margin_keys": round(self.effective_margin_keys, 3),
                "per_peer_admitted": dict(sorted(self.per_peer_admitted.items())),
                "per_peer_rejected": dict(sorted(self.per_peer_rejected.items())),
            }
