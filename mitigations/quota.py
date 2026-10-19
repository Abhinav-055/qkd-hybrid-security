"""Mitigation 1: per-peer QKD key quota (token bucket).

Peer *p* may consume at most `Q_p` keys per window `W`. The bucket is
consulted **inside the QKD client** (as a `KeyRequestGate`), so a peer that
has exhausted its quota sees exactly what an empty pool looks like, and the
mode-dependent behaviour applies unchanged: silent PQC-only under
`REFERENCE_SILENT`, an abort under `STRICT_ERROR`, a signalled downgrade
under `EXPLICIT_DOWNGRADE`.

What this buys: one greedy peer can no longer drain the shared pool and
push *everyone else* onto PQC-only. It does not create key material, so it
cannot raise the aggregate hybrid ceiling -- it redistributes who gets to
stay hybrid. The mitigation study measures exactly that trade: fairness up,
aggregate hybrid throughput unchanged or slightly down.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class QuotaPolicy:
    """`keys_per_window` keys every `window_seconds`, burstable to `burst`."""

    keys_per_window: float
    window_seconds: float = 1.0
    #: Bucket capacity. Defaults to one full window's allowance.
    burst: Optional[float] = None

    @property
    def tokens_per_second(self) -> float:
        return self.keys_per_window / self.window_seconds

    @property
    def capacity(self) -> float:
        return self.keys_per_window if self.burst is None else self.burst

    @classmethod
    def from_share(
        cls,
        supply_bps: float,
        peers: int,
        key_size_bits: int = 256,
        window_seconds: float = 1.0,
        share: float = 1.0,
    ) -> "QuotaPolicy":
        """An equal share of the QKD supply: (supply/key_size) / peers.

        `share` scales that allowance -- 1.0 is exactly fair, below 1.0
        deliberately under-commits the pool.
        """
        keys_per_second = supply_bps / key_size_bits / peers * share
        return cls(
            keys_per_window=keys_per_second * window_seconds,
            window_seconds=window_seconds,
        )


@dataclass
class _Bucket:
    tokens: float
    last_refill: float
    granted: int = 0
    rejected: int = 0


@dataclass
class PeerQuota:
    """Thread-safe per-peer token buckets. Implements `KeyRequestGate`.

    Buckets are created lazily on first sight of a peer, so the load
    generator does not need to declare its peer set up front.
    """

    default_policy: QuotaPolicy
    per_peer_policies: dict[str, QuotaPolicy] = field(default_factory=dict)
    _buckets: dict[str, _Bucket] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def policy_for(self, peer_id: str) -> QuotaPolicy:
        return self.per_peer_policies.get(peer_id, self.default_policy)

    def try_consume(self, peer_id: str, count: int = 1) -> bool:
        """Spend `count` tokens for `peer_id`, or refuse.

        Refusal is all-or-nothing: a partially funded request would leave the
        caller with fewer keys than the handshake needs.
        """
        policy = self.policy_for(peer_id)
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(peer_id)
            if bucket is None:
                bucket = _Bucket(tokens=policy.capacity, last_refill=now)
                self._buckets[peer_id] = bucket

            elapsed = max(now - bucket.last_refill, 0.0)
            bucket.tokens = min(
                policy.capacity, bucket.tokens + elapsed * policy.tokens_per_second
            )
            bucket.last_refill = now

            if bucket.tokens >= count:
                bucket.tokens -= count
                bucket.granted += count
                return True
            bucket.rejected += count
            return False

    def tokens_available(self, peer_id: str) -> float:
        with self._lock:
            bucket = self._buckets.get(peer_id)
            if bucket is None:
                return self.policy_for(peer_id).capacity
            elapsed = max(time.monotonic() - bucket.last_refill, 0.0)
            policy = self.policy_for(peer_id)
            return min(policy.capacity, bucket.tokens + elapsed * policy.tokens_per_second)

    def stats(self) -> dict[str, dict[str, int]]:
        """Per-peer grant/rejection counts, for the fairness analysis."""
        with self._lock:
            return {
                peer_id: {"granted": bucket.granted, "rejected": bucket.rejected}
                for peer_id, bucket in sorted(self._buckets.items())
            }

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
