"""Thread-safe key pool: generation, refill accounting, and starvation tracking.

This module has no knowledge of HTTP, SAE identities, or ETSI shapes — it
only manages symmetric key material. api.py is responsible for turning
pool operations into ETSI-shaped responses and request-level log lines.
"""
from __future__ import annotations

import logging
import secrets
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger("qkd_server.key_pool")


class PoolEmpty(Exception):
    """Raised when a key is requested but the pool has none available."""


class KeyNotFound(Exception):
    """Raised when get_key_by_id() is called with an id the pool never issued."""


@dataclass(frozen=True)
class _KeyRecord:
    key_id: str
    key_bytes: bytes


class KeyPool:
    def __init__(self, refill_rate_bps: int, max_keys: int, key_size_bits: int = 256):
        if refill_rate_bps < 0:
            raise ValueError("refill_rate_bps must be >= 0")
        if max_keys <= 0:
            raise ValueError("max_keys must be > 0")
        if key_size_bits <= 0 or key_size_bits % 8 != 0:
            raise ValueError("key_size_bits must be a positive multiple of 8")

        self.refill_rate_bps = refill_rate_bps
        self.max_keys = max_keys
        self.key_size_bits = key_size_bits
        self.key_size_bytes = key_size_bits // 8

        self._lock = threading.Lock()
        self._queue: deque[_KeyRecord] = deque()
        # Every key ever issued stays indexed here (even after being popped
        # from _queue) so the responder side (dec_keys) can retrieve key
        # material by id after the initiator side (enc_keys) has consumed it.
        self._by_id: dict[str, bytes] = {}
        # Fractional bit credit carried between refill ticks. Without this,
        # flooring per-tick at low rates (e.g. 1 kbps / 100ms tick = 0.39
        # keys/tick) would round down to zero forever and never refill.
        self._bit_credit: float = 0.0
        self._starvation_events = 0

        self._stop_event = threading.Event()
        self._refill_thread: threading.Thread | None = None

    # -- key generation / refill -------------------------------------------------

    def refill(self, dt_seconds: float) -> int:
        """Advance the refill accumulator by dt_seconds worth of key material.

        Generates floor(refill_rate_bps * dt / key_size_bits) new keys
        (using an accumulator so fractional bits carry over across calls),
        capped at max_keys. Excess key material for a tick that would
        overflow the cap is discarded (and logged), matching a real QKD
        device that can't bank unstored key material.

        Returns the number of keys actually added.
        """
        with self._lock:
            self._bit_credit += self.refill_rate_bps * dt_seconds
            possible_new = int(self._bit_credit // self.key_size_bits)
            if possible_new <= 0:
                return 0
            self._bit_credit -= possible_new * self.key_size_bits

            space = max(self.max_keys - len(self._queue), 0)
            added = min(possible_new, space)
            discarded = possible_new - added

            for _ in range(added):
                key_id = str(uuid.uuid4())
                key_bytes = secrets.token_bytes(self.key_size_bytes)
                record = _KeyRecord(key_id, key_bytes)
                self._queue.append(record)
                self._by_id[key_id] = key_bytes

            pool_after = len(self._queue)

        if added > 0:
            logger.info(
                {
                    "event": "refill",
                    "added": added,
                    "discarded": discarded,
                    "pool_after": pool_after,
                }
            )
        elif discarded > 0:
            logger.debug(
                {
                    "event": "refill_discard",
                    "added": 0,
                    "discarded": discarded,
                    "pool_after": pool_after,
                }
            )
        return added

    # -- key dispensing -----------------------------------------------------

    def get_key(self) -> tuple[str, bytes]:
        """Pop one key. Raises PoolEmpty (and counts a starvation event) if empty."""
        with self._lock:
            if not self._queue:
                self._starvation_events += 1
                raise PoolEmpty("key pool is empty")
            record = self._queue.popleft()
        return record.key_id, record.key_bytes

    def get_keys(self, count: int) -> list[tuple[str, bytes]]:
        """Atomically pop `count` keys, all-or-nothing.

        Not part of the required KeyPool surface, but needed so the
        enc_keys endpoint can honor "do not partially fulfill": without an
        atomic multi-pop, a concurrent request could drain the pool between
        an availability check and a loop of individual get_key() calls.
        """
        if count <= 0:
            return []
        with self._lock:
            if len(self._queue) < count:
                self._starvation_events += 1
                raise PoolEmpty(f"requested {count} keys but only {len(self._queue)} available")
            records = [self._queue.popleft() for _ in range(count)]
        return [(r.key_id, r.key_bytes) for r in records]

    def get_key_by_id(self, key_id: str) -> bytes:
        """Look up key material by id. Does not affect occupancy or starvation."""
        with self._lock:
            try:
                return self._by_id[key_id]
            except KeyError:
                raise KeyNotFound(f"unknown key_id: {key_id}") from None

    # -- accounting -----------------------------------------------------------

    def occupancy(self) -> int:
        with self._lock:
            return len(self._queue)

    def starvation_events(self) -> int:
        with self._lock:
            return self._starvation_events

    # -- background refill loop ------------------------------------------------

    def start_refill_loop(self, tick_seconds: float = 0.1) -> None:
        """Start a daemon thread that calls refill() at a fixed tick."""
        if self._refill_thread is not None:
            return
        self._stop_event.clear()

        def _loop() -> None:
            last = time.monotonic()
            while not self._stop_event.wait(tick_seconds):
                now = time.monotonic()
                dt = now - last
                last = now
                self.refill(dt)

        self._refill_thread = threading.Thread(target=_loop, name="qkd-key-pool-refill", daemon=True)
        self._refill_thread.start()

    def stop_refill_loop(self, timeout: float | None = 1.0) -> None:
        if self._refill_thread is None:
            return
        self._stop_event.set()
        self._refill_thread.join(timeout=timeout)
        self._refill_thread = None
