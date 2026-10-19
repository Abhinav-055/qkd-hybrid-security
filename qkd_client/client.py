"""HTTP client for the mock ETSI GS QKD 014 key server.

This is the **only** module in the project permitted to talk to the QKD
server. The crypto layer never does; the protocol layer calls this client,
and this client calls the ETSI HTTP API.

The three modes in `QKDMode` are the experimental treatment. The default,
`REFERENCE_SILENT`, reproduces the phenomenon under study: when the pool is
empty the client reports "no key" and the handshake quietly continues
PQC-only. That is not a bug to fix here, it is the thing being measured.
"""
from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Protocol, runtime_checkable

import httpx

logger = logging.getLogger("qkd_client")

# The key server returns 503 *only* for PoolEmpty, so 503 is a semantic answer
# ("supply exhausted"), not a transient failure. See DECISIONS.md D7.
POOL_EMPTY_STATUS = 503
RETRYABLE_STATUSES = frozenset({500, 502, 504})
#: The key server's advertised `max_key_per_request`. Only `drain()` batches;
#: a handshake always asks for exactly one key (DECISIONS.md D4).
MAX_KEYS_PER_REQUEST = 128


class QKDMode(Enum):
    """What the client does when the QKD pool cannot serve a key."""

    #: Empty pool -> return None; protocol proceeds PQC-only; app not told.
    REFERENCE_SILENT = "reference_silent"
    #: Empty pool -> raise QKDUnavailable; the handshake aborts.
    STRICT_ERROR = "strict_error"
    #: Empty pool -> return None, and the downgrade is surfaced to the caller.
    EXPLICIT_DOWNGRADE = "explicit_downgrade"


class QKDUnavailable(Exception):
    """No QKD key material is available and the mode forbids continuing."""


class QKDServerError(Exception):
    """The QKD server could not be reached, or answered unusably."""


@dataclass(frozen=True)
class KeyResult:
    """Outcome of one key request.

    On success: ``(key_id, key, True, False)``.

    On an empty pool in a non-strict mode: ``(None, None, False, True)`` --
    identical in both non-strict modes. Whether ``downgraded`` reaches the
    application is decided by the protocol layer, not here.
    """

    key_id: Optional[str]
    key: Optional[bytes]
    qkd_used: bool
    downgraded: bool


@runtime_checkable
class KeyRequestGate(Protocol):
    """Client-side admission hook, used by the quota mitigation.

    A gate that refuses a request makes the client behave exactly as if the
    pool were empty, so the mode-dependent behaviour above applies unchanged.
    """

    def try_consume(self, peer_id: str, count: int = 1) -> bool:
        ...


class QKDClient:
    """ETSI 014 client with retry, timeout, and mode-dependent starvation."""

    def __init__(
        self,
        base_url: str,
        sae_id: str,
        mode: QKDMode = QKDMode.REFERENCE_SILENT,
        *,
        timeout: float = 2.0,
        max_retries: int = 3,
        backoff_seconds: float = 0.02,
        gate: Optional[KeyRequestGate] = None,
        peer_id: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.sae_id = sae_id
        self.mode = mode
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.gate = gate
        self.peer_id = peer_id or sae_id

        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout)

        # Counters the experiments read instead of re-parsing server logs.
        self.keys_requested = 0
        self.keys_granted = 0
        self.starvation_events = 0
        self.quota_rejections = 0

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> "QKDClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- ETSI operations ----------------------------------------------------

    def status(self) -> dict:
        """GET /api/v1/keys/{sae}/status -- pool depth and KME parameters."""
        response = self._request("GET", f"/api/v1/keys/{self.sae_id}/status")
        if response.status_code != 200:
            raise QKDServerError(
                f"status returned HTTP {response.status_code}: {_message_of(response)}"
            )
        return response.json()

    def get_key(self, peer_id: Optional[str] = None) -> KeyResult:
        """POST .../enc_keys -- consume one 256-bit key from the pool.

        An empty pool (or a gate rejection) yields
        ``KeyResult(None, None, False, True)`` in the non-strict modes, and
        raises `QKDUnavailable` in `STRICT_ERROR`.
        """
        self.keys_requested += 1
        effective_peer = peer_id or self.peer_id

        if self.gate is not None and not self.gate.try_consume(effective_peer, 1):
            self.quota_rejections += 1
            logger.debug({"event": "quota_reject", "peer": effective_peer})
            return self._starved("per-peer QKD quota exhausted")

        keys = self._enc_keys(1)

        if keys is None:
            self.starvation_events += 1
            logger.debug({"event": "starvation", "peer": effective_peer})
            return self._starved("insufficient key material in pool")

        entry = keys[0]
        self.keys_granted += 1
        return KeyResult(
            key_id=entry["key_ID"],
            key=base64.b64decode(entry["key"]),
            qkd_used=True,
            downgraded=False,
        )

    def drain(self, batch: int = MAX_KEYS_PER_REQUEST) -> int:
        """Consume every key currently in the pool, returning how many.

        Used by the experiment harness to bring a server to a defined empty
        starting state (DECISIONS.md D12). It requests keys in **batches**,
        halving the batch size whenever the pool cannot fill it, which is
        what lets the drain outrun the refill: one-at-a-time draining tops
        out near 400 keys/sec and so cannot empty a pool refilling faster
        than that -- it would spin indefinitely.

        Deliberately excluded from `keys_requested`/`starvation_events`: this
        is test-harness plumbing, not handshake demand, and must not appear
        in the measurements.
        """
        total = 0
        size = max(1, min(batch, MAX_KEYS_PER_REQUEST))
        while True:
            keys = self._enc_keys(size)
            if keys is None:
                # Fewer than `size` keys available (the server is
                # all-or-nothing). Narrow in; at size 1 the pool is empty.
                if size == 1:
                    return total
                size = max(1, size // 2)
                continue
            total += len(keys)

    def _enc_keys(self, number: int) -> Optional[list[dict]]:
        """POST .../enc_keys for `number` keys. None means the pool said 503."""
        response = self._request(
            "POST",
            f"/api/v1/keys/{self.sae_id}/enc_keys",
            json={"number": number, "size": 256},
        )

        if response.status_code == POOL_EMPTY_STATUS:
            return None
        if response.status_code != 200:
            raise QKDServerError(
                f"enc_keys returned HTTP {response.status_code}: {_message_of(response)}"
            )

        keys = _keys_of(response)
        if not keys:
            raise QKDServerError("enc_keys returned an empty key list")
        return keys

    def get_key_by_id(self, key_id: str) -> bytes:
        """POST .../dec_keys -- fetch key material by id, without consuming depth.

        The responder side of a handshake uses this to obtain the same key the
        initiator pulled. A key id the KME never issued is a hard error, not a
        downgrade: it means the peer is confused or hostile.
        """
        response = self._request(
            "POST",
            f"/api/v1/keys/{self.sae_id}/dec_keys",
            json={"key_IDs": [{"key_ID": key_id}]},
        )

        if response.status_code == 404:
            raise QKDUnavailable(f"unknown key_ID {key_id}: {_message_of(response)}")
        if response.status_code != 200:
            raise QKDServerError(
                f"dec_keys returned HTTP {response.status_code}: {_message_of(response)}"
            )

        keys = _keys_of(response)
        if not keys:
            raise QKDServerError("dec_keys returned an empty key list")
        return base64.b64decode(keys[0]["key"])

    # -- internals ----------------------------------------------------------

    def _starved(self, reason: str) -> KeyResult:
        if self.mode is QKDMode.STRICT_ERROR:
            raise QKDUnavailable(reason)
        # REFERENCE_SILENT and EXPLICIT_DOWNGRADE are deliberately identical
        # here; the protocol layer decides what the application sees.
        return KeyResult(key_id=None, key=None, qkd_used=False, downgraded=True)

    def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        """Issue one request, retrying transient 5xx and transport errors."""
        url = f"{self.base_url}{path}"
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries):
            try:
                response = self._http.request(method, url, timeout=self.timeout, **kwargs)
            except httpx.TimeoutException as exc:
                last_error = QKDServerError(f"{method} {path} timed out after {self.timeout}s")
                last_error.__cause__ = exc
            except httpx.HTTPError as exc:
                last_error = QKDServerError(f"{method} {path} failed: {exc}")
                last_error.__cause__ = exc
            else:
                if response.status_code not in RETRYABLE_STATUSES:
                    return response
                last_error = QKDServerError(
                    f"{method} {path} returned HTTP {response.status_code}"
                )

            if attempt < self.max_retries - 1:
                time.sleep(self.backoff_seconds * (2**attempt))

        assert last_error is not None
        raise last_error


def _message_of(response: httpx.Response) -> str:
    """Pull the ETSI error `message` field, tolerating a non-JSON body."""
    try:
        body = response.json()
    except ValueError:
        return response.text
    return body.get("message", response.text) if isinstance(body, dict) else response.text


def _keys_of(response: httpx.Response) -> list[dict]:
    try:
        body = response.json()
    except ValueError as exc:
        raise QKDServerError(f"non-JSON response body: {response.text[:200]}") from exc
    if not isinstance(body, dict) or "keys" not in body:
        raise QKDServerError(f"response has no 'keys' field: {body!r}")
    return body["keys"]
