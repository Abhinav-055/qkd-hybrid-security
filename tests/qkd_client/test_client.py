"""QKD client: mode behaviour against a live server, retries, timeouts."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from qkd_client import QKDClient, QKDMode, QKDServerError, QKDUnavailable
from tests.conftest import _wait_for_keys, free_port

SAE = "SAE-BOB"


# -- mode behaviour against a live key server --------------------------------


def test_get_key_success_returns_material(stocked_qkd_server):
    with QKDClient(stocked_qkd_server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        result = client.get_key()

    assert result.qkd_used is True
    assert result.downgraded is False
    assert result.key_id
    assert isinstance(result.key, bytes) and len(result.key) == 32


def test_reference_silent_returns_empty_result_on_empty_pool(empty_qkd_server):
    with QKDClient(empty_qkd_server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        result = client.get_key()

    assert (result.key_id, result.key) == (None, None)
    assert result.qkd_used is False
    assert result.downgraded is True
    assert client.starvation_events == 1


def test_explicit_downgrade_returns_the_same_shape_as_silent(empty_qkd_server):
    """The two non-strict modes are identical in this module by design."""
    with QKDClient(empty_qkd_server.base_url, SAE, QKDMode.REFERENCE_SILENT) as silent:
        silent_result = silent.get_key()
    with QKDClient(empty_qkd_server.base_url, SAE, QKDMode.EXPLICIT_DOWNGRADE) as explicit:
        explicit_result = explicit.get_key()

    assert silent_result == explicit_result


def test_strict_error_raises_on_empty_pool(empty_qkd_server):
    with QKDClient(empty_qkd_server.base_url, SAE, QKDMode.STRICT_ERROR) as client:
        with pytest.raises(QKDUnavailable):
            client.get_key()
    assert client.starvation_events == 1


def test_strict_error_still_succeeds_while_keys_remain(stocked_qkd_server):
    with QKDClient(stocked_qkd_server.base_url, SAE, QKDMode.STRICT_ERROR) as client:
        assert client.get_key().qkd_used is True


def test_pool_drains_to_starvation(qkd_server_factory):
    """Exactly N keys available, then every mode sees an empty pool."""
    server = qkd_server_factory(refill_rate_bps=0, max_keys=8, prefill_keys=3)
    with QKDClient(server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        granted = [client.get_key() for _ in range(3)]
        starved = client.get_key()

    assert all(r.qkd_used for r in granted)
    assert len({r.key_id for r in granted}) == 3
    assert starved.qkd_used is False and starved.downgraded is True
    assert client.keys_granted == 3


def test_get_key_by_id_matches_initiator_material(stocked_qkd_server):
    """The responder-side lookup returns the same bytes, without consuming depth."""
    with QKDClient(stocked_qkd_server.base_url, SAE, QKDMode.REFERENCE_SILENT) as initiator:
        pulled = initiator.get_key()
        depth_before = initiator.status()["stored_key_count"]

    with QKDClient(stocked_qkd_server.base_url, "SAE-ALICE", QKDMode.REFERENCE_SILENT) as responder:
        material = responder.get_key_by_id(pulled.key_id)
        depth_after = responder.status()["stored_key_count"]

    assert material == pulled.key
    assert depth_after >= depth_before  # dec_keys never pops


def test_get_key_by_id_unknown_id_raises(stocked_qkd_server):
    with QKDClient(stocked_qkd_server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        with pytest.raises(QKDUnavailable):
            client.get_key_by_id("00000000-0000-0000-0000-000000000000")


def test_drain_empties_a_static_pool(qkd_server_factory):
    server = qkd_server_factory(refill_rate_bps=0, max_keys=512, prefill_keys=200)
    with QKDClient(server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        drained = client.drain()
        assert drained == 200
        assert client.get_key().qkd_used is False
        assert client.status()["stored_key_count"] == 0


def test_drain_is_excluded_from_the_measurement_counters(qkd_server_factory):
    """Harness plumbing must not show up as handshake demand."""
    server = qkd_server_factory(refill_rate_bps=0, max_keys=512, prefill_keys=50)
    with QKDClient(server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        client.drain()
        assert client.keys_requested == 0
        assert client.keys_granted == 0
        assert client.starvation_events == 0


def test_drain_outruns_a_fast_refill(qkd_server_factory):
    """One-at-a-time draining cannot beat a fast refill; batching can."""
    # 20 Mbps is ~78,000 keys/sec, far above any achievable per-key request rate.
    server = qkd_server_factory(refill_rate_bps=20_000_000, max_keys=256)
    _wait_for_keys(server.base_url, minimum=256)
    with QKDClient(server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        start = time.monotonic()
        drained = client.drain()
        elapsed = time.monotonic() - start

    assert drained >= 256
    assert elapsed < 10.0, "drain did not converge against a fast refill"


def test_drain_of_an_already_empty_pool_is_a_no_op(empty_qkd_server):
    with QKDClient(empty_qkd_server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        assert client.drain() == 0


def test_drain_respects_the_servers_max_key_per_request(qkd_server_factory):
    """Asking for more than max_key_per_request would be a 400, not a 503."""
    server = qkd_server_factory(refill_rate_bps=0, max_keys=512, prefill_keys=300)
    with QKDClient(server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        # batch is clamped to the advertised limit, so no request is rejected
        assert client.status()["max_key_per_request"] == 128
        assert client.drain(batch=10_000) == 300


def test_status_reports_pool_parameters(stocked_qkd_server):
    with QKDClient(stocked_qkd_server.base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        body = client.status()

    assert body["key_size"] == 256
    assert body["max_key_count"] == 512
    assert body["source_KME_ID"] == "KME-TEST"


# -- gate (quota) hook -------------------------------------------------------


def test_gate_rejection_looks_exactly_like_an_empty_pool(stocked_qkd_server):
    class DenyAll:
        def try_consume(self, peer_id: str, count: int = 1) -> bool:
            return False

    with QKDClient(
        stocked_qkd_server.base_url, SAE, QKDMode.REFERENCE_SILENT, gate=DenyAll()
    ) as client:
        result = client.get_key(peer_id="peer-1")

    assert result.qkd_used is False and result.downgraded is True
    assert client.quota_rejections == 1
    assert client.starvation_events == 0  # the pool was never asked


def test_gate_rejection_raises_under_strict_error(stocked_qkd_server):
    class DenyAll:
        def try_consume(self, peer_id: str, count: int = 1) -> bool:
            return False

    with QKDClient(
        stocked_qkd_server.base_url, SAE, QKDMode.STRICT_ERROR, gate=DenyAll()
    ) as client:
        with pytest.raises(QKDUnavailable):
            client.get_key()


# -- retry / timeout behaviour against a scripted HTTP server ----------------


class _ScriptedHandler(BaseHTTPRequestHandler):
    """Replays a scripted list of (status, body) per request; last entry repeats."""

    script: list[tuple[int, bytes]] = []
    delay_seconds: float = 0.0
    hits: list[str] = []

    def _respond(self) -> None:
        type(self).hits.append(self.path)
        index = min(len(type(self).hits) - 1, len(type(self).script) - 1)
        status, body = type(self).script[index]
        if type(self).delay_seconds:
            time.sleep(type(self).delay_seconds)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._respond()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        self._respond()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def scripted_server():
    """A fake KME that returns a scripted status sequence, for retry tests."""
    started: list[HTTPServer] = []

    def start(script: list[tuple[int, bytes]], delay_seconds: float = 0.0) -> str:
        handler = type("Handler", (_ScriptedHandler,), {})
        handler.script = script
        handler.delay_seconds = delay_seconds
        handler.hits = []

        port = free_port()
        server = HTTPServer(("127.0.0.1", port), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
        return f"http://127.0.0.1:{port}", handler

    yield start

    for server in started:
        server.shutdown()
        server.server_close()


ONE_KEY_BODY = (
    b'{"keys":[{"key_ID":"11111111-1111-1111-1111-111111111111",'
    b'"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}'
)


def test_transient_5xx_is_retried_then_succeeds(scripted_server):
    base_url, handler = scripted_server(
        [(500, b'{"message":"boom"}'), (502, b'{"message":"boom"}'), (200, ONE_KEY_BODY)]
    )
    with QKDClient(base_url, SAE, QKDMode.REFERENCE_SILENT, backoff_seconds=0.001) as client:
        result = client.get_key()

    assert result.qkd_used is True
    assert len(handler.hits) == 3


def test_retries_are_bounded_and_then_raise(scripted_server):
    base_url, handler = scripted_server([(500, b'{"message":"boom"}')])
    with QKDClient(
        base_url, SAE, QKDMode.REFERENCE_SILENT, max_retries=3, backoff_seconds=0.001
    ) as client:
        with pytest.raises(QKDServerError):
            client.get_key()

    assert len(handler.hits) == 3


def test_503_is_not_retried_because_it_means_supply_exhausted(scripted_server):
    """DECISIONS.md D7: retrying 503 would smear the starvation signal."""
    base_url, handler = scripted_server([(503, b'{"message":"QKD supply exhausted"}')])
    with QKDClient(base_url, SAE, QKDMode.REFERENCE_SILENT, backoff_seconds=0.001) as client:
        result = client.get_key()

    assert result.downgraded is True
    assert len(handler.hits) == 1


def test_timeout_raises_qkd_server_error(scripted_server):
    base_url, _ = scripted_server([(200, ONE_KEY_BODY)], delay_seconds=0.5)
    with QKDClient(
        base_url, SAE, QKDMode.REFERENCE_SILENT, timeout=0.05, max_retries=2, backoff_seconds=0.001
    ) as client:
        with pytest.raises(QKDServerError, match="timed out"):
            client.get_key()


def test_unreachable_server_raises_qkd_server_error():
    base_url = f"http://127.0.0.1:{free_port()}"
    with QKDClient(base_url, SAE, QKDMode.REFERENCE_SILENT, max_retries=2, backoff_seconds=0.001) as client:
        with pytest.raises(QKDServerError):
            client.get_key()


def test_malformed_success_body_raises(scripted_server):
    base_url, _ = scripted_server([(200, b'{"not_keys":[]}')])
    with QKDClient(base_url, SAE, QKDMode.REFERENCE_SILENT) as client:
        with pytest.raises(QKDServerError, match="no 'keys' field"):
            client.get_key()


def test_shared_http_client_is_not_closed_by_the_qkd_client(stocked_qkd_server):
    shared = httpx.Client(timeout=2.0)
    client = QKDClient(stocked_qkd_server.base_url, SAE, http_client=shared)
    client.close()
    assert shared.is_closed is False
    shared.close()
