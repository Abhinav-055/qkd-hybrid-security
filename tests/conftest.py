"""Shared fixtures: live key servers, and long-term KEM key material.

The key server is consumed here exactly the way the rest of the system must
consume it -- over HTTP, on a random port, never by importing KeyPool.
"""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterator

import httpx
import pytest
import uvicorn

from qkd_server.config import Config
from qkd_server.server import create_app


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class LiveServer:
    base_url: str
    port: int
    config: Config


class _ThreadedServer:
    """Runs a uvicorn server in a daemon thread for the duration of a test."""

    def __init__(self, app, host: str, port: int) -> None:
        self._config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self._server = uvicorn.Server(self._config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self, base_url: str, timeout: float = 15.0) -> None:
        self._thread.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._server.started:
                return
            if not self._thread.is_alive():
                raise RuntimeError("QKD server thread died during startup")
            time.sleep(0.02)
        raise TimeoutError(f"QKD server at {base_url} did not start within {timeout}s")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10.0)


@pytest.fixture
def qkd_server_factory(tmp_path) -> Iterator[Callable[..., LiveServer]]:
    """Start one or more live key servers on random ports.

    ``refill_rate_bps=0`` gives a pool that never refills, which is how the
    tests force the starvation path deterministically.
    """
    running: list[_ThreadedServer] = []

    def start(
        refill_rate_bps: int = 0,
        max_keys: int = 64,
        key_size_bits: int = 256,
        prefill_keys: int = 0,
        kme_id: str = "KME-TEST",
    ) -> LiveServer:
        config = Config()
        config.server.host = "127.0.0.1"
        config.server.port = free_port()
        config.pool.refill_rate_bps = refill_rate_bps
        config.pool.max_keys = max_keys
        config.pool.key_size_bits = key_size_bits
        config.identity.kme_id = kme_id
        config.logging.path = str(tmp_path / f"qkd_server_{config.server.port}.log.jsonl")

        app = create_app(config)
        if prefill_keys:
            # Seed exactly prefill_keys keys without waiting on the refill
            # loop: drive one second of an equivalent rate, then restore the
            # configured rate (0 for "this many keys and no more, ever").
            pool = app.state.pool
            pool.refill_rate_bps = key_size_bits * prefill_keys
            pool.refill(1.0)
            pool.refill_rate_bps = refill_rate_bps

        server = _ThreadedServer(app, config.server.host, config.server.port)
        base_url = f"http://{config.server.host}:{config.server.port}"
        server.start(base_url)
        running.append(server)
        return LiveServer(base_url=base_url, port=config.server.port, config=config)

    yield start

    for server in running:
        server.stop()


@pytest.fixture
def empty_qkd_server(qkd_server_factory) -> LiveServer:
    """A server whose pool is empty and will never refill."""
    return qkd_server_factory(refill_rate_bps=0, max_keys=64)


@pytest.fixture
def stocked_qkd_server(qkd_server_factory) -> LiveServer:
    """A server with a fast refill, so keys are effectively always available."""
    server = qkd_server_factory(refill_rate_bps=2_000_000, max_keys=512)
    _wait_for_keys(server.base_url, minimum=16)
    return server


def _wait_for_keys(base_url: str, minimum: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    with httpx.Client(timeout=2.0) as client:
        while time.monotonic() < deadline:
            body = client.get(f"{base_url}/api/v1/keys/SAE-BOB/status").json()
            if body["stored_key_count"] >= minimum:
                return
            time.sleep(0.05)
    raise TimeoutError(f"pool at {base_url} never reached {minimum} keys")
