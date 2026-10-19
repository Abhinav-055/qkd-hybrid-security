"""HTTP app assembly and CLI entry point for the mock QKD server.

    python -m qkd_server.server --config configs/qkd_server.example.yaml

# TODO(auth): this mock serves plain HTTP with no TLS/mTLS and performs no
# SAE authentication/authorization — any caller can hit any SAE's keys.
# A production ETSI 014 KME requires mutual TLS with SAE client
# certificates bound to the URL's SAE ID. That hook (and the QKD client
# that would present a cert) is out of scope for this testbed.
"""
from __future__ import annotations

import argparse
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from .api import create_router
from .config import Config
from .key_pool import KeyPool

REFILL_TICK_SECONDS = 0.1


class JsonlFormatter(logging.Formatter):
    """Renders each LogRecord as one JSON line.

    Loggers in this package pass a dict as the log message (e.g.
    logger.info({"event": "refill", ...})); this formatter serializes it
    directly and stamps a "ts" field (epoch seconds) if the caller didn't
    already include one.
    """

    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, dict):
            payload = dict(record.msg)
        else:
            payload = {"event": "log", "message": record.getMessage()}
        payload.setdefault("ts", record.created)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(config: Config) -> None:
    log_path = Path(config.logging.path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(JsonlFormatter())

    pkg_logger = logging.getLogger("qkd_server")
    pkg_logger.setLevel(config.logging.level.upper())
    pkg_logger.handlers.clear()
    pkg_logger.addHandler(handler)
    pkg_logger.propagate = False


def create_app(config: Config) -> FastAPI:
    configure_logging(config)

    pool = KeyPool(
        refill_rate_bps=config.pool.refill_rate_bps,
        max_keys=config.pool.max_keys,
        key_size_bits=config.pool.key_size_bits,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        pool.start_refill_loop(tick_seconds=REFILL_TICK_SECONDS)
        try:
            yield
        finally:
            pool.stop_refill_loop()

    app = FastAPI(title="Mock QKD Server (ETSI GS QKD 014)", lifespan=lifespan)
    app.state.pool = pool
    app.state.config = config
    app.include_router(create_router(pool, config))

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock ETSI GS QKD 014 key-distribution server")
    parser.add_argument("--config", type=str, default=None, help="Path to a YAML config file")
    args = parser.parse_args()

    config = Config.load(args.config)
    app = create_app(config)

    import uvicorn

    uvicorn.run(app, host=config.server.host, port=config.server.port, log_level=config.logging.level.lower())


if __name__ == "__main__":
    main()
