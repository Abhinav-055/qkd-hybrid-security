"""ETSI GS QKD 014 endpoint handlers.

Implements the three GS QKD 014 operations closely enough that a real
014 client library should work against this mock with only a base-URL
change:

  GET  /api/v1/keys/{slave_SAE_ID}/status
  POST /api/v1/keys/{slave_SAE_ID}/enc_keys    (GetKey)
  POST /api/v1/keys/{master_SAE_ID}/dec_keys   (GetKeyWithIDs)

ETSI-shape decisions made where the spec text given to us was ambiguous
are called out inline with "# ETSI-shape decision:" comments.
"""
from __future__ import annotations

import base64
import logging
import time
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import Config
from .key_pool import KeyNotFound, KeyPool, PoolEmpty

logger = logging.getLogger("qkd_server.api")

MAX_KEY_PER_REQUEST = 128




class EncKeysRequest(BaseModel):
    number: int = Field(default=1, ge=1)
    size: Optional[int] = None


class KeyIdItem(BaseModel):
    key_ID: str


class DecKeysRequest(BaseModel):
    key_IDs: list[KeyIdItem]


class KeyEntry(BaseModel):
    key_ID: str
    key: str


class KeysResponse(BaseModel):
    keys: list[KeyEntry]


class StatusResponse(BaseModel):
    source_KME_ID: str
    target_KME_ID: str
    stored_key_count: int
    max_key_count: int
    key_size: int
    max_key_per_request: int


def _error_body(message: str) -> dict:
    # ETSI-shape decision: the 014 spec's "Error" message data format uses a
    # single "message" string field. We mirror that instead of FastAPI's
    # default {"detail": ...} wrapper so a real ETSI client's error parsing
    # works unmodified.
    return {"message": message}


def _log_event(
    event: str,
    requester_sae: str,
    key_id: Optional[str],
    pool_before: int,
    pool_after: int,
    granted: bool,
    starvation: bool,
    http_status: int,
) -> None:
    logger.info(
        {
            "event": event,
            "requester_sae": requester_sae,
            "key_id": key_id,
            "pool_before": pool_before,
            "pool_after": pool_after,
            "granted": granted,
            "starvation": starvation,
            "http_status": http_status,
        }
    )


def create_router(pool: KeyPool, config: Config) -> APIRouter:
    router = APIRouter()
    kme_id = config.identity.kme_id

    @router.get("/api/v1/keys/{slave_sae_id}/status")
    def status(slave_sae_id: str) -> StatusResponse:
        # ETSI-shape decision: this mock models a single KME serving both
        # sides of one point-to-point link, so there is no separate remote
        # KME to name as target_KME_ID. We report this KME's own id for
        # both source and target rather than inventing a second KME.
        return StatusResponse(
            source_KME_ID=kme_id,
            target_KME_ID=kme_id,
            stored_key_count=pool.occupancy(),
            max_key_count=pool.max_keys,
            key_size=pool.key_size_bits,
            max_key_per_request=MAX_KEY_PER_REQUEST,
        )

    @router.post("/api/v1/keys/{slave_sae_id}/enc_keys")
    def enc_keys(slave_sae_id: str, body: EncKeysRequest):
        number = body.number
        size = body.size if body.size is not None else pool.key_size_bits

        if size != pool.key_size_bits:
            return JSONResponse(
                status_code=400,
                content=_error_body(
                    f"unsupported key size {size}; this KME only provides "
                    f"{pool.key_size_bits}-bit keys"
                ),
            )
        if number > MAX_KEY_PER_REQUEST:
            return JSONResponse(
                status_code=400,
                content=_error_body(
                    f"requested {number} keys exceeds max_key_per_request={MAX_KEY_PER_REQUEST}"
                ),
            )

        pool_before = pool.occupancy()
        try:
            popped = pool.get_keys(number)
        except PoolEmpty:
            pool_after = pool.occupancy()
            _log_event(
                event="get_key",
                requester_sae=slave_sae_id,
                key_id=None,
                pool_before=pool_before,
                pool_after=pool_after,
                granted=False,
                starvation=True,
                http_status=503,
            )
            return JSONResponse(
                status_code=503,
                content=_error_body("insufficient key material in pool; QKD supply exhausted"),
            )

        keys = []
        depth = pool_before
        for key_id, key_bytes in popped:
            depth -= 1
            _log_event(
                event="get_key",
                requester_sae=slave_sae_id,
                key_id=key_id,
                pool_before=depth + 1,
                pool_after=depth,
                granted=True,
                starvation=False,
                http_status=200,
            )
            keys.append({"key_ID": key_id, "key": base64.b64encode(key_bytes).decode("ascii")})

        return {"keys": keys}

    @router.post("/api/v1/keys/{master_sae_id}/dec_keys")
    def dec_keys(master_sae_id: str, body: DecKeysRequest):
        # All-or-nothing: check every id exists before building a response,
        # so we never log a "granted" line for a key that isn't actually
        # returned to the caller because a later id in the batch was unknown.
        requested_ids = [item.key_ID for item in body.key_IDs]
        depth = pool.occupancy()

        for key_id in requested_ids:
            try:
                pool.get_key_by_id(key_id)
            except KeyNotFound:
                _log_event(
                    event="get_key_by_id",
                    requester_sae=master_sae_id,
                    key_id=key_id,
                    pool_before=depth,
                    pool_after=depth,
                    granted=False,
                    starvation=False,
                    http_status=404,
                )
                return JSONResponse(
                    status_code=404,
                    content=_error_body(f"unknown key_ID: {key_id}"),
                )

        keys = []
        for key_id in requested_ids:
            key_bytes = pool.get_key_by_id(key_id)
            _log_event(
                event="get_key_by_id",
                requester_sae=master_sae_id,
                key_id=key_id,
                pool_before=depth,
                pool_after=depth,
                granted=True,
                starvation=False,
                http_status=200,
            )
            keys.append({"key_ID": key_id, "key": base64.b64encode(key_bytes).decode("ascii")})

        return {"keys": keys}

    return router
