import base64

import pytest
from fastapi.testclient import TestClient
from jsonschema import validate

from qkd_server.config import Config
from qkd_server.key_pool import KeyPool
from qkd_server.server import create_app

STATUS_SCHEMA = {
    "type": "object",
    "required": [
        "source_KME_ID",
        "target_KME_ID",
        "stored_key_count",
        "max_key_count",
        "key_size",
        "max_key_per_request",
    ],
    "properties": {
        "source_KME_ID": {"type": "string"},
        "target_KME_ID": {"type": "string"},
        "stored_key_count": {"type": "integer"},
        "max_key_count": {"type": "integer"},
        "key_size": {"type": "integer"},
        "max_key_per_request": {"type": "integer"},
    },
}

KEYS_SCHEMA = {
    "type": "object",
    "required": ["keys"],
    "properties": {
        "keys": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["key_ID", "key"],
                "properties": {
                    "key_ID": {"type": "string"},
                    "key": {"type": "string"},
                },
            },
        }
    },
}

ERROR_SCHEMA = {
    "type": "object",
    "required": ["message"],
    "properties": {"message": {"type": "string"}},
}


def make_client(refill_rate_bps: int = 0, max_keys: int = 100, key_size_bits: int = 256, tmp_log=None):
    config = Config()
    config.pool.refill_rate_bps = refill_rate_bps
    config.pool.max_keys = max_keys
    config.pool.key_size_bits = key_size_bits
    config.identity.kme_id = "KME-TEST"
    if tmp_log is not None:
        config.logging.path = str(tmp_log)
    app = create_app(config)
    return TestClient(app), app


@pytest.fixture
def prefilled_client(tmp_path):
    # refill_rate_bps here only needs to be nonzero -- we drive refill()
    # synchronously with a large dt to fill the pool without depending on
    # the background thread's timing.
    client, app = make_client(refill_rate_bps=256, max_keys=100, tmp_log=tmp_path / "log.jsonl")
    pool: KeyPool = app.state.pool
    pool.refill(1000)  # 256 bps * 1000s / 256 bits = 1000 keys, capped at max_keys=100
    return client, pool


@pytest.fixture
def empty_client(tmp_path):
    client, app = make_client(refill_rate_bps=0, max_keys=100, tmp_log=tmp_path / "log.jsonl")
    return client, app.state.pool


def test_status_happy_path(prefilled_client):
    client, pool = prefilled_client
    resp = client.get("/api/v1/keys/SAE-BOB/status")
    assert resp.status_code == 200
    body = resp.json()
    validate(instance=body, schema=STATUS_SCHEMA)
    assert body["source_KME_ID"] == "KME-TEST"
    assert body["stored_key_count"] == pool.occupancy()
    assert body["max_key_count"] == 100
    assert body["key_size"] == 256


def test_enc_keys_happy_path(prefilled_client):
    client, pool = prefilled_client
    before = pool.occupancy()

    resp = client.post("/api/v1/keys/SAE-BOB/enc_keys", json={"number": 3, "size": 256})
    assert resp.status_code == 200
    body = resp.json()
    validate(instance=body, schema=KEYS_SCHEMA)
    assert len(body["keys"]) == 3

    for entry in body["keys"]:
        raw = base64.b64decode(entry["key"])
        assert len(raw) == 32

    assert pool.occupancy() == before - 3


def test_enc_keys_default_number_is_one(prefilled_client):
    client, pool = prefilled_client
    resp = client.post("/api/v1/keys/SAE-BOB/enc_keys", json={})
    assert resp.status_code == 200
    assert len(resp.json()["keys"]) == 1


def test_dec_keys_happy_path(prefilled_client):
    client, pool = prefilled_client
    enc_resp = client.post("/api/v1/keys/SAE-BOB/enc_keys", json={"number": 2, "size": 256})
    issued = enc_resp.json()["keys"]

    dec_resp = client.post(
        "/api/v1/keys/SAE-ALICE/dec_keys",
        json={"key_IDs": [{"key_ID": k["key_ID"]} for k in issued]},
    )
    assert dec_resp.status_code == 200
    body = dec_resp.json()
    validate(instance=body, schema=KEYS_SCHEMA)

    returned = {k["key_ID"]: k["key"] for k in body["keys"]}
    for k in issued:
        assert returned[k["key_ID"]] == k["key"]


def test_enc_keys_503_on_empty_pool(empty_client):
    client, pool = empty_client
    assert pool.occupancy() == 0

    resp = client.post("/api/v1/keys/SAE-BOB/enc_keys", json={"number": 1, "size": 256})
    assert resp.status_code == 503
    body = resp.json()
    validate(instance=body, schema=ERROR_SCHEMA)


def test_enc_keys_503_does_not_partially_fulfill(prefilled_client):
    client, pool = prefilled_client
    occ = pool.occupancy()

    resp = client.post("/api/v1/keys/SAE-BOB/enc_keys", json={"number": occ + 10, "size": 256})
    assert resp.status_code == 503
    # pool must be untouched -- no partial fulfillment
    assert pool.occupancy() == occ


def test_dec_keys_404_on_unknown_id(prefilled_client):
    client, pool = prefilled_client
    resp = client.post(
        "/api/v1/keys/SAE-ALICE/dec_keys",
        json={"key_IDs": [{"key_ID": "00000000-0000-4000-8000-000000000000"}]},
    )
    assert resp.status_code == 404
    body = resp.json()
    validate(instance=body, schema=ERROR_SCHEMA)


def test_dec_keys_404_all_or_nothing(prefilled_client):
    client, pool = prefilled_client
    enc_resp = client.post("/api/v1/keys/SAE-BOB/enc_keys", json={"number": 1, "size": 256})
    real_id = enc_resp.json()["keys"][0]["key_ID"]

    resp = client.post(
        "/api/v1/keys/SAE-ALICE/dec_keys",
        json={"key_IDs": [{"key_ID": real_id}, {"key_ID": "bogus-id"}]},
    )
    assert resp.status_code == 404


def test_enc_keys_rejects_unsupported_size(prefilled_client):
    client, pool = prefilled_client
    resp = client.post("/api/v1/keys/SAE-BOB/enc_keys", json={"number": 1, "size": 128})
    assert resp.status_code == 400
    validate(instance=resp.json(), schema=ERROR_SCHEMA)
