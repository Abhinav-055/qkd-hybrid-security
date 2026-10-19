# qkd_server

A mock QKD key-distribution device that behaves like an ETSI GS QKD 014 KME
endpoint: it maintains a pool of pre-generated 256-bit symmetric keys,
refills the pool at a configurable rate, and serves keys over an HTTP API.

This package is **not** cryptography, a QKD implementation, or a client.
It is the server that the rest of the testbed (QKD client, crypto layer,
HAKE protocol, load generator, mitigations) talks to when studying what
happens as the QKD key supply runs out.

## Running

```bash
pip install -r ../requirements.txt   # from repo root
python -m qkd_server.server --config configs/qkd_server.example.yaml
```

The server binds to `server.host:server.port` from the config (default
`127.0.0.1:8000`). Config values can be overridden with environment
variables without touching the YAML file — see [Configuration](#configuration).

Serves plain HTTP only. `# TODO(auth)` in `server.py` marks where
TLS/mTLS and SAE authentication would be added; that's out of scope here.

## Endpoints

### GET /api/v1/keys/{slave_SAE_ID}/status

```bash
curl http://127.0.0.1:8000/api/v1/keys/SAE-BOB/status
```

```json
{
  "source_KME_ID": "KME-ALICE",
  "target_KME_ID": "KME-ALICE",
  "stored_key_count": 812,
  "max_key_count": 1024,
  "key_size": 256,
  "max_key_per_request": 128
}
```

### POST /api/v1/keys/{slave_SAE_ID}/enc_keys (GetKey)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/keys/SAE-BOB/enc_keys \
  -H "Content-Type: application/json" \
  -d '{"number": 2, "size": 256}'
```

```json
{
  "keys": [
    {"key_ID": "2289bc38-29af-4e94-bff7-7f323c64c3ca", "key": "Y0K0Wd5ld9bbsr..."},
    {"key_ID": "f9345a49-f63c-4263-88c2-8c7ce2844de2", "key": "EB+In4/3sPCAkt..."}
  ]
}
```

If the pool can't fully satisfy `number`, no keys are popped and the server
returns `503`:

```json
{"message": "insufficient key material in pool; QKD supply exhausted"}
```

### POST /api/v1/keys/{master_SAE_ID}/dec_keys (GetKeyWithIDs)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/keys/SAE-ALICE/dec_keys \
  -H "Content-Type: application/json" \
  -d '{"key_IDs": [{"key_ID": "2289bc38-29af-4e94-bff7-7f323c64c3ca"}]}'
```

Returns the same `{"keys": [...]}` shape as `enc_keys`. An unknown
`key_ID` returns `404` with `{"message": "unknown key_ID: <id>"}` and, for a
batch request, no keys are returned at all (all-or-nothing, same as
`enc_keys`).

## Configuration

Loaded from an optional YAML file, then overridden by environment
variables — see `configs/qkd_server.example.yaml` for the full shape.

| Env var | Overrides |
|---|---|
| `QKD_HOST` | `server.host` |
| `QKD_PORT` | `server.port` |
| `QKD_REFILL_RATE_BPS` | `pool.refill_rate_bps` |
| `QKD_MAX_KEYS` | `pool.max_keys` |
| `QKD_KEY_SIZE_BITS` | `pool.key_size_bits` |
| `QKD_KME_ID` | `identity.kme_id` |
| `QKD_SAE_IDS` | `identity.sae_ids` (comma-separated) |
| `QKD_LOG_PATH` | `logging.path` |
| `QKD_LOG_LEVEL` | `logging.level` |

## Log schema

Every line in `logging.path` is one JSON object. Two event types:

**Per-request** (`get_key` from `enc_keys`, `get_key_by_id` from `dec_keys`):

```json
{
  "ts": 1731945600.123,
  "event": "get_key",
  "requester_sae": "SAE-BOB",
  "key_id": "2289bc38-29af-4e94-bff7-7f323c64c3ca",
  "pool_before": 12,
  "pool_after": 11,
  "granted": true,
  "starvation": false,
  "http_status": 200
}
```

One line is written per key granted (a request for `number: 5` writes 5
lines). A rejected request (503 / 404) writes a single line with
`key_id: null` and `granted: false`.

**Per-refill** (only written when pool depth actually changes):

```json
{"ts": 1731945600.123, "event": "refill", "added": 4, "discarded": 0, "pool_after": 16}
```

## Tests

```bash
pytest tests/qkd_server -v
```
