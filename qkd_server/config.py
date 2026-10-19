"""Configuration dataclasses and loader for the mock QKD server.

Config is loaded from an optional YAML file and then overridden by
environment variables, in that order. This lets the load-sweep
harness spawn many server instances with different rates purely via env vars.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000


@dataclass
class PoolConfig:
    refill_rate_bps: int = 10000
    max_keys: int = 1024
    key_size_bits: int = 256


@dataclass
class IdentityConfig:
    kme_id: str = "KME-ALICE"
    sae_ids: list[str] = field(default_factory=lambda: ["SAE-ALICE", "SAE-BOB"])


@dataclass
class LoggingConfig:
    path: str = "results/qkd_server.log.jsonl"
    level: str = "INFO"


# env var name -> (section attr on Config, field name, value parser)
_ENV_OVERRIDES: dict[str, tuple[str, str, Any]] = {
    "QKD_HOST": ("server", "host", str),
    "QKD_PORT": ("server", "port", int),
    "QKD_REFILL_RATE_BPS": ("pool", "refill_rate_bps", int),
    "QKD_MAX_KEYS": ("pool", "max_keys", int),
    "QKD_KEY_SIZE_BITS": ("pool", "key_size_bits", int),
    "QKD_KME_ID": ("identity", "kme_id", str),
    "QKD_SAE_IDS": ("identity", "sae_ids", "list"),
    "QKD_LOG_PATH": ("logging", "path", str),
    "QKD_LOG_LEVEL": ("logging", "level", str),
}


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    pool: PoolConfig = field(default_factory=PoolConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @classmethod
    def load(cls, path: str | None = None, env: dict[str, str] | None = None) -> "Config":
        """Load config from a YAML file (if given), then apply env var overrides."""
        data: dict[str, Any] = {}
        if path is not None:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

        cfg = cls(
            server=ServerConfig(**data.get("server", {})),
            pool=PoolConfig(**data.get("pool", {})),
            identity=IdentityConfig(**data.get("identity", {})),
            logging=LoggingConfig(**data.get("logging", {})),
        )
        cfg._apply_env_overrides(os.environ if env is None else env)
        return cfg

    def _apply_env_overrides(self, env: dict[str, str]) -> None:
        for env_var, (section, attr, kind) in _ENV_OVERRIDES.items():
            raw = env.get(env_var)
            if raw is None:
                continue
            section_obj = getattr(self, section)
            if kind == "list":
                value: Any = [item.strip() for item in raw.split(",") if item.strip()]
            else:
                value = kind(raw)
            setattr(section_obj, attr, value)
