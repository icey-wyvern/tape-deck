import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class Config:
    listen_host: str
    listen_port: int
    cassette_dir: Path
    upstream_timeout_ms: int
    match: Dict[str, Any]
    redaction: Dict[str, Any]
    cassette: Dict[str, Any]
    tls: Dict[str, Any]


def load_config(path: str) -> Config:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    listen = raw["listen"]
    limits = raw["limits"]
    tls = {**default_config_dict()["tls"], **raw.get("tls", {})}
    cfg = Config(
        listen_host=listen["host"],
        listen_port=int(listen["port"]),
        cassette_dir=Path(raw["cassette_dir"]),
        upstream_timeout_ms=int(limits["upstream_timeout_ms"]),
        match=raw["match"],
        redaction=raw["redaction"],
        cassette=raw["cassette"],
        tls=tls,
    )
    return cfg


def default_config_dict() -> Dict[str, Any]:
    return {
        "listen": {"host": "127.0.0.1", "port": 8080},
        "cassette_dir": "cassettes",
        "limits": {"upstream_timeout_ms": 30000},
        "match": {
            "method": True,
            "url": True,
            "ignore_query_params": [],
            "headers_allowlist": [],
            "headers_denylist": [],
            "body": {"strategy": "hash"},
        },
        "redaction": {
            "headers": ["authorization", "cookie", "set-cookie", "x-api-key"],
            "body_patterns": [{"pattern": "Bearer [A-Za-z0-9._-]+", "replacement": "***"}],
        },
        "cassette": {"file_strategy": "single", "schema_version": 1},
        "tls": {
            "enabled": False,
            "ca_dir": "ca",
            "ca_key": "ca.key",
            "ca_cert": "ca.crt",
            "leaf_dir": "ca/leaf",
            "key_password": None,
            "upstream_insecure": False,
            "upstream_ca_bundle": None,
        },
    }


def config_errors(raw: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    required = ["listen", "cassette_dir", "limits", "match", "redaction", "cassette"]
    for key in required:
        if key not in raw:
            errors.append(f"missing key: {key}")
    return errors
