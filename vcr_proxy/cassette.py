import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from .config import Config


def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class Interaction:
    request: Dict[str, Any]
    response: Dict[str, Any]
    timing: Dict[str, Any]


def load_cassette(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_cassette(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, sort_keys=True)
    path.write_text(text + "\n", encoding="utf-8")


def cassette_path(cfg: Config, host: str) -> Path:
    strategy = cfg.cassette["file_strategy"]
    if strategy == "single":
        return cfg.cassette_dir / "cassette.json"
    safe_host = host.replace(":", "_")
    return cfg.cassette_dir / f"{safe_host}.json"


def new_cassette(cfg: Config) -> Dict[str, Any]:
    return {"schema_version": cfg.cassette["schema_version"], "interactions": []}
